"""
drive_client.py — Google Drive API Client (OAuth 2.0)
======================================================
Handles:
  - OAuth 2.0 authentication with token caching
  - Recursive file listing (all supported MIME types)
  - Binary file download via streaming (MediaIoBaseDownload)
  - Google Workspace native format export (Docs → TXT, Sheets → CSV)
  - Rate-limited API calls
"""

import io
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, List, Optional

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload

from config import GoogleAuthConfig, ScanConfig, GOOGLE_NATIVE_TYPES, MIME_TYPE_MAP
from rate_limiter import RateLimiter

logger = logging.getLogger("scanner.drive_client")


@dataclass
class DriveFile:
    """Metadata for a discovered Google Drive file."""
    file_id: str
    name: str
    mime_type: str
    path: str          # Full path within Drive (e.g., '/Folder/SubFolder/file.pdf')
    size: int = 0      # bytes; 0 for Google native files
    modified_time: str = ""
    parents: List[str] = None

    def __post_init__(self):
        if self.parents is None:
            self.parents = []


class DriveClient:
    """
    Google Drive API client with OAuth 2.0 and streaming file downloads.
    Caches OAuth tokens to avoid re-authentication on subsequent runs.
    """

    PAGE_SIZE = 100       # Files per API page (max 1000, using 100 for safety)
    MAX_RETRIES = 3       # Retry attempts on transient API errors
    RETRY_DELAY = 2.0     # Base delay (seconds) for exponential backoff

    def __init__(self, auth_config: GoogleAuthConfig, rate_limiter: RateLimiter):
        import threading
        self.auth_config = auth_config
        self.rate_limiter = rate_limiter
        self._local = threading.local()
        self._creds = None
        self._folder_cache: dict = {}   # folder_id → folder_name

    # ── Authentication ─────────────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """
        Perform OAuth 2.0 authentication with token caching.

        Flow:
          1. Load cached token from disk (if it exists)
          2. Refresh expired token automatically
          3. Launch browser OAuth flow for new authentication
          4. Save token for future reuse

        Returns:
            True if authentication succeeded, False on failure.
        """
        creds = None
        token_path = Path(self.auth_config.token_path)
        creds_path = Path(self.auth_config.oauth_credentials_path)

        # Step 1: Load existing token
        if token_path.exists():
            try:
                creds = Credentials.from_authorized_user_file(
                    str(token_path), self.auth_config.scopes
                )
                logger.info("🔑 Loaded cached OAuth token")
            except Exception as e:
                logger.warning(f"⚠️  Cached token invalid: {e} — will re-authenticate")
                creds = None

        # Step 2: Refresh or re-authenticate
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    logger.info("🔄 OAuth token refreshed successfully")
                except Exception as e:
                    logger.warning(f"⚠️  Token refresh failed: {e} — launching browser flow")
                    creds = None

        # Build Drive service
        if not creds:
            if not creds_path.exists():
                logger.error(
                    f"❌ OAuth credentials not found: '{creds_path}'\n"
                    "   👉 Download client_secret.json from:\n"
                    "      Google Cloud Console → APIs & Services → Credentials\n"
                    "      Then place it at: credentials/client_secret.json"
                )
                return False

            # Detect credential type (Service Account vs Desktop OAuth)
            import json
            try:
                with open(creds_path, 'r', encoding='utf-8') as f:
                    cred_data = json.load(f)
            except Exception as e:
                logger.error(f"❌ Failed to read credentials JSON: {e}")
                return False

            if cred_data.get("type") == "service_account":
                # Use Service Account without browser popup
                from google.oauth2 import service_account
                logger.info("🤖 Detected Service Account credentials. Authenticating directly...")
                
                # Filter out spreadsheets scope for DWD to prevent unauthorized_client error
                drive_scopes = [s for s in self.auth_config.scopes if "spreadsheets" not in s]
                
                creds = service_account.Credentials.from_service_account_file(
                    str(creds_path), scopes=drive_scopes
                )
                
                # Check for Domain-Wide Delegation target
                if getattr(self.auth_config, "impersonate_user_email", None):
                    logger.info(f"🎭 Using DWD to impersonate target user: {self.auth_config.impersonate_user_email}")
                    creds = creds.with_subject(self.auth_config.impersonate_user_email)
                    
                logger.info("✅ Service Account authentication successful")
            else:
                # Step 3: Launch browser-based OAuth flow for normal accounts
                logger.info("🌐 Opening browser for Google OAuth 2.0 authentication...")
                flow = InstalledAppFlow.from_client_secrets_file(
                    str(creds_path), self.auth_config.scopes
                )
                creds = flow.run_local_server(
                    port=0,
                    prompt="consent",
                    access_type="offline",
                )
                logger.info("✅ OAuth authentication successful")

                # Step 4: Cache token for future runs (only for User OAuth)
                token_path.parent.mkdir(parents=True, exist_ok=True)
                with open(str(token_path), "w") as f:
                    f.write(creds.to_json())
                logger.info(f"💾 Token cached at: {token_path}")

        self._creds = creds
        logger.info("🚀 Google Drive credentials loaded (service built per-thread)")
        return True

    @property
    def _service(self):
        """Thread-safe property that builds a unique API client per thread."""
        if not hasattr(self._local, "service"):
            # google-api-python-client is NOT thread-safe, must build per thread
            self._local.service = build("drive", "v3", credentials=self._creds)
        return self._local.service

    # ── Folder Traversal ───────────────────────────────────────────────────────

    def _get_folder_name(self, folder_id: str) -> str:
        """Resolve folder ID to name with caching."""
        if folder_id in self._folder_cache:
            return self._folder_cache[folder_id]
        if folder_id == "root":
            return "My Drive"
        try:
            self.rate_limiter.acquire()
            meta = self._service.files().get(
                fileId=folder_id, fields="name"
            ).execute()
            name = meta.get("name", folder_id)
        except Exception:
            name = folder_id
        self._folder_cache[folder_id] = name
        return name

    def _list_files_in_folder(
        self, folder_id: str, folder_path: str, scan_config: ScanConfig
    ) -> Generator[DriveFile, None, None]:
        """
        Recursively list all scannable files under a folder.

        Args:
            folder_id:   Drive folder ID to search.
            folder_path: Human-readable path prefix for display.
            scan_config: Configuration with MIME types and folder scope.

        Yields:
            DriveFile instances for each discovered file.
        """
        # Build MIME type filter (exclude Google folders themselves)
        mime_conditions = " or ".join(
            f"mimeType='{mt}'" for mt in scan_config.mime_types
        )
        # Also include subfolders for recursion
        query = (
            f"'{folder_id}' in parents and trashed=false and "
            f"(mimeType='application/vnd.google-apps.folder' or {mime_conditions})"
        )

        page_token = None
        while True:
            self.rate_limiter.acquire()
            try:
                response = self._api_call_with_retry(
                    self._service.files().list(
                        q=query,
                        pageSize=self.PAGE_SIZE,
                        fields="nextPageToken, files(id, name, mimeType, size, modifiedTime, parents)",
                        pageToken=page_token,
                        supportsAllDrives=True,
                        includeItemsFromAllDrives=True,
                    )
                )
            except HttpError as e:
                logger.error(f"❌ API error listing '{folder_path}': {e}")
                break

            items = response.get("files", [])
            for item in items:
                mime = item["mimeType"]
                item_path = f"{folder_path}/{item['name']}"

                if mime == "application/vnd.google-apps.folder":
                    # Recurse into subfolder
                    logger.info(f"📁 Entering folder: {item_path}")
                    yield from self._list_files_in_folder(
                        item["id"], item_path, scan_config
                    )
                else:
                    # Yield scannable file
                    yield DriveFile(
                        file_id=item["id"],
                        name=item["name"],
                        mime_type=mime,
                        path=item_path,
                        size=int(item.get("size", 0)),
                        modified_time=item.get("modifiedTime", ""),
                        parents=item.get("parents", []),
                    )

            page_token = response.get("nextPageToken")
            if not page_token:
                break

    def list_files(self, scan_config: ScanConfig) -> List[DriveFile]:
        """
        List all scannable files under the configured folder.

        Returns:
            Sorted list of DriveFile objects.
        """
        folder_id = scan_config.folder_id
        folder_name = self._get_folder_name(folder_id)
        logger.info(f"🔍 Scanning Drive folder: '{folder_name}' (id: {folder_id})")

        files = list(self._list_files_in_folder(folder_id, f"/{folder_name}", scan_config))
        logger.info(f"📋 Found {len(files)} scannable file(s)")
        return files

    # ── File Download ──────────────────────────────────────────────────────────

    def download_file(self, drive_file: DriveFile) -> Optional[bytes]:
        """
        Download file bytes from Google Drive.

        For Google native types (Docs, Sheets), uses the export API.
        For uploaded files (PDF, DOCX, TXT), uses get_media streaming.

        Returns:
            Raw bytes of file content, or None on error.
        """
        if self._service is None:
            logger.error("❌ Not authenticated — call authenticate() first")
            return None

        self.rate_limiter.acquire()

        try:
            if drive_file.mime_type in GOOGLE_NATIVE_TYPES:
                return self._export_native_file(drive_file)
            else:
                return self._download_binary_file(drive_file)
        except HttpError as e:
            status = e.resp.status
            if status == 403:
                logger.warning(f"🔒 No permission for: {drive_file.name}")
            elif status == 404:
                logger.warning(f"🔍 File not found: {drive_file.name}")
            elif status == 429:
                logger.warning(f"⏳ Rate limit hit for: {drive_file.name} — pausing 60s")
                time.sleep(60)
            else:
                logger.error(f"❌ HTTP {status} downloading '{drive_file.name}': {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Unexpected error downloading '{drive_file.name}': {e}")
            return None

    def _download_binary_file(self, drive_file: DriveFile) -> Optional[bytes]:
        """Stream binary file download using MediaIoBaseDownload."""
        buffer = io.BytesIO()
        request = self._service.files().get_media(
            fileId=drive_file.file_id,
            supportsAllDrives=True,
        )
        downloader = MediaIoBaseDownload(buffer, request, chunksize=4 * 1024 * 1024)  # 4MB chunks

        done = False
        while not done:
            _, done = downloader.next_chunk()

        content = buffer.getvalue()
        logger.debug(f"  ⬇️  Downloaded {len(content):,} bytes: {drive_file.name}")
        return content

    def _export_native_file(self, drive_file: DriveFile) -> Optional[bytes]:
        """Export Google Docs/Sheets to text/CSV format."""
        export_mime = MIME_TYPE_MAP.get(drive_file.mime_type)
        if not export_mime:
            logger.warning(f"  No export MIME for: {drive_file.mime_type}")
            return None

        buffer = io.BytesIO()
        request = self._service.files().export_media(
            fileId=drive_file.file_id,
            mimeType=export_mime,
        )
        downloader = MediaIoBaseDownload(buffer, request)
        done = False
        while not done:
            _, done = downloader.next_chunk()

        content = buffer.getvalue()
        logger.debug(f"  📤 Exported {drive_file.name} as {export_mime}: {len(content):,} bytes")
        return content

    # ── API Retry Logic ────────────────────────────────────────────────────────

    def _api_call_with_retry(self, request):
        """Execute an API request with exponential backoff retry."""
        import socket
        for attempt in range(self.MAX_RETRIES):
            try:
                return request.execute()
            except HttpError as e:
                if e.resp.status in (403, 404):
                    raise  # Don't retry permission/not found errors
                if attempt < self.MAX_RETRIES - 1:
                    delay = self.RETRY_DELAY * (2 ** attempt)
                    logger.warning(f"⏳ API HTTP error {e.resp.status} — retry {attempt+1} in {delay}s")
                    time.sleep(delay)
                else:
                    raise
            except (ConnectionError, socket.error, OSError) as e:
                # Catches WinError 10054 and other network rips
                if attempt < self.MAX_RETRIES - 1:
                    delay = self.RETRY_DELAY * (2 ** attempt)
                    logger.warning(f"🔌 Network Drop ({e}) — retry {attempt+1} in {delay}s")
                    time.sleep(delay)
                else:
                    raise
        raise RuntimeError("Max retries exceeded")
