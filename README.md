# AI-Powered Security Scanner

> PII/NPI 탐지를 위한 Google Drive + Microsoft Presidio 기반 보안 스캐너

## 아키텍처

```
main.py (CLI 진입점)
├── drive_client.py        → Google Drive DWD(도메인 전체 위임) 인증, 폴더 탐색, 재시도(Retry) 로직
├── file_extractor.py      → PDF/DOCX/TXT/CSV 텍스트 추출
├── scanner_engine.py      → Dual-Engine (Presidio + Native Regex Fallback)
│   ├── npi_recognizer.py      → NPI Custom Recognizer (Luhn 검증)
│   └── korean_recognizer.py   → 한국 PII 인식기 (주민번호/여권/카드/전화)
├── report_generator.py    → JSON 리포트 생성 (마스킹 처리)
├── sheets_reporter.py     → Google Sheets 리포트 연동
├── rate_limiter.py        → Token Bucket 속도 제한
└── config.py              → DWD 및 실행 환경 설정 관리
```

---

## 🌟 주요 기능 요약

- **Dual-Engine 시스템**: C++ 의존성이 필요한 Microsoft Presidio/spaCy 사용이 불가능한 환경에서도 순수 파이썬 정규식을 활용하는 **Native Pattern Engine** 자동 전환
- **Domain-Wide Delegation (DWD)**: 관리자 승인 한 번으로 사내 특정 사용자(예: 퇴사자)의 드라이브를 공유 절차 없이 직접 스니핑(Impersonate)
- **네트워크 안정성**: 방대한 용량 및 파일 다운로드 시 구글 서버로부터 `[WinError 10054]` 등의 소켓 오류가 발생해도 `threading.local` 독립 네트워크 분리 및 **Auto-Retry** 로직으로 극복
- **이어하기(캐시) 지원**: 중간에 끊겨도 실시간 기록되는 `scan_cache.json`을 통해 이미 검사한 파일은 자동 스킵하여 분석 시간 획기적 단축

---

## 빠른 시작

### 1. 사전 요구사항
- Python 3.9+
- Google Workspace Admin 권한 (DWD 사용 시)

### 2. 의존성 설치

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### 3. Google Cloud 설정

1. [Google Cloud Console](https://console.cloud.google.com/) 접속
2. 새 프로젝트 생성 (또는 기존 프로젝트 선택)
3. **APIs & Services → Library** 에서 다음 API 활성화:
   - Google Drive API
   - Google Sheets API
4. **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**
   - Application type: **Desktop app**
   - 생성 후 JSON 다운로드
5. 다운로드한 파일을 `credentials/client_secret.json` 으로 저장

### 4. 환경 변수 설정

```bash
cp .env.example .env
# .env 파일을 열고 설정값 입력
```

주요 설정값:
| 변수 | 설명 | 예시 |
|------|------|------|
| `GOOGLE_OAUTH_CREDENTIALS_PATH` | GCP 서비스 계정 인증 JSON | `credentials/client_secret.json` |
| `IMPERSONATE_USER_EMAIL` | (DWD 전용) 탐색 대리 권한을 부여받을 대상 구글 계정 | `backup@daangnservice.com` |
| `SCAN_FOLDER_ID` | 스캔할 Drive 폴더 ID (`root` 지정 시 임퍼소네이트 유저의 전체 내 드라이브) | `root` |
| `REPORT_SPREADSHEET_ID` | 결과를 쓸 Google Sheets ID | `1BxiM...` |
| `MAX_WORKERS` | 병렬 처리 워커 수 | `4` |

### 5. 실행

```bash
# 1. 로컬 테스트 (Drive 연결 없이, 샘플 파일 자동 생성)
python main.py --local-test

# 2. 전체 My Drive 스캔
python main.py

# 3. 특정 폴더만 스캔
python main.py --folder-id YOUR_FOLDER_ID

# 4. 특정 폴더 + Sheets 리포트
python main.py --folder-id YOUR_FOLDER_ID --spreadsheet-id YOUR_SHEET_ID

# 5. 상세 로그 출력
python main.py --local-test --verbose
```

---

## 탐지 가능한 개인정보 유형

| 엔티티 | 설명 | 검증 방식 |
|--------|------|----------|
| `NPI` | 미국 의료 제공자 식별번호 (10자리) | Luhn 알고리즘 (CMS 표준) |
| `PERSON` | 사람 이름 | spaCy NER (en_core_web_lg) |
| `PHONE_NUMBER` | 전화번호 (미국) | Regex + 패턴 |
| `EMAIL_ADDRESS` | 이메일 주소 | Regex |
| `LOCATION` | 위치 정보 | spaCy NER |
| `CREDIT_CARD` | 신용카드 번호 (국제) | Luhn 알고리즘 |
| `US_SSN` | 미국 사회보장번호 | Regex |
| `KR_RRN` | 주민등록번호 | 체크섬 알고리즘 |
| `KR_PASSPORT` | 한국 여권번호 | Regex (구/신형식) |
| `KR_CARD_NUMBER` | 한국 신용/체크카드 | Luhn 알고리즘 |
| `KR_PHONE` | 한국 전화번호 | Regex (010/02/+82) |

---

## 리포트 구조

### JSON 리포트 (`reports/scan_report_YYYYMMDD_HHMMSS.json`)

```json
{
  "metadata": { "report_generated_at": "...", "duration_seconds": 12.3 },
  "summary": {
    "total_files_scanned": 42,
    "flagged_files": 3,
    "total_pii_findings": 17,
    "risk_distribution": { "CRITICAL": 1, "HIGH": 2 }
  },
  "flagged_files": [
    {
      "file_name": "patient_records.pdf",
      "risk_level": "CRITICAL",
      "risk_score": 0.95,
      "findings": [
        { "entity_type": "NPI", "confidence": 0.95, "masked_value": "1*******3" }
      ]
    }
  ]
}
```

### Google Sheets 리포트 (3개 탭)
- **Summary** — 전체 스캔 통계
- **Flagged Files** — 위험 파일 목록 (위험도 색상 표시)
- **All Findings** — 개별 PII 탐지 기록

---

## 위험도 기준

| 레벨 | 신뢰도 점수 | 색상 |
|------|------------|------|
| 🔴 CRITICAL | ≥ 0.85 | 빨간색 |
| 🟠 HIGH | ≥ 0.70 | 주황색 |
| 🟡 MEDIUM | ≥ 0.50 | 노란색 |
| 🟢 LOW | > 0.00 | 초록색 |
| ✅ CLEAN | 0.00 | — |

---

## 테스트 실행

```bash
python -m pytest tests/ -v
```

---

## 보안 주의사항

- ⚠️ **실제 PII 데이터는 절대 로그에 기록되지 않습니다** — 마스킹된 값만 저장
- `.env`, `credentials/`, `reports/` 디렉터리는 `.gitignore`에 포함됨
- OAuth 토큰은 `credentials/token.json`에 로컬 저장 (Git에 커밋하지 마세요)
- 스캐너는 Drive **읽기 전용** 권한(`drive.readonly`)만 사용

---

## 종료 코드

| 코드 | 의미 |
|------|------|
| `0` | 성공 — PII 미발견 |
| `1` | 오류 — 설정/인증 실패 |
| `2` | 경고 — PII 발견됨 |
