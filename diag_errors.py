path = r"C:\Users\user\.antigravity\liences tool\saas-admin\src\app\data-management\page.tsx"
content = open(path, encoding='utf-8').read()

# Find the filtering useMemo for NPI files
keywords = ['filteredNpi', 'sharing', 'risk_level', 'sharingStatus', 'toggleNpiFilter', 'activeNpiFilter']
for kw in keywords:
    idx = content.find(kw)
    if idx >= 0:
        print(f"\n=== {kw} (at {idx}) ===")
        print(repr(content[max(0,idx-50):idx+200]))
    else:
        print(f"\n=== {kw} NOT FOUND ===")
