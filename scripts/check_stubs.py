import os, re

stubs = []
detailed = []
root = r"E:\claw\workspace\vuln-pocs\cves"

for cve in os.listdir(root):
    p = os.path.join(root, cve, "poc.py")
    if not os.path.isfile(p):
        continue
    content = open(p, encoding="utf-8", errors="ignore").read()
    has_http = bool(re.search(r"(requests\.|http\.|urllib\.|session\.|post\(|get\()", content))
    lines = len(content.splitlines())
    if lines < 30 or not has_http:
        stubs.append((cve, lines))
    else:
        detailed.append((cve, lines))

print(f"Detailed: {len(detailed)}")
print(f"Stub only: {len(stubs)}")
print()
print("=== Stub list (name | lines) ===")
for c, l in sorted(stubs):
    print(f"  {c:<35} {l} lines")
