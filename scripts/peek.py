import os

root = r"E:\claw\workspace\vuln-pocs\cves"
samples = ["CVE-2024-3400", "CVE-2024-23897", "CVE-2023-22515",
           "CVE-2025-2024", "CVE-2025-8266", "CVE-2025-48957", "CVE-2025-22952"]

for cve in samples:
    p = os.path.join(root, cve, "poc.py")
    if os.path.exists(p):
        lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
        print(f"=== {cve} ({len(lines)}L) ===")
        for l in lines[:15]:
            print(l)
        print()
