with open(r"E:\claw\workspace\vuln-pocs\scripts\fix_all_cves.py", "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace('"venn":', '"vuln":')
with open(r"E:\claw\workspace\vuln-pocs\scripts\fix_all_cves.py", "w", encoding="utf-8") as f:
    f.write(content)
print("typo fixed")
