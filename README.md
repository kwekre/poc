# vuln-pocs

Web Security Vulnerability Proof-of-Concept (POC) Collection

## Structure

- `cves/` - CVE-based vulnerability POCs (network products, OS, middleware, etc.)
- `oacms/` - OA system and CMS vulnerability POCs (Chinese enterprise software focus)
- `runtime/` - POC runner framework with fingerprint + dispatch support
- `tools/` - Utility scripts (web scanner, HTTP client, etc.)
- `utils/` - Shared Python utilities

## Usage

```bash
# Single target scan
python3 runtime/poc_runner.py -u http://target.com -l cves

# Auto fingerprint + scan
python3 runtime/poc_runner.py -u http://target.com --auto

# List all available POCs
python3 runtime/poc_runner.py --list

# Run specific CVE
python3 cves/CVE-XXXX-XXXXX/poc.py
```

## CVE Coverage

| Year | Count | Top CVEs |
|------|-------|----------|
| 2023 | 1 | CVE-2023-22515 (Confluence RCE) |
| 2024 | 37 | CVE-2024-38077 (Windows RCE), CVE-2024-47575 (FortiOS RCE), CVE-2024-1709 (ScreenConnect RCE) |
| OA/CMS | 40 | Weaver, Seeyon, TongDa, DedeCMS, EmpireCMS, WordPress, Laravel, GitLab, Strapi |

## Legal Notice

All POCs in this repository are for **authorized security testing** only.
Unauthorized scanning or exploitation is prohibited by law.
