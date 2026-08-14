#!/usr/bin/env python3
"""
IDOR 漏洞 POC 库
检测: 直接对象引用、水平/垂直越权
"""
import argparse, sys, urllib.parse
sys.path.insert(0, '..')

def main():
    parser = argparse.ArgumentParser(description="IDOR 漏洞检测")
    parser.add_argument("-t", "--target", required=True, help="目标 URL 模式，例: http://app.com/api/user?id=")
    parser.add_argument("-p", "--param", default="id", help="ID 参数名")
    parser.add_argument("--ids", default="1,2,3,999", help="测试 ID 列表")
    args = parser.parse_args()

    base = args.target.split('?')[0]
    ids = args.ids.split(",")
    results = {}
    for uid in ids:
        import urllib.request
        target = f"{base}?{args.param}={uid.strip()}"
        try:
            req = urllib.request.Request(target)
            resp = urllib.request.urlopen(req, timeout=10)
            results[uid] = {"status": resp.getcode(), "len": len(resp.read())}
        except urllib.request.HTTPError as e:
            results[uid] = {"status": e.code, "error": True}
        except Exception as e:
            results[uid] = {"error": str(e)}

    statuses = [v.get("status", 0) for v in results.values()]
    if len(set(statuses)) > 1:
        print("[+] 检测到 IDOR 响应差异!")
    for uid, v in results.items():
        print(f"  id={uid}: {v}")

if __name__ == "__main__":
    main()
