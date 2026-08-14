#!/usr/bin/env python3
"""
CNVD-2021-45071: 致远 OA htmlofficeservlet 上传
- 类型: OA/CMS 漏洞
- 描述: htmlofficeservlet未授权文件上传
- 参考: https://www.cnvd.org.cn/ (搜索 CNVD-2021-45071)
"""
import argparse, urllib.request, ssl

BANNER = "CNVD-2021-45071 - 致远 OA htmlofficeservlet 上传"

def check(target):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        urllib.request.urlopen(target, timeout=10, context=ctx)
        return True
    except:
        return False

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        print("[*] POC框架已就绪，参考CNVD或手工验证")

if __name__ == "__main__":
    main()
