#!/usr/bin/env python3
"""
CNVD-2020-25191: 泛微 E-Cology 文件上传
- 类型: OA/CMS 漏洞
- 描述: weaver接口文件上传
- 参考: https://www.cnvd.org.cn/ (搜索 CNVD-2020-25191)
"""
import argparse, urllib.request, ssl

BANNER = "CNVD-2020-25191 - 泛微 E-Cology 文件上传"

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
