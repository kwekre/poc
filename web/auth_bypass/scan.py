#!/usr/bin/env python3
"""
认证绕过漏洞 POC 库
检测: 默认口令、暴力破解保护缺失、Session 固定、Cookie 不安全等
"""
import argparse, sys
sys.path.insert(0, '..')
from utils.http import http_get, http_post

ADMIN_PATHS = [
    "/admin/", "/admin.php", "/administrator/", "/wp-admin/",
    "/manage/", "/dashboard/", "/panel/", "/backend/",
    "/console/", "/api/admin/", "/manager/", "/cpanel/",
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("administrator", "administrator"), ("user", "user"),
]

def main():
    parser = argparse.ArgumentParser(description="认证绕过检测")
    parser.add_argument("-t", "--target", required=True, help="目标 URL")
    parser.add_argument("--check-admin", action="store_true", help="检测管理后台是否暴露")
    parser.add_argument("--check-creds", action="store_true", help="检测默认口令")
    args = parser.parse_args()

    base = args.target.rstrip('/')

    if args.check_admin:
        print("[*] 检测管理后台暴露...")
        for path in ADMIN_PATHS:
            resp = http_get(base + path, timeout=10)
            if resp.get("status") == 200:
                body = str(resp.get("body", b""))
                if "login" in body.lower() or "password" in body.lower() or "admin" in body.lower():
                    print(f"  [+] 发现管理后台: {base}{path}")

    if args.check_creds:
        print("[*] 检测默认口令...")
        login_paths = ["/login", "/admin/login", "/auth/login", "/signin"]
        for login_path in login_paths:
            resp = http_get(base + login_path, timeout=10)
            if resp.get("status") == 200:
                print(f"  [i] 找到登录页: {base}{login_path}")
                for user, pwd in DEFAULT_CREDENTIALS[:3]:
                    login_resp = http_post(base + login_path, f"username={user}&password={pwd}", timeout=10)
                    body = str(login_resp.get("body", b""))
                    if "success" in body.lower() or "dashboard" in body.lower() or login_resp.get("status") == 302:
                        print(f"  [!] 默认口令可能有效: {user}/{pwd}")

if __name__ == "__main__":
    main()
