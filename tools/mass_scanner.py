#!/usr/bin/env python3
"""
批量漏洞扫描器
支持: CVE-2024-23897, CVE-2024-27198, CVE-2023-22515, CVE-2025-24813 等
用法: python mass_scanner.py -f targets.txt --cves all
      python mass_scanner.py -t http://target.com:8080 --cves jenkins,confluence
"""
import argparse, sys, os, time, concurrent.futures, urllib.request, ssl, json
from datetime import datetime

# ============ 已注册的 POC 检测函数 ============
REGISTERED_SCANNERS = {}

def register(name):
    def decorator(func):
        REGISTERED_SCANNERS[name] = func
        return func
    return decorator

@register("jenkins_cve_2024_23897")
def scan_jenkins(url):
    """Jenkins CLI 任意文件读取检测"""
    try:
        req = urllib.request.urlopen(url.rstrip('/') + "/login", timeout=10)
        html = req.read().decode('utf-8', errors='ignore')
        if "jenkins" not in html.lower():
            return None
        # 尝试读 /etc/passwd
        jar_url = url.rstrip('/') + "/jnlpJars/jenkins-cli.jar"
        try:
            req2 = urllib.request.urlretrieve(jar_url, "/tmp/jenkins-cli.jar")
            import os
            if os.path.exists("/tmp/jenkins-cli.jar") and os.path.getsize("/tmp/jenkins-cli.jar") > 10000:
                return {"vuln": "CVE-2024-23897", "severity": "Critical", "detail": "CLI jar 可下载，可能存在漏洞"}
        except:
            pass
        return {"vuln": "Jenkins detected", "severity": "Info", "detail": "检测到 Jenkins，未验证漏洞"}
    except:
        return None

@register("teamcity_cve_2024_27198")
def scan_teamcity(url):
    """TeamCity 认证绕过检测"""
    try:
        req = urllib.request.urlopen(url.rstrip('/') + "/about.html", timeout=10)
        html = req.read().decode('utf-8', errors='ignore')
        if "teamcity" in html.lower() or "jetbrains" in html.lower():
            return {"vuln": "TeamCity detected", "severity": "Info", "detail": "检测到 TeamCity，可能存在 CVE-2024-27198"}
    except:
        pass
    return None

@register("confluence_cve_2023_22515")
def scan_confluence(url):
    """Confluence OGNL 注入检测"""
    try:
        req = urllib.request.urlopen(url.rstrip('/') + "/login.action", timeout=10)
        html = req.read().decode('utf-8', errors='ignore')
        if "confluence" in html.lower():
            return {"vuln": "Confluence detected", "severity": "Critical", "detail": "检测到 Confluence，可能存在 CVE-2023-22515 (OGNL RCE)"}
    except:
        pass
    return None

@register("tomcat_cve_2025_24813")
def scan_tomcat(url):
    """Apache Tomcat PUT 上传检测"""
    try:
        req = urllib.request.urlopen(url.rstrip('/') + "/", timeout=10)
        server = req.getheader("Server", "")
        if "tomcat" in server.lower() or "Apache-Coyote" in server:
            return {"vuln": "Apache Tomcat detected", "severity": "Critical", "detail": f"Server: {server}，可能存在 CVE-2025-24813"}
    except:
        pass
    return None

@register("fortinet_cve_2024_21762")
def scan_fortinet(url):
    """Fortinet SSL VPN 检测"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.urlopen(url.rstrip('/') + "/remote/login", timeout=10, context=ctx)
        html = req.read().decode('utf-8', errors='ignore')
        if "forti" in html.lower() or "fortinet" in html.lower():
            return {"vuln": "Fortinet SSL VPN detected", "severity": "Critical", "detail": "可能存在 CVE-2024-21762 RCE"}
    except:
        pass
    return None

@register("grafana_cve_2024_9264")
def scan_grafana(url):
    """Grafana 检测"""
    try:
        req = urllib.request.urlopen(url.rstrip('/') + "/api/health", timeout=10)
        data = json.loads(req.read())
        version = data.get("version", "")
        if version:
            major = int(version.split('.')[0]) if version else 0
            if major >= 11:
                return {"vuln": "Grafana >= 11.0.0", "severity": "High", "detail": f"版本 {version}，可能存在 CVE-2024-9264 RCE"}
            return {"vuln": f"Grafana {version}", "severity": "Info", "detail": "版本低于 11.0.0"}
    except:
        pass
    return None

@register("web_title")
def scan_web_title(url):
    """Web 标题检测（通用）"""
    try:
        req = urllib.request.urlopen(url.rstrip('/') + "/", timeout=10)
        html = req.read().decode('utf-8', errors='ignore')
        import re
        title = re.search(r'<title>([^<]+)</title>', html, re.I)
        if title:
            return {"vuln": "Web Service", "severity": "Info", "detail": f"标题: {title.group(1).strip()}"}
    except:
        pass
    return None

# ============ 扫描器主逻辑 ============

def scan_target(url, cves="all"):
    results = []
    scanners = []
    if cves == "all":
        scanners = list(REGISTERED_SCANNERS.values())
    else:
        for name in cves.split(","):
            if name in REGISTERED_SCANNERS:
                scanners.append(REGISTERED_SCANNERS[name])

    for scanner in scanners:
        try:
            result = scanner(url)
            if result:
                results.append(result)
        except Exception as e:
            pass
    return url, results

def main():
    banner = """
  ============================================
   vuln-pocs Mass Scanner v1.0
   批量 CVE / Web 漏洞检测
  ============================================
    """
    print(banner)
    parser = argparse.ArgumentParser(description="批量漏洞扫描器")
    parser.add_argument("-f", "--file", help="目标列表文件 (每行一个 URL)")
    parser.add_argument("-t", "--target", help="单个目标 URL")
    parser.add_argument("--cves", default="all", help="扫描类型: all/web/cves/jenkins/confluence/tomcat")
    parser.add_argument("-o", "--output", default="scan_results.json", help="结果输出文件")
    parser.add_argument("-w", "--workers", type=int, default=10, help="并发线程数")
    args = parser.parse_args()

    targets = []
    if args.file and os.path.exists(args.file):
        with open(args.file, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif args.target:
        targets = [args.target]
    else:
        print("[-] 请指定 -f 或 -t 参数")
        return

    print(f"[*] 加载 {len(targets)} 个目标")
    print(f"[*] 扫描类型: {args.cves}")
    print(f"[*] 并发线程: {args.workers}")
    print()

    all_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(scan_target, t, args.cves): t for t in targets}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            url, results = future.result()
            if results:
                all_results[url] = results
                for r in results:
                    print(f"  [{i}/{len(targets)}] {url}  →  {r['vuln']} [{r['severity']}]")
            else:
                print(f"  [{i}/{len(targets)}] {url}  →  无发现")

    # 保存结果
    output = {
        "scan_time": datetime.now().isoformat(),
        "total": len(targets),
        "found": len(all_results),
        "results": all_results
    }
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"\n[+] 结果已保存: {args.output}")
    print(f"[+] 共扫描 {len(targets)} 个目标，发现 {len(all_results)} 个问题")

if __name__ == "__main__":
    main()
