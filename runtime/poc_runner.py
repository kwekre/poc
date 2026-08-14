#!/usr/bin/env python3
"""
POC Runner - 统一调度框架
支持四种模式：
  1. 单 POC → 单 URL      (python runner.py -p xxx.py -t http://target)
  2. 单 POC → 多 URL      (python runner.py -p xxx.py -f urls.txt)
  3. 多 POC → 单 URL      (python runner.py -f pocs.txt -t http://target)
  4. 多 POC → 多 URL      (python runner.py -f pocs.txt -f urls.txt) ★
"""
import sys, os, argparse, json, time, ssl, subprocess
from pathlib import Path
from datetime import datetime

# 路径
BASE_DIR = Path(__file__).parent.parent.resolve()
CVE_DIR = BASE_DIR / "cves"
OACMS_DIR = BASE_DIR / "oacms"
WEB_DIR = BASE_DIR / "web"
REGISTRY_FILE = BASE_DIR / "runtime" / "poc_registry.json"

BANNER = r"""
  ╔══════════════════════════════════════════╗
  ║     POC Runner - 漏洞 POC 调度框架       ║
  ║   1 POC × 1 URL | 1 × N | N × 1 | N × N ║
  ╚══════════════════════════════════════════╝
"""

class Colors:
    RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, RESET = (
        "\033[91m", "\033[92m", "\033[93m", "\033[94m",
        "\033[95m", "\033[96m", "\033[0m"
    )

def cprint(msg, color="RESET"):
    print(f"{getattr(Colors, color)}{msg}{Colors.RESET}")

def load_registry():
    """加载 POC 注册表"""
    if REGISTRY_FILE.exists():
        with open(REGISTRY_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    # 自动扫描生成注册表
    return scan_and_register()

def scan_and_register():
    """扫描所有 POC 并生成注册表"""
    registry = {}
    # CVE POC
    for d in CVE_DIR.iterdir():
        if d.is_dir() and d.name.startswith("CVE-"):
            poc = d / "poc.py"
            if poc.exists():
                registry[d.name] = {
                    "path": str(poc.relative_to(BASE_DIR)),
                    "type": "cve",
                    "module": guess_module(poc),
                }
        elif d.is_dir():
            # oacms/weaver/ 这种
            for sub in d.iterdir():
                if sub.suffix == ".py":
                    registry[d.name + "_" + sub.stem] = {
                        "path": str(sub.relative_to(BASE_DIR)),
                        "type": "oacms" if "oacms" in str(sub) else "script",
                        "module": guess_module(sub),
                    }
    # OACMS 目录
    for sys_dir in OACMS_DIR.iterdir():
        if sys_dir.is_dir():
            for poc_file in sys_dir.rglob("*.py"):
                if poc_file.name in ("__init__.py", "gen_oa_stubs.py"):
                    continue
                key = f"{sys_dir.name}_{poc_file.stem}"
                registry[key] = {
                    "path": str(poc_file.relative_to(BASE_DIR)),
                    "type": "oacms",
                    "module": guess_module(poc_file),
                }
    # 保存注册表
    with open(REGISTRY_FILE, 'w', encoding='utf-8') as f:
        json.dump(registry, f, ensure_ascii=False, indent=2)
    return registry

def guess_module(poc_path):
    """从文件名猜测漏洞类型"""
    name = poc_path.name.lower()
    if any(x in name for x in ["sqli", "sql", "注入"]):
        return "sql_injection"
    if any(x in name for x in ["rce", "exec", "command", "命令"]):
        return "rce"
    if any(x in name for x in ["upload", "文件上传"]):
        return "upload"
    if any(x in name for x in ["lfi", "file_read", "文件读取", "任意文件"]):
        return "file_read"
    if any(x in name for x in ["xss"]):
        return "xss"
    if any(x in name for x in ["auth", "bypass", "认证"]):
        return "auth_bypass"
    if any(x in name for x in ["ssrf"]):
        return "ssrf"
    if any(x in name for x in ["xxe"]):
        return "xxe"
    return "general"

def list_pocs(registry, filter_type=None, keyword=None):
    """列出所有 POC"""
    items = list(registry.items())
    if filter_type:
        items = [(k, v) for k, v in items if v.get("type") == filter_type]
    if keyword:
        items = [(k, v) for k, v in items
                 if keyword.lower() in k.lower() or keyword.lower() in v.get("path","").lower()]

    print(f"\n{'='*65}")
    cprint(f"  共找到 {len(items)} 个 POC", "CYAN")
    print(f"{'='*65}")
    print(f"{'序号':<5} {'名称':<35} {'类型':<12} {'路径'}")
    print(f"{'-'*65}")
    for i, (k, v) in enumerate(items, 1):
        t = v.get("type","?")
        p = v.get("path","")
        t_color = {"cve":"MAGENTA","oacms":"YELLOW","web":"BLUE","script":"CYAN"}.get(t,"")
        print(f"{i:<5} {k[:33]:<35} {cprint(t, t_color) or t:<12} {p}")
    return items

def run_poc(poc_path, target, timeout=30):
    """运行单个 POC，返回 (成功, 输出)"""
    poc_abs = BASE_DIR / poc_path
    if not poc_abs.exists():
        return False, f"文件不存在: {poc_abs}"

    target = target.rstrip('/')
    try:
        result = subprocess.run(
            [sys.executable, str(poc_abs), "-t", target, "--check"],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='ignore',
            cwd=str(BASE_DIR)
        )
        output = result.stdout + result.stderr
        # 判断是否可能存在漏洞（响应长度/关键字）
        vulnerable = any(kw in output.lower() for kw in [
            "存在", "vulnerable", "确认", "confirmed", "可能", "候选",
            "延迟", "delay", "found", "success", "[+]"
        ])
        return vulnerable, output
    except subprocess.TimeoutExpired:
        return False, "[!] 超时"
    except Exception as ex:
        return False, f"[!] 错误: {ex}"

def scan_multi_poc_multi_url(poc_names, targets, registry, delay=1):
    """模式4: 多 POC × 多 URL"""
    results = {}
    total = len(poc_names) * len(targets)
    current = 0

    cprint(f"\n[*] 开始扫描: {len(poc_names)} 个 POC × {len(targets)} 个目标 = {total} 次", "YELLOW")
    print(f"[*] 延迟: {delay}s\n")

    for poc_name in poc_names:
        if poc_name not in registry:
            cprint(f"[-] 未知 POC: {poc_name}", "RED")
            continue
        info = registry[poc_name]
        poc_path = info["path"]
        results[poc_name] = {}

        for target in targets:
            current += 1
            cprint(f"  [{current}/{total}] {poc_name} -> {target}", "BLUE")

            vuln, output = run_poc(poc_path, target)
            results[poc_name][target] = {"vulnerable": vuln, "output": output[:500]}

            if vuln:
                cprint(f"    [!] 可能存在漏洞!", "GREEN")
            else:
                cprint(f"    [-] 未发现", "RESET")

            time.sleep(delay)

    return results

def scan_multi_poc_single_url(poc_names, target, registry, delay=1):
    """模式3: 多 POC × 单 URL"""
    results = {}
    for i, poc_name in enumerate(poc_names, 1):
        if poc_name not in registry:
            cprint(f"[-] 未知: {poc_name}", "RED")
            continue
        info = registry[poc_name]
        poc_path = info["path"]
        cprint(f"  [{i}/{len(poc_names)}] {poc_name}", "CYAN")
        vuln, output = run_poc(poc_path, target)
        results[poc_name] = {"vulnerable": vuln, "output": output[:500]}
        cprint(f"    {'[!] 可能存在' if vuln else '[-] 未发现'}", "GREEN" if vuln else "RESET")
        time.sleep(delay)
    return results

def scan_single_poc_multi_url(poc_name, targets, registry, delay=1):
    """模式2: 单 POC × 多 URL"""
    if poc_name not in registry:
        cprint(f"[-] 未知 POC: {poc_name}", "RED")
        return None
    info = registry[poc_name]
    poc_path = info["path"]
    results = {}
    for i, target in enumerate(targets, 1):
        cprint(f"  [{i}/{len(targets)}] {target}", "BLUE")
        vuln, output = run_poc(poc_path, target)
        results[target] = {"vulnerable": vuln, "output": output[:500]}
        cprint(f"    {'[!] 可能存在' if vuln else '[-] 未发现'}", "GREEN" if vuln else "RESET")
        time.sleep(delay)
    return results

def save_results(results, out_file=None):
    """保存扫描结果"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = out_file or str(BASE_DIR / "runtime" / f"scan_results_{timestamp}.json")

    # 统计
    vuln_count = sum(
        1 for r in results.values()
        for v in r.values()
        if v.get("vulnerable")
    )

    data = {
        "timestamp": timestamp,
        "total_vulnerabilities": vuln_count,
        "results": results,
    }

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # 打印摘要
    print(f"\n{'='*65}")
    cprint(f"  扫描完成 | 发现 {vuln_count} 个可能漏洞", "GREEN" if vuln_count else "YELLOW")
    print(f"  结果已保存: {out_path}")
    print(f"{'='*65}")

    # 列出发现的漏洞
    if vuln_count:
        cprint("\n  漏洞汇总:", "GREEN")
        for poc_name, targets in results.items():
            vulns = [t for t, r in targets.items() if r.get("vulnerable")]
            if vulns:
                print(f"  {Colors.MAGENTA}{poc_name}{Colors.RESET}:")
                for t in vulns:
                    print(f"    {Colors.GREEN}[+]{Colors.RESET} {t}")

    return out_path

def auto_detect_and_scan(target, registry):
    """自动识别目标指纹，匹配合适的 POC"""
    cprint(f"\n[*] 自动识别目标: {target}", "YELLOW")
    fingerprint = auto_fingerprint(target)
    if fingerprint:
        cprint(f"  [+] 识别结果: {fingerprint}", "GREEN")
    else:
        cprint(f"  [!] 未识别，使用全量扫描", "YELLOW")

    # 匹配 POC
    matched = []
    for name, info in registry.items():
        if fingerprint and fingerprint.lower() in name.lower():
            matched.append(name)
        elif info.get("module") in ["sql_injection", "rce", "file_read", "upload", "auth_bypass"]:
            matched.append(name)

    matched = list(set(matched))[:50]  # 限制数量
    cprint(f"  [*] 匹配到 {len(matched)} 个适用 POC\n", "CYAN")
    return matched, fingerprint

def auto_fingerprint(target):
    """指纹识别"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        import urllib.request
        req = urllib.request.urlopen(target.rstrip('/') + "/", timeout=10, context=ctx)
        html = req.read().decode('utf-8', errors='ignore').lower()

        if "weaver" in html or "泛微" in html:
            return "weaver"
        if "seeyon" in html or "致远" in html:
            return "seeyon"
        if "tongda" in html or "通达" in html:
            return "tongda"
        if "dedecms" in html or "织梦" in html:
            return "dedecms"
        if "empire" in html or "帝国" in html:
            return "empirecms"
        if "74cms" in html or "骑士" in html:
            return "74cms"
        if "confluence" in html:
            return "confluence"
        if "jenkins" in html:
            return "jenkins"
        if "grafana" in html:
            return "grafana"
        if "fortinet" in html or "fortigate" in html:
            return "fortinet"
        if "wordpress" in html or "wp-" in html:
            return "wordpress"
        if "tomcat" in html:
            return "tomcat"
        if "nginx" in html:
            return "nginx"
    except:
        pass
    return None

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="POC Runner - 统一调度框架")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--poc", help="单个 POC 名称或路径")
    group.add_argument("-f", "--poc-file", dest="poc_file", help="包含多个 POC 名称的文件")
    group.add_argument("-l", "--list", action="store_true", help="列出所有 POC")
    group.add_argument("--list-cve", action="store_true", help="仅列出 CVE POC")
    group.add_argument("--list-oacms", action="store_true", help="仅列出 OA/CMS POC")
    group.add_argument("--auto", metavar="URL", help="自动识别目标并匹配合适 POC")

    parser.add_argument("-t", "--target", help="单个目标 URL")
    parser.add_argument("-u", "--url-file", dest="url_file",
                        help="包含多个 URL 的文件（每行一个）")
    parser.add_argument("-o", "--output", help="输出文件 (.json)")
    parser.add_argument("-d", "--delay", type=float, default=1.0, help="请求间隔 (秒)")
    parser.add_argument("--timeout", type=int, default=30, help="单个 POC 超时 (秒)")
    parser.add_argument("-m", "--module", help="按模块过滤, 如: sql_injection,rce")
    parser.add_argument("-k", "--keyword", help="按关键字过滤 POC 名称")
    parser.add_argument("--type", choices=["cve","oacms","web","all"], default="all",
                        help="按类型过滤")
    args = parser.parse_args()

    # 加载注册表
    registry = load_registry()
    cprint(f"[*] 已加载 {len(registry)} 个 POC\n", "CYAN")

    # 列出模式
    if args.list:
        items = list_pocs(registry, filter_type=args.type if args.type != "all" else None,
                           keyword=args.keyword)
        return
    if args.list_cve:
        items = list_pocs(registry, filter_type="cve")
        return
    if args.list_oacms:
        items = list_pocs(registry, filter_type="oacms")
        return

    # 自动模式
    if args.auto:
        target = args.auto
        matched, fingerprint = auto_detect_and_scan(target, registry)
        if not matched:
            cprint("[!] 未匹配到 POC，尝试全量扫描", "YELLOW")
            matched = list(registry.keys())
        targets = [target]
        poc_names = matched
        results = scan_multi_poc_single_url(poc_names, target, registry, args.delay)
        if results:
            save_results({p: {target: r} for p, r in results.items()}, args.output)
        return

    # 解析 POC 列表
    if args.poc_file:
        with open(args.poc_file, 'r', encoding='utf-8') as f:
            poc_names = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    elif args.poc:
        poc_names = [args.poc]
    else:
        cprint("[-] 请指定 -p 或 -f", "RED")
        return

    # 过滤
    if args.keyword:
        poc_names = [n for n in poc_names if args.keyword.lower() in n.lower()]
    if args.module:
        mods = args.module.split(",")
        poc_names = [n for n in poc_names if registry.get(n, {}).get("module") in mods]

    # 解析 URL 列表
    if args.url_file:
        with open(args.url_file, 'r', encoding='utf-8') as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    elif args.target:
        targets = [args.target]
    else:
        cprint("[-] 请指定 -t 或 -u", "RED")
        return

    # 执行
    cprint(f"[*] 模式: {len(poc_names)} POC × {len(targets)} URL\n", "YELLOW")

    if len(poc_names) == 1 and len(targets) == 1:
        # 模式1
        vuln, output = run_poc(registry[poc_names[0]]["path"], targets[0], args.timeout)
        print(output)
        cprint(f"\n{'[!] 可能存在漏洞' if vuln else '[-] 未发现漏洞'}", "GREEN" if vuln else "RESET")
    elif len(poc_names) == 1:
        # 模式2
        results = scan_single_poc_multi_url(poc_names[0], targets, registry, args.delay)
        save_results(results, args.output)
    elif len(targets) == 1:
        # 模式3
        results = scan_multi_poc_single_url(poc_names, targets[0], registry, args.delay)
        save_results(results, args.output)
    else:
        # 模式4
        results = scan_multi_poc_multi_url(poc_names, targets, registry, args.delay)
        save_results(results, args.output)

if __name__ == "__main__":
    main()
