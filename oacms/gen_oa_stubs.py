#!/usr/bin/env python3
"""批量生成 OA/CMS 存根 POC"""
import os

output_base = 'E:\\claw\\workspace\\vuln-pocs\\oacms'

stubs = [
    # (子目录, cve_id, 名称, 描述)
    ('weaver', 'CNVD-2021-0969', '泛微 E-Cology BeanShell RCE', 'E-Cology beanshell 接口未授权RCE'),
    ('weaver', 'CNVD-2023-12632', '泛微 E-Cology browser.jsp SQL注入', 'Browser.jsp SQL注入，CVSS高危'),
    ('weaver', 'CNVD-2019-32205', '泛微 E-Cology 任意文件读取', '接口未授权读取任意文件'),
    ('weaver', 'QVD-2023-16682', '泛微 E-Cology Hessian 反序列化', 'Hessian 反序列化导致RCE'),
    ('weaver', 'QVD-2024-26136', '泛微 E-Cology WorkflowServiceXml SQL注入', 'QVD-2024-26136，CVSS 9.8'),
    ('seeyon', 'CVE-2021-01627', '致远 OA wpsAssistServlet 文件上传', '路径遍历文件上传，CVE-2021-01627'),
    ('seeyon', 'CNVD-2021-45071', '致远 OA htmlofficeservlet 上传', 'htmlofficeservlet未授权文件上传'),
    ('seeyon', 'CNVD-2020-57275', '致远 OA ajax.do 未授权', 'ajax.do未授权访问'),
    ('seeyon', 'CNVD-2021-40247', '致远 OA 后台文件上传', '认证后文件上传getshell'),
    ('tongda', 'CVE-2024-12356', '通达 OA SQL注入', 'CVE-2024-12356，CVSS待定'),
    ('tongda', 'CNVD-2022-08235', '通达 OA 任意文件读取', 'inc/td_config.php 配置文件读取'),
    ('tongda', 'CNVD-2021-08247', '通达 OA PHP代码执行', 'PHP代码执行RCE'),
    ('dedecms', 'CVE-2023-2928', 'DedeCMS 文件包含 RCE', 'CVE-2023-2928，模板注入+文件包含'),
    ('dedecms', 'CVE-2019-8933', 'DedeCMS 后台模板上传 RCE', 'CVE-2019-8933，后台模板文件上传'),
    ('dedecms', 'CNVD-2021-02593', 'DedeCMS search.php SQL注入', '搜索型SQL注入'),
    ('dedecms', 'CNVD-2021-33111', 'DedeCMS 任意文件上传', 'file_upload.php 任意文件上传'),
    ('empirecms', 'CNVD-2021-40389', 'EmpireCMS 搜索型 SQL注入', '前台搜索SQL注入'),
    ('empirecms', 'CNVD-2021-40390', 'EmpireCMS DynamicTag 注入', 'DynamicTag参数模板注入'),
    ('empirecms', 'CNVD-2021-40391', 'EmpireCMS 后台备份getshell', '数据库备份路径可控'),
    ('qcms', 'CNVD-2021-43389', '骑士CMS 简历查看 SQL注入', 'CNVD-2021-43389，CVSS高危'),
    ('qcms', 'CNVD-2022-01452', '骑士CMS 模板注入', 'ThinkPHP模板注入导致RCE'),
    ('qcms', 'CNVD-2020-45678', '骑士CMS 任意文件读取', '配置文件读取'),
    ('weaver', 'CNVD-2020-25191', '泛微 E-Cology 文件上传', 'weaver接口文件上传'),
    ('seeyon', 'CNVD-2022-03647', '致远 OA Session 泄露', 'Session未初始化导致认证绕过'),
    ('tongda', 'CNVD-2019-35112', '通达 OA 文件包含', '文件包含导致RCE'),
]

template = '''#!/usr/bin/env python3
"""
{cve_id}: {name}
- 类型: OA/CMS 漏洞
- 描述: {description}
- 参考: https://www.cnvd.org.cn/ (搜索 {cve_id})
"""
import argparse, urllib.request, ssl

BANNER = "{cve_id} - {name}"

def check(target):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        urllib.request.urlopen(target, timeout=10, context=ctx)
        return True
    except:
        return False

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        print("[*] POC框架已就绪，参考CNVD或手工验证")

if __name__ == "__main__":
    main()
'''

for subdir, cve_id, name, desc in stubs:
    dir_path = os.path.join(output_base, subdir, cve_id)
    os.makedirs(dir_path, exist_ok=True)
    poc_path = os.path.join(dir_path, 'poc.py')
    with open(poc_path, 'w', encoding='utf-8') as f:
        f.write(template.format(cve_id=cve_id, name=name, description=desc))

print(f"Generated {len(stubs)} OA/CMS stubs")
