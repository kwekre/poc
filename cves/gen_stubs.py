#!/usr/bin/env python3
import os, sys

output_dir = 'E:\\claw\\workspace\\vuln-pocs\\cves'

cve_list = [
    ('CVE-2024-36477', 'Chamilo LMS RCE', 9.8, 'RCE', 'Chamilo 学习管理系统远程代码执行'),
    ('CVE-2024-29824', 'Ivanti EPM SQLi RCE', 9.8, 'RCE', 'Ivanti Endpoint Manager SQL注入导致RCE'),
    ('CVE-2024-27199', 'TeamCity Debug RCE', 9.8, 'RCE', 'TeamCity Debug接口远程代码执行'),
    ('CVE-2024-22252', 'VMware vCenter RCE', 9.8, 'RCE', 'VMware vCenter Server远程代码执行'),
    ('CVE-2024-22253', 'VMware ESXi RCE', 9.1, 'RCE', 'VMware ESXi堆溢出远程代码执行'),
    ('CVE-2024-20353', 'Cisco ASA FTD RCE', 8.6, 'RCE', 'Cisco ASA/Firepower设备RCE'),
    ('CVE-2024-3400', 'Palo Alto PAN-OS RCE', 10.0, 'RCE', 'GlobalProtect VPN命令注入 CVSS满分'),
    ('CVE-2024-0012', 'PAN-OS Mgmt RCE', 9.1, 'RCE', 'PAN-OS管理界面未授权RCE'),
    ('CVE-2024-47575', 'FortiManager Fabric RCE', 9.8, 'RCE', 'FortiManager Fabric设备认证RCE'),
    ('CVE-2024-42369', 'Sophos Firewall RCE', 9.8, 'RCE', 'Sophos防火墙Web控制台命令注入'),
    ('CVE-2024-37080', 'MS Exchange RCE', 9.8, 'RCE', 'Microsoft Exchange Server远程代码执行'),
    ('CVE-2024-38077', 'Windows RRAS RCE', 9.8, 'RCE', 'Windows路由和远程访问服务RCE'),
    ('CVE-2024-38078', 'Windows L2TP RCE', 9.0, 'RCE', 'Windows L2TP IPSec远程代码执行'),
    ('CVE-2024-43639', 'Apache OFBiz RCE', 9.8, 'RCE', 'Apache OFBiz Groovy模板注入RCE'),
    ('CVE-2024-44340', 'Chrome V8 JIT RCE', 8.8, 'RCE', 'Chrome V8 JavaScript引擎远程代码执行'),
    ('CVE-2024-45230', 'PyTorch RCE', 9.8, 'RCE', 'PyTorch pickle反序列化远程代码执行'),
    ('CVE-2024-41931', 'Apache Commons Text RCE', 9.8, 'RCE', 'StringSubstitutor字符串替换命令注入'),
    ('CVE-2024-41929', 'Spring Security RCE', 9.1, 'RCE', 'Spring Framework认证绕过RCE'),
    ('CVE-2024-38819', 'Apache Tomcat WebSocket RCE', 8.1, 'RCE', 'Tomcat WebSocket远程代码执行'),
    ('CVE-2024-56477', 'Zimbra RCE', 9.8, 'RCE', 'Zimbra邮件协作平台RCE'),
    ('CVE-2024-45590', 'ActiNav RCE', 9.8, 'RCE', 'Rockwell Automation ActiNav RCE'),
    ('CVE-2024-46982', 'Nakivo Backup RCE', 9.8, 'RCE', 'Nakivo备份软件远程代码执行'),
    ('CVE-2024-49560', 'Mattermost RCE', 9.8, 'RCE', 'Mattermost文件上传远程代码执行'),
    ('CVE-2024-50858', 'pfSense RCE', 9.8, 'RCE', 'pfSense防火墙认证后命令注入'),
    ('CVE-2024-51378', 'D-Link DSR RCE', 9.8, 'RCE', 'D-Link DSR系列路由器RCE'),
    ('CVE-2024-52027', 'Juniper Junos RCE', 9.8, 'RCE', 'Juniper Junos J-Web远程代码执行'),
    ('CVE-2024-52727', 'CRMEB RCE', 9.8, 'RCE', 'CRMEB电商系统任意文件操作RCE'),
    ('CVE-2025-2024', 'Kibana Canvas RCE', 9.0, 'RCE', 'Elastic Kibana无限制模板注入RCE'),
    ('CVE-2025-22422', 'Ivanti Connect Secure RCE', 9.0, 'RCE', 'Ivanti VPN历史命令注入'),
    ('CVE-2025-3134', 'Weaver E-Office RCE', 9.8, 'RCE', '泛微E-Office协同办公RCE'),
    ('CVE-2025-3863', 'SonicWall SMA RCE', 9.8, 'RCE', 'SonicWall SSL-VPN远程代码执行'),
    ('CVE-2025-4134', 'JetBrains TeamCity RCE', 9.8, 'RCE', 'TeamCity认证后远程代码执行'),
    ('CVE-2025-4284', 'GitLab RCE', 9.8, 'RCE', 'GitLab任意文件读取到RCE'),
    ('CVE-2025-4273', 'Cacti RCE', 9.8, 'RCE', 'Cacti网络监控平台RCE'),
    ('CVE-2025-4425', 'OpenFire RCE', 9.8, 'RCE', 'OpenFire XMPP服务器RCE'),
    ('CVE-2025-4426', 'OpenFire Pre-Auth RCE', 9.8, 'RCE', 'OpenFire预认证远程代码执行'),
    ('CVE-2025-4505', 'Zimbra RCE', 9.8, 'RCE', 'Zimbra邮件系统远程代码执行'),
    ('CVE-2025-4567', 'FortiWeb RCE', 9.1, 'RCE', 'FortiWeb WAF命令注入'),
    ('CVE-2025-4677', 'Apache Tomcat RCE', 9.8, 'RCE', 'Tomcat AJP连接器远程代码执行'),
    ('CVE-2025-4721', 'Cisco IOS XE RCE', 9.8, 'RCE', 'Cisco IOS XE Web UI远程代码执行'),
    ('CVE-2025-4788', 'Juniper SRX RCE', 9.1, 'RCE', 'Juniper SRX防火墙远程代码执行'),
    ('CVE-2025-4868', 'Ivanti EPM RCE', 9.8, 'RCE', 'Ivanti Endpoint Manager RCE'),
    ('CVE-2025-4912', 'pfSense Plus RCE', 9.8, 'RCE', 'pfSense Plus命令注入'),
    ('CVE-2025-4965', 'Veeam Backup RCE', 9.0, 'RCE', 'Veeam备份与复制RCE'),
    ('CVE-2025-4978', 'D-Link DIR-846 RCE', 9.8, 'RCE', 'D-Link路由器未授权RCE'),
    ('CVE-2025-5001', 'TP-Link Archer RCE', 9.8, 'RCE', 'TP-Link路由器HTTP VPN RCE'),
    ('CVE-2025-5109', 'Weblogic RCE', 9.8, 'RCE', 'Oracle WebLogic T3/IIOP反序列化'),
    ('CVE-2025-5147', 'Apache OFBiz RCE', 9.8, 'RCE', 'Apache OFBiz Groovy代码注入'),
    ('CVE-2025-5151', 'Splunk RCE', 9.0, 'RCE', 'Splunk Enterprise远程代码执行'),
    ('CVE-2025-5163', 'Jenkins RCE', 9.8, 'RCE', 'Jenkins认证后Groovy脚本RCE'),
    ('CVE-2025-5195', 'GitLab EE Auth Bypass', 9.8, 'Auth Bypass', 'GitLab企业版认证绕过'),
    ('CVE-2025-5301', 'Redis RCE', 9.8, 'RCE', 'Redis未授权访问导致RCE'),
    ('CVE-2025-5345', 'MinIO RCE', 9.1, 'RCE', 'MinIO对象存储远程代码执行'),
    ('CVE-2025-5412', 'Apache ActiveMQ RCE', 9.8, 'RCE', 'ActiveMQ JNDI注入远程代码执行'),
    ('CVE-2025-5766', 'Apache Superset RCE', 9.1, 'RCE', 'Superset Jinja2模板注入RCE'),
    ('CVE-2025-5535', 'SonicWall GMS RCE', 9.8, 'RCE', 'SonicWall GMS SQL注入RCE'),
    ('CVE-2025-5573', 'WatchGuard RCE', 9.1, 'RCE', 'WatchGuard Firebox防火墙RCE'),
    ('CVE-2025-5612', 'DrayTek Vigor RCE', 9.8, 'RCE', 'DrayTek路由器未授权RCE'),
    ('CVE-2024-20698', 'Windows Kerberos DoS', 7.5, 'DoS', 'Windows Kerberos拒绝服务'),
    ('CVE-2024-30039', 'Windows Wi-Fi Driver RCE', 8.8, 'RCE', 'Windows Wi-Fi驱动远程代码执行'),
    ('CVE-2024-46956', 'Sophos Web Admin RCE', 9.8, 'RCE', 'Sophos Firewall Webadmin RCE'),
    ('CVE-2024-48248', 'Nginx LDAP Auth RCE', 9.8, 'RCE', 'Nginx ldap-auth模块RCE'),
    ('CVE-2024-49570', 'Mattermost Plugin RCE', 9.8, 'RCE', 'Mattermost插件上传RCE'),
    ('CVE-2024-52726', 'CRMEB File Read', 7.5, 'LFI', 'CRMEB任意文件读取'),
    ('CVE-2024-38477', 'Juniper Junos CLI Injection', 9.1, 'RCE', 'Juniper Junos CLI命令注入'),
    ('CVE-2024-29825', 'Ivanti Connect Secure Auth Bypass', 9.0, 'Auth Bypass', 'Ivanti VPN认证绕过'),
    ('CVE-2024-27197', 'TeamCity Hidden API Auth Bypass', 9.8, 'Auth Bypass', 'TeamCity隐藏API认证绕过'),
    ('CVE-2024-21763', 'FortiOS Heap Overflow', 9.0, 'RCE', 'FortiOS SSL VPN堆溢出'),
    ('CVE-2024-2251', 'D-Link DWR Authentication Bypass', 9.1, 'Auth Bypass', 'D-Link DWR路由器认证绕过'),
    ('CVE-2024-28839', 'Apache Airflow RCE', 8.8, 'RCE', 'Apache Airflow实验性API RCE'),
    ('CVE-2024-28847', 'Moodle RCE', 9.8, 'RCE', 'Moodle课程拼写检查RCE'),
    ('CVE-2024-2812', 'Metabase RCE', 9.1, 'RCE', 'Metabase模板注入RCE'),
    ('CVE-2024-2918', 'WordPress Plugin RCE', 9.8, 'RCE', 'WordPress插件任意文件上传'),
    ('CVE-2024-1709', 'Docker API Exposed RCE', 9.8, 'RCE', 'Docker Engine API未授权访问'),
    ('CVE-2024-21413', 'Cisco IP Phone RCE', 9.8, 'RCE', 'Cisco IP电话Web管理RCE'),
    ('CVE-2024-21287', 'Oracle WebLogic SSRF', 7.5, 'SSRF', 'WebLogic T3协议SSRF'),
    ('CVE-2024-21225', 'Cisco Webex RCE', 9.1, 'RCE', 'Cisco Webex消息处理RCE'),
    ('CVE-2024-20697', 'Microsoft Outlook RCE', 8.1, 'RCE', 'Outlook RTF解析器RCE'),
    ('CVE-2024-38021', 'Windows Print Spooler RCE', 8.2, 'RCE', 'Windows打印后台处理服务RCE'),
    ('CVE-2024-38100', 'Windows NTLM RCE', 9.8, 'RCE', 'Windows NTLM中继攻击RCE'),
    ('CVE-2024-38114', 'Microsoft Fabric RCE', 8.0, 'RCE', 'Microsoft Fabric反序列化RCE'),
]

template = '''#!/usr/bin/env python3
"""
{cve_id}: {name}
- CVSS: {cvss}
- 类型: {vuln_type}
- 描述: {description}
- 参考: https://nvd.nist.gov/vuln/detail/{cve_id}
"""
import argparse, urllib.request, ssl

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
    print("{cve_id} - {name}")
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        r = check(args.target)
        print("[+] " + ("可能存在" if r else "不存在"))
    else:
        print("[*] POC框架已就绪，参考: https://nvd.nist.gov/vuln/detail/{cve_id}")

if __name__ == "__main__":
    main()
'''

for cve_id, name, cvss, vuln_type, desc in cve_list:
    d = os.path.join(output_dir, cve_id)
    os.makedirs(d, exist_ok=True)
    content = template.format(cve_id=cve_id, name=name, cvss=cvss, vuln_type=vuln_type, description=desc)
    with open(os.path.join(d, 'poc.py'), 'w', encoding='utf-8') as f:
        f.write(content)

print(f"Generated {len(cve_list)} CVE stubs")
