# CVE 漏洞索引 | vuln-pocs

> 本仓库收录 **100+** 近年高危 CVE POC，覆盖 Web 安全、系统服务、云原生、工控等领域。

---

## 📊 按 CVSS 评分

### 🔴 Critical (9.0~10.0)

| CVE ID | 漏洞名称 | CVSS | 类型 | 影响 |
|--------|---------|------|------|------|
| CVE-2023-22515 | Atlassian Confluence OGNL RCE | **10.0** | RCE | 企业内网渗透入口 |
| CVE-2024-3400 | Palo Alto PAN-OS Command Injection | **10.0** | RCE | VPN 网关沦陷 |
| CVE-2024-27198 | TeamCity 认证绕过 | **9.8** | Auth Bypass | 未授权建管理员 |
| CVE-2024-56145 | Craft CMS FTP Upload RCE | **9.8** | RCE | 文件上传写入webshell |
| CVE-2025-24813 | Apache Tomcat PUT RCE | **9.8** | RCE | PUT 上传 JSP |
| CVE-2025-49002 | DataEase H2 JDBC RCE | **9.8** | RCE | 反序列化 |
| CVE-2025-2825 | CrushFTP Auth Bypass | **9.8** | Auth Bypass | 管理员Session |
| CVE-2025-20354 | Cisco CCX RMI RCE | **9.8** | RCE | RMI 未授权上传 |
| CVE-2025-8266 | ChanCms RCE | **9.8** | RCE | 命令注入 |
| CVE-2025-34035 | EnGenius 命令注入 | **9.8** | RCE | 路由器未授权 |
| CVE-2024-23897 | Jenkins CLI 文件读取 | **9.1** | LFI | → RCE |
| CVE-2024-9264 | Grafana SQL Expression RCE | **8.5** | RCE | shellfs 插件 |
| CVE-2024-21762 | FortiOS SSL VPN RCE | **9.6** | RCE | HTTP 编码绕过 |
| CVE-2024-24919 | Check Point LFI | **7.5** | LFI | 敏感文件读取 |
| CVE-2024-29640 | aliyundrive-webdav RCE | **9.8** | RCE | sid 参数注入 |

### 🟠 High (7.0~8.9)

| CVE ID | 漏洞名称 | CVSS | 类型 |
|--------|---------|------|------|
| CVE-2025-27817 | Apache Kafka Connect 任意文件访问 | 8.8 | File Access |
| CVE-2025-22952 | Elestio Memos SSRF | 8.6 | SSRF |
| CVE-2024-36477 | Chamilo LMS RCE | 9.8 | RCE |
| CVE-2024-29824 | Ivanti EPM SQLi RCE | 9.8 | RCE |
| CVE-2024-22252 | VMware vCenter RCE | 9.8 | RCE |
| CVE-2024-47575 | FortiManager Fabric Device RCE | 9.8 | RCE |
| CVE-2024-37080 | MS Exchange Server RCE | 9.8 | RCE |
| CVE-2024-38077 | Windows RRAS RCE | 9.8 | RCE |
| CVE-2024-43639 | Apache OFBiz RCE | 9.8 | RCE |
| CVE-2024-45230 | PyTorch 反序列化 RCE | 9.8 | RCE |
| CVE-2024-41931 | Apache Commons Text RCE | 9.8 | RCE |
| CVE-2024-56477 | Zimbra RCE | 9.8 | RCE |
| CVE-2025-2024 | Kibana Canvas RCE | 9.0 | RCE |
| CVE-2025-22422 | Ivanti Connect Secure RCE | 9.0 | RCE |
| CVE-2024-41929 | Spring Security RCE | 9.1 | RCE |
| CVE-2024-38819 | Apache Tomcat WebSocket RCE | 8.1 | RCE |
| CVE-2024-44340 | Chrome V8 JIT RCE | 8.8 | RCE |
| CVE-2025-30406 | CentreStack 反序列化 | 9.1 | RCE |

---

## 📂 按漏洞类型

### 远程代码执行 (RCE)
- `CVE-2023-22515` - Confluence OGNL
- `CVE-2024-23897` - Jenkins CLI → RCE
- `CVE-2024-27198` - TeamCity → RCE
- `CVE-2024-21762` - FortiOS VPN
- `CVE-2024-9264` - Grafana
- `CVE-2024-56145` - Craft CMS
- `CVE-2024-29640` - aliyundrive-webdav
- `CVE-2025-24813` - Apache Tomcat
- `CVE-2025-49002` - DataEase H2
- `CVE-2025-20354` - Cisco CCX
- `CVE-2025-8266` - ChanCms
- `CVE-2025-55449` - AstrBot

### SQL 注入
- `CVE-2024-29824` - Ivanti EPM
- `CVE-2025-49003` - DataEase API
- `web/sql_injection/` - 通杀型 SQLi 扫描

### 任意文件读取 / LFI
- `CVE-2024-23897` - Jenkins
- `CVE-2024-24919` - Check Point
- `CVE-2025-48957` - AstrBot
- `web/file_read/` - 通杀型 LFI 扫描

### 认证绕过
- `CVE-2024-27198` - TeamCity
- `CVE-2025-2825` - CrushFTP
- `web/auth_bypass/` - 管理后台扫描

### SSRF
- `CVE-2025-22952` - Elestio Memos
- `web/ssrf/` - SSRF 检测

### XXE
- `CVE-2025-49493` - Akamai CloudTest
- `web/xxe/` - XXE 检测

### 命令注入
- `CVE-2024-3400` - Palo Alto PAN-OS
- `CVE-2025-34035` - EnGenius
- `web/command_injection/` - 命令注入扫描

---

## 🛠️ 使用方法

### 单个 CVE 检测
```bash
python3 cves/CVE-2024-23897/poc.py -t http://target.com:8080 --check
python3 cves/CVE-2023-22515/poc.py -t http://target.com --check
```

### 批量扫描
```bash
python3 tools/mass_scanner.py -f targets.txt -o results.json
```

### Web 漏洞类型扫描
```bash
# 命令注入
python3 web/command_injection/scan.py -t "http://target.com/ping?cmd=" -p cmd

# SQL 注入
python3 web/sql_injection/scan.py -t "http://target.com/user?id=" -p id

# LFI
python3 web/file_read/scan.py -t "http://target.com/download?file=" -p file

# SSRF
python3 web/ssrf/scan.py -t "http://target.com/fetch?url=" -p url
```

---

*最后更新: 2026-08-14 | 共收录 100+ CVE POC*
