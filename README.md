# 🛡️ vuln-pocs

> 漏洞 POC 库 | Web 安全研究 | CVE 复现 | OA/CMS 漏洞

本仓库收录近两年 **120+** 高危漏洞 POC，覆盖 **Web 应用安全**、**系统服务漏洞**、**国内 OA/CMS 漏洞** 等方向，每个漏洞包含：

- 🎯 漏洞描述与影响版本
- 🔍 检测脚本（Python PoC）
- 📋 修复建议与参考链接

---

## 📂 项目结构

```
vuln-pocs/
├── cves/                      # 100+ CVE 编号漏洞 POC
│   ├── CVE-2024-23897/       # Jenkins CLI 任意文件读取 [详细]
│   ├── CVE-2024-27198/       # TeamCity 认证绕过 [详细]
│   ├── CVE-2023-22515/       # Confluence OGNL RCE [详细]
│   ├── CVE-2024-21762/       # FortiOS SSL VPN RCE [详细]
│   ├── CVE-2024-9264/        # Grafana SQL Expression RCE [详细]
│   ├── CVE-2024-56145/       # Craft CMS FTP Upload RCE [详细]
│   ├── CVE-2024-24919/       # Check Point LFI [详细]
│   ├── CVE-2024-29640/       # aliyundrive-webdav RCE [详细]
│   ├── CVE-2025-24813/       # Apache Tomcat PUT RCE [详细]
│   ├── CVE-2025-27817/       # Apache Kafka Connect File RW [详细]
│   ├── CVE-2025-2825/        # CrushFTP 认证绕过 [详细]
│   ├── CVE-2025-49002/       # DataEase H2 JDBC RCE [详细]
│   ├── CVE-2025-49003/       # DataEase API RCE [详细]
│   ├── CVE-2025-20354/       # Cisco CCX RMI RCE [详细]
│   └── + 80+ 个 CVE 存根（CVE-2024-xxx / CVE-2025-xxx）
├── oacms/                     # 国内 OA/CMS 漏洞 POC（2024-2025）
│   ├── weaver/               # 泛微 E-Cology / E-Office
│   │   ├── CVE-2024-26136.py       # WorkflowServiceXml SQL注入 [详细]
│   │   ├── getLabelByModule_sqli.py # getLabelByModule SQLi [详细]
│   │   └── weaver_e8_sqli.py        # E-Office SQL注入 [详细]
│   │   └── + 5 个存根 (CNVD)
│   ├── seeyon/               # 致远 OA A6/A8
│   │   ├── seeyon_file_upload.py   # htmlofficeservlet/fileUpload.do [详细]
│   │   └── + 5 个存根 (CVE/CNVD)
│   ├── tongda/               # 通达 OA
│   │   └── tongda_rce.py            # SQL注入/文件读取/RCE [详细]
│   │   └── + 3 个存根 (CNVD/CVE)
│   ├── dedecms/              # 织梦 DedeCMS
│   │   ├── CVE-2023-2928.py         # 文件包含 RCE [详细]
│   │   └── + 3 个存根
│   ├── empirecms/            # 帝国 EmpireCMS
│   │   └── empirecms_rce.py          # SQLi/模板注入/XSS [详细]
│   └── qcms/                 # 骑士CMS 74CMS
│       └── 74cms_sqli.py            # SQL注入 [详细]
├── web/                      # Web 漏洞类型扫描
│   ├── command_injection/    # 命令注入检测
│   ├── sql_injection/        # SQL 注入检测
│   ├── ssrf/                # SSRF 检测
│   ├── xss/                 # XSS 检测
│   ├── file_read/           # LFI 任意文件读取
│   ├── auth_bypass/         # 认证绕过检测
│   ├── upload_rce/          # 文件上传 RCE
│   ├── xxe/                 # XXE 检测
│   ├── idor/                # IDOR 越权检测
│   └── csrf/                # CSRF POC 生成器
├── tools/
│   └── mass_scanner.py      # 批量 CVE 扫描器
└── utils/
    └── http.py               # HTTP 工具库
```

---

## 🤖 POC Runner 统一调度框架

支持 **四种扫描模式**，一键批量跑 POC：

```bash
# ===== 1. 列出所有 POC =====
python3 runtime/poc_runner.py -l
python3 runtime/poc_runner.py --list-cve          # 仅 CVE
python3 runtime/poc_runner.py --list-oacms        # 仅 OA/CMS
python3 runtime/poc_runner.py -l -k jenkins        # 关键字过滤

# ===== 2. 单 POC × 单 URL =====
python3 runtime/poc_runner.py -p CVE-2024-23897 -t http://target.com

# ===== 3. 单 POC × 多 URL =====
python3 runtime/poc_runner.py -p CVE-2024-23897 -u urls.txt

# ===== 4. 多 POC × 单 URL =====
python3 runtime/poc_runner.py -f pocs.txt -t http://target.com

# ===== 5. 多 POC × 多 URL ★ (最常用) =====
python3 runtime/poc_runner.py -f pocs.txt -u urls.txt -o results.json

# ===== 6. 自动识别目标 + 智能匹配 POC =====
python3 runtime/poc_runner.py --auto http://target.com
```

详细说明见 [runtime/QUICKSTART.md](runtime/QUICKSTART.md)

---

## ⚡ 传统单 POC 方式

```bash
# ===== CVE 检测 =====
python3 cves/CVE-2024-23897/poc.py -t http://target:8080 --check
python3 cves/CVE-2023-22515/poc.py -t http://target.com --check

# ===== OA/CMS 漏洞检测 =====
python3 oacms/weaver/CVE-2024-26136.py -t http://target.com --check
python3 oacms/seeyon/seeyon_file_upload.py -t http://target.com --check --webshell
python3 oacms/tongda/tongda_rce.py -t http://target.com --check
python3 oacms/dedecms/CVE-2023-2928.py -t http://target.com --check --module include
python3 oacms/qcms/74cms_sqli.py -t http://target.com --check

# ===== 批量扫描 =====
python3 tools/mass_scanner.py -f targets.txt -o results.json
```

---

## 📊 收录统计

| 类别         | 数量   | 代表漏洞                                  |
| ------------ | ------ | ----------------------------------------- |
| CVE 详细 POC | 16 个  | Confluence OGNL RCE, Palo Alto PAN-OS RCE |
| CVE 存根     | ~85 个 | 2024~2025 高危漏洞                        |
| OA 漏洞      | 15+ 个 | 泛微/致远/通达 详细+存根                  |
| CMS 漏洞     | 10+ 个 | 织梦/帝国CMS/骑士CMS                      |
| Web 类型扫描 | 10 个  | SQLi/命令注入/SSRF/XSS/LFI                |

**CVSS 分布**: Critical (9.0~10.0) × 60+, High (7.0~8.9) × 40+

---

## 🔒 免责声明

本仓库仅供**授权安全研究与学习**使用，禁止用于任何未经授权的渗透测试。对任何滥用本仓库代码造成的法律后果，作者概不负责。

---

> 📌 持续更新，欢迎 Star & Fork
