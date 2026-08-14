# OA / CMS 漏洞 POC 合集

> 本目录收录国内主流 OA 和 CMS 系统的漏洞 POC，覆盖泛微、致远、通达、织梦、帝国CMS、骑士CMS。

---

## 📂 目录结构

```
oacms/
├── README.md              # 本文件
├── weaver/               # 泛微 OA (E-Cology / E-Office)
├── seeyon/               # 致远 OA (A6/A8)
├── tongda/               # 通达 OA
├── dedecms/              # 织梦 DedeCMS
├── empirecms/            # 帝国 EmpireCMS
└── qcms/                # 骑士CMS (74CMS)
```

---

## 🔴 泛微 OA (Weaver E-Cology / E-Office)

### E-Cology
| 漏洞 | CVE/QVD | CVSS | 类型 | POC |
|------|---------|------|------|-----|
| WorkflowServiceXml SQL注入 | QVD-2024-26136 | 9.8 | SQLi | `CVE-2024-26136.py` |
| getLabelByModule SQL注入 | CNVD | 高危 | SQLi | `getLabelByModule_sqli.py` |
| FileDownloadLocation 认证绕过+SQLi | CNVD | 高危 | 认证绕过+SQLi | - |
| browser.jsp SQL注入 | CNVD-2023-12632 | 高危 | SQLi | - |
| Hessian 反序列化 RCE | - | 高危 | RCE | - |

### E-Office
| 漏洞 | CVSS | 类型 | POC |
|------|------|------|-----|
| SQL注入（多个接口） | 高危 | SQLi | `weaver_e8_sqli.py` |
| 任意文件读取 | 高危 | LFI | - |
| 后台文件上传 | 高危 | RCE | - |

**识别特征**: FOFA: `app="泛微-E-Weaver"` 或 `app="泛微-OA(E-Office)"`

```bash
# 检测泛微 E-Cology SQL注入
python3 weaver/CVE-2024-26136.py -t http://target.com --check

# 泛微 E-Office SQL注入
python3 weaver/weaver_e8_sqli.py -t http://target.com --check
```

---

## 🟠 致远 OA (Seeyon A6/A8)

| 漏洞 | CVSS | 类型 | POC |
|------|------|------|-----|
| htmlofficeservlet 文件上传 | Critical | 未授权上传 | `seeyon_file_upload.py` |
| fileUpload.do 绕过上传 | Critical | 未授权上传 | `seeyon_file_upload.py` |
| wpsAssistServlet 路径遍历上传 | 高危 | 路径穿越 | - |
| thirdpartyController.do 认证绕过 | Critical | 认证绕过 | `seeyon_file_upload.py` |
| ajax.do 未授权访问 | 高危 | 未授权 | - |
| Session泄露 | 中危 | 信息泄露 | - |

**识别特征**: FOFA: `title="致远互联"` 或 `app="致远科技-OA"`

```bash
# 致远 OA 文件上传利用
python3 seeyon/seeyon_file_upload.py -t http://target.com --check
python3 seeyon/seeyon_file_upload.py -t http://target.com --webshell
```

---

## 🟡 通达 OA (Tongda OA)

| 漏洞 | CVSS | 类型 | POC |
|------|------|------|-----|
| SQL注入 | 高危 | SQLi | `tongda_rce.py` |
| 任意文件读取 | 高危 | LFI | `tongda_rce.py` |
| 任意文件上传 | 高危 | RCE | `tongda_rce.py` |
| PHP代码执行 | Critical | RCE | `tongda_rce.py` |

**识别特征**: FOFA: `app="通达OA"` 或 `title="通达信德"`

```bash
python3 tongda/tongda_rce.py -t http://target.com --check
```

---

## 🟢 DedeCMS 织梦

| 漏洞 | CVE | CVSS | 类型 | POC |
|------|-----|------|------|-----|
| 文件包含 RCE | CVE-2023-2928 | 高危 | 文件包含 | `CVE-2023-2928.py` |
| 模板注入 ShowMsg | - | 高危 | 模板注入 | `CVE-2023-2928.py` |
| 后台模板上传 RCE | CVE-2019-8933 | 高危 | 后台上传 | - |
| 搜索型 SQL注入 | - | 高危 | SQLi | `CVE-2023-2928.py` |
| 任意文件上传 | - | 中危 | 上传 | - |

**识别特征**: FOFA: `app="DedeCMS-织梦CMS"`

```bash
python3 dedecms/CVE-2023-2928.py -t http://target.com --check
python3 dedecms/CVE-2023-2928.py -t http://target.com --module include
```

---

## 🔵 EmpireCMS 帝国CMS

| 漏洞 | CVSS | 类型 | POC |
|------|------|------|-----|
| 搜索 SQL注入 | 高危 | SQLi | `empirecms_rce.py` |
| DynamicTag 模板注入 | 高危 | 模板注入 | `empirecms_rce.py` |
| 后台备份路径可控 getshell | 高危 | 后台RCE | - |
| WAP 模块 XSS | 中危 | XSS | `empirecms_rce.py` |

**识别特征**: FOFA: `app="EmpireCMS"`

```bash
python3 empirecms/empirecms_rce.py -t http://target.com --check
```

---

## 🟣 骑士CMS (74CMS)

| 漏洞 | CNVD | CVSS | 类型 | POC |
|------|------|------|------|-----|
| 简历查看 SQL注入 | CNVD-2021-43389 | 高危 | SQLi | `74cms_sqli.py` |
| 模板注入→日志包含 RCE | - | 高危 | 模板注入 | `74cms_sqli.py` |
| 任意文件读取 | - | 中危 | LFI | - |

**识别特征**: FOFA: `app="74CMS-骑士CMS"` 或 `title="骑士人才系统"`

```bash
python3 qcms/74cms_sqli.py -t http://target.com --check
```

---

*最后更新: 2026-08-14 | 仅供授权安全研究*
