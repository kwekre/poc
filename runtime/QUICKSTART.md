# POC Runner 快速上手指南

## 四种扫描模式

### ✅ 模式1: 单 POC × 单 URL
```bash
python3 runtime/poc_runner.py -p CVE-2024-23897 -t http://target.com
```

### ✅ 模式2: 单 POC × 多 URL (批量目标)
```bash
# 先建文件
echo http://target1.com > urls.txt
echo http://target2.com >> urls.txt
echo http://target3.com >> urls.txt

python3 runtime/poc_runner.py -p CVE-2024-23897 -u urls.txt
```

### ✅ 模式3: 多 POC × 单 URL (全面检测)
```bash
# 先建文件（每行一个 POC 名称）
echo CVE-2024-23897 > pocs.txt
echo CVE-2024-27198 >> pocs.txt
echo CVE-2023-22515 >> pocs.txt

python3 runtime/poc_runner.py -f pocs.txt -t http://target.com
```

### ✅ 模式4: 多 POC × 多 URL ★ (最常用)
```bash
# urls.txt 和 pocs.txt 准备好后
python3 runtime/poc_runner.py -f pocs.txt -u urls.txt -o results.json
```

---

## 自动识别模式（最省心）
```bash
# 自动识别目标类型并匹配合适 POC
python3 runtime/poc_runner.py --auto http://target.com

# 自动扫描 + 输出结果
python3 runtime/poc_runner.py --auto http://target.com -o result.json
```

---

## 过滤与查找

```bash
# 列出所有 POC
python3 runtime/poc_runner.py -l

# 只列 CVE POC
python3 runtime/poc_runner.py --list-cve

# 只列 OA/CMS POC
python3 runtime/poc_runner.py --list-oacms

# 按关键字过滤
python3 runtime/poc_runner.py -l -k jenkins
python3 runtime/poc_runner.py -l -k 泛微

# 按类型过滤
python3 runtime/poc_runner.py -l --type cve
python3 runtime/poc_runner.py -l --type oacms
```

---

## 高级用法

```bash
# 关键字过滤 + 指定 POC
python3 runtime/poc_runner.py -f pocs.txt -t http://target.com -k rce

# 调整请求延迟（防 WAF）
python3 runtime/poc_runner.py -f pocs.txt -u urls.txt -d 2.0

# 增加单个 POC 超时
python3 runtime/poc_runner.py -p CVE-2024-23897 -t http://target.com --timeout 60
```

---

## 生成示例文件

### urls.txt 示例
```
http://10.0.0.1:8080
http://10.0.0.2:80
https://oa.company.com
```

### pocs.txt 示例
```
CVE-2024-23897
CVE-2024-27198
CVE-2023-22515
CVE-2024-21762
CVE-2025-24813
weaver_e8_sqli
seeyon_file_upload
tongda_rce
```

---

## GitHub 使用

```bash
cd E:\claw\workspace\vuln-pocs
git init
git add .
git commit -m "feat: add POC runner + 120+ CVEs + OA/CMS + 2026 CVEs"
git remote add origin https://github.com/kwekre/poc.git
git branch -M main
git push -u origin main
```

---

## 提示

- POC 会自动扫描并注册到 `runtime/poc_registry.json`
- 新增 POC 后自动出现在列表中，无需手动注册
- 扫描结果自动保存为 JSON，含时间戳和漏洞汇总
- 遇到 WAF/防火墙可加 `-d 3` 增大请求间隔
