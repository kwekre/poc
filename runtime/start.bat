@echo off
chcp 65001 >nul
:: POC 批量扫描快捷脚本

echo ===== POC Runner 使用指南 =====
echo.
echo 模式1: 列出所有 POC
echo   run.bat -l
echo.
echo 模式2: 列出 CVE POC
echo   run.bat --list-cve
echo.
echo 模式3: 列出 OA/CMS POC
echo   run.bat --list-oacms
echo.
echo 模式4: 自动识别目标并扫描
echo   run.bat --auto http://target.com
echo.
echo 模式5: 单 POC x 单 URL
echo   run.bat -p CVE-2024-23897 -t http://target.com
echo.
echo 模式6: 单 POC x 多 URL (文件)
echo   run.bat -p CVE-2024-23897 -u urls.txt
echo.
echo 模式7: 多 POC x 单 URL
echo   run.bat -f pocs.txt -t http://target.com
echo.
echo 模式8: 多 POC x 多 URL ★
echo   run.bat -f pocs.txt -u urls.txt
echo.
echo ===== 开始扫描 =====
echo.
python3 runtime\poc_runner.py %*
