@echo off
:: POC Runner 启动脚本 (Windows)
chcp 65001 >nul
cd /d "%~dp0"
python3 runtime\poc_runner.py %*
