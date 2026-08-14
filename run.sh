#!/bin/bash
# POC Runner 启动脚本 (Linux/macOS/WSL)
cd "$(dirname "$0")"
python3 runtime/poc_runner.py "$@"
