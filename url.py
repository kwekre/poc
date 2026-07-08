import os
import re

# 打印当前工作目录
print(f"当前工作目录: {os.getcwd()}")

# 读取原始资产文件
with open("\目标.txt", "r", encoding="utf-8") as f:
    raw = f.read()

lines = raw.splitlines()
url_list = []
reg = r"([0-9a-f:.]+)\s*\|\s*(\d+)\s*\|\s*(http|https)"
for line in lines:
    line = line.strip()
    match = re.search(reg, line)
    if match:
        proto, ip, port = match.group(3), match.group(1), match.group(2)
        full_url = f"{proto}://{ip}:{port}"
        url_list.append(full_url)

# 去重并写入url.txt
url_unique = list(set(url_list))
url_unique.sort()

# 使用绝对路径保存，确保知道文件在哪
save_path = os.path.join(os.getcwd(), "url.txt")
with open(save_path, "w", encoding="utf-8") as out:
    for u in url_unique:
        out.write(u + "\n")

print(f"转换完成，共{len(url_unique)}条地址")
print(f"文件保存位置: {os.path.abspath(save_path)}")