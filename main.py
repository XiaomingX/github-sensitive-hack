#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
import re
import sys
import zlib
import struct
import binascii
import threading
import requests
from queue import Queue
from urllib.parse import urlparse

# 较新的浏览器UA，提高请求成功率
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
# 忽略SSL证书验证（针对自签证书场景）
requests.packages.urllib3.disable_warnings()

# 敏感信息模式匹配规则
SENSITIVE_PATTERNS = {
    'api_key': re.compile(r'(?i)(api_key|api_secret|api-token|access_key|secret_key)\s*=\s*.+'),
    'password': re.compile(r'(?i)(password|pass|pwd|secret)\s*=\s*.+'),
    'database': re.compile(r'(?i)(db_user|db_pass|db_password|database_url|db_host|db_name)\s*=\s*.+'),
    'token': re.compile(r'(?i)(token|auth_token|jwt|oauth|bearer)\s*=\s*.+'),
    'private_key': re.compile(r'(?i)(private_key|rsa_private|ssh_private)\s*=\s*.+'),
    'credit_card': re.compile(r'(?i)(credit_card|cc_number|card_number)\s*=\s*.+'),
}


def parse_git_index(filename):
    """解析.git/index文件，提取文件SHA1哈希和路径"""
    try:
        with open(filename, "rb") as f:
            data = f.read()
        mmapped_file = memoryview(data)
        offset = 0

        # 读取指定格式的二进制数据并更新偏移量
        def read(fmt):
            nonlocal offset
            size = struct.calcsize(fmt)
            result = struct.unpack(fmt, mmapped_file[offset:offset+size])[0]
            offset += size
            return result

        # 验证index文件签名（必须为DIRC）
        signature = mmapped_file[offset:offset+4].tobytes().decode("ascii")
        offset += 4
        if signature != "DIRC":
            raise ValueError("非法Git index文件")

        # 仅支持2、3版本的index文件
        version = read("!I")
        if version not in {2, 3}:
            raise ValueError(f"不支持的index版本: {version}")

        # 解析所有文件条目
        entries_count = read("!I")
        for _ in range(entries_count):
            # 读取文件元数据（仅提取需要的SHA1和文件名）
            entry = {
                "sha1": binascii.hexlify(mmapped_file[offset:offset+20].tobytes()).decode("ascii"),
                "flags": read("!H")
            }
            offset += 20  # SHA1字段占20字节

            # 读取文件名（长度从flags中提取）
            name_length = entry["flags"] & 0xFFF
            entry["name"] = mmapped_file[offset:offset+name_length].tobytes().decode("utf-8", "replace")
            offset += name_length

            # 跳过对齐字节（Git index条目按8字节对齐）
            offset = (offset + 7) & ~7
            yield entry

    except FileNotFoundError:
        print(f"[ERROR] index文件不存在: {filename}")
    except ValueError as ve:
        print(f"[ERROR] 解析index失败: {ve}")


class GitScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        # 生成目标目录（用域名替换冒号避免路径错误）
        self.domain = urlparse(base_url).netloc.replace(':', '_')
        self.dest_dir = os.path.abspath(self.domain)
        os.makedirs(self.dest_dir, exist_ok=True)
        
        self.queue = Queue()
        self.lock = threading.Lock()
        self.thread_count = 10  # 默认10线程，平衡速度与稳定性

    def download_index(self):
        """下载.git/index文件到本地"""
        index_url = f"{self.base_url}/index"
        index_path = os.path.join(self.dest_dir, "index")
        
        try:
            response = requests.get(
                index_url,
                headers={'User-Agent': USER_AGENT},
                verify=False,
                timeout=10
            )
            response.raise_for_status()  # 触发HTTP错误（4xx/5xx）
            
            with open(index_path, "wb") as f:
                f.write(response.content)
            return index_path

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] 下载index失败: {str(e)}")
            return None

    def check_env_file(self):
        """检查并下载根目录下的.env文件，检测敏感信息"""
        print("[+] 开始检测.env文件敏感信息泄露...")
        
        # 构建可能的.env文件URL（根目录下）
        base_domain = self.base_url.replace('/.git', '')
        env_urls = [
            f"{base_domain}/.env",
            f"{base_domain}/env",
            f"{base_domain}/.env.local",
            f"{base_domain}/.env.example",
            f"{base_domain}/.env.development",
            f"{base_domain}/.env.production"
        ]
        
        env_path = os.path.join(self.dest_dir, ".env_checked")
        os.makedirs(env_path, exist_ok=True)
        
        for url in env_urls:
            try:
                response = requests.get(
                    url,
                    headers={'User-Agent': USER_AGENT},
                    verify=False,
                    timeout=10
                )
                response.raise_for_status()
                
                # 保存下载的.env文件
                filename = os.path.basename(url)
                save_path = os.path.join(env_path, filename)
                with open(save_path, "wb") as f:
                    f.write(response.content)
                
                print(f"[WARNING] 发现暴露的{filename}文件: {url}")
                print(f"[INFO] {filename}文件已保存至: {save_path}")
                
                # 检测敏感信息
                self.detect_sensitive_info(save_path)
                
            except requests.exceptions.RequestException:
                continue  # 不输出未找到的信息，避免干扰
        
        print("[+] .env文件检测完成")

    def detect_sensitive_info(self, file_path):
        """检测文件中的敏感信息"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            found_sensitive = False
            for category, pattern in SENSITIVE_PATTERNS.items():
                matches = pattern.findall(content)
                if matches:
                    if not found_sensitive:
                        print("[!] 检测到敏感信息:")
                        found_sensitive = True
                    print(f"  - {category}: {len(matches)}处匹配")
                    # 打印前3个匹配项（部分隐藏敏感内容）
                    for i, match in enumerate(matches[:3]):
                        # 处理元组类型的匹配结果
                        if isinstance(match, tuple):
                            match_str = "=".join(match)
                        else:
                            match_str = match
                        # 隐藏部分敏感内容
                        if "=" in match_str:
                            key, value = match_str.split("=", 1)
                            # 只显示值的前3个字符和后3个字符
                            if len(value) > 6:
                                masked_value = value[:3] + "..." + value[-3:]
                                print(f"    示例: {key}={masked_value}")
                            else:
                                print(f"    示例: {key}=***")
                        else:
                            print(f"    示例: {match_str[:10]}...")
        
        except Exception as e:
            print(f"[ERROR] 检测敏感信息时出错: {str(e)}")

    def enqueue_files(self, index_path):
        """从index文件提取文件信息，加入下载队列"""
        for entry in parse_git_index(index_path):
            if not entry:
                continue
            sha1, file_name = entry["sha1"], entry["name"]
            # 过滤危险路径（防止路径遍历）
            if ".." not in file_name:
                self.queue.put((sha1, file_name))
                
                # 特别检查是否有.env相关文件在Git历史中
                if '.env' in file_name:
                    with self.lock:
                        print(f"[WARNING] Git历史中发现敏感文件: {file_name}")

    def _fetch_data(self, url):
        """内部请求方法，获取Git对象文件"""
        response = requests.get(
            url,
            headers={'User-Agent': USER_AGENT},
            verify=False,
            timeout=10
        )
        response.raise_for_status()
        return response.content

    def fetch_file(self):
        """线程任务：从队列获取文件信息，下载并还原"""
        while True:
            try:
                sha1, file_name = self.queue.get(timeout=0.5)
                # 构建Git对象URL（格式：.git/objects/前两位SHA1/剩余SHA1）
                obj_url = f"{self.base_url}/objects/{sha1[:2]}/{sha1[2:]}"
                
                # 下载并处理Git对象（解压+去除blob头）
                obj_data = self._fetch_data(obj_url)
                obj_data = zlib.decompress(obj_data)
                # 只匹配一次blob头（格式：blob 大小\x00），避免误删文件内容
                obj_data = re.sub(rb"blob \d+\x00", b"", obj_data, count=1)

                # 写入文件（自动创建父目录）
                target_path = os.path.join(self.dest_dir, file_name)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "wb") as f:
                    f.write(obj_data)

                # 线程安全打印成功信息
                with self.lock:
                    print(f"[OK] {file_name}")

            except Queue.Empty:
                break  # 队列空，线程退出
            except Exception as e:
                # 只打印关键错误信息，避免输出冗余
                with self.lock:
                    print(f"[ERROR] 处理失败: {str(e)}")
            finally:
                self.queue.task_done()

    def run_threads(self):
        """启动多线程处理队列任务"""
        threads = [
            threading.Thread(target=self.fetch_file, daemon=True)
            for _ in range(self.thread_count)
        ]
        for thread in threads:
            thread.start()
        # 等待所有任务完成
        self.queue.join()


def main():
    # 检查参数
    if len(sys.argv) < 2:
        print("用法: python3 main.py <URL>")
        print("示例: python3 main.py http://www.example.com 或 python3 main.py http://www.example.com/.git")
        sys.exit(1)

    # 自动补充.git路径（若用户未输入）
    base_url = sys.argv[1].rstrip('/')
    if '/.git' not in base_url:
        base_url += '/.git'

    # 初始化扫描器并执行恢复流程
    scanner = GitScanner(base_url)
    print(f"[+] 目标URL: {base_url}")
    print(f"[+] 输出目录: {scanner.dest_dir}")
    
    # 先检查.env文件泄露
    scanner.check_env_file()
    
    # 然后执行Git文件恢复流程
    print("[+] 正在下载并解析.git/index文件...")

    index_path = scanner.download_index()
    if index_path and os.path.exists(index_path):
        scanner.enqueue_files(index_path)
        file_count = scanner.queue.qsize()
        if file_count == 0:
            print("[ERROR] 未从index文件中提取到有效文件")
            return

        print(f"[+] 发现 {file_count} 个文件待恢复，启动多线程下载...")
        scanner.run_threads()
        print("[+] 所有可恢复文件处理完成！")
    else:
        print("[ERROR] 无法获取index文件，恢复流程终止")


if __name__ == '__main__':
    main()
