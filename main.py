#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
import re
import ssl
import sys
import threading
import zlib
from queue import Queue
from urllib.request import Request, urlopen
from urllib.parse import urlparse
from collections import OrderedDict
import mmap
import struct
import binascii

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36'
SSL_CONTEXT = ssl._create_unverified_context()

def parse_git_index(filename):
    """Parses the .git/index file."""
    try:
        with open(filename, "rb") as f:
            mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

            def read(fmt):
                size = struct.calcsize(fmt)
                return struct.unpack(fmt, mmapped_file.read(size))[0]

            signature = mmapped_file.read(4).decode("ascii")
            if signature != "DIRC":
                raise ValueError("Not a Git index file")

            version = read("!I")
            if version not in {2, 3}:
                raise ValueError(f"Unsupported index version: {version}")

            entries_count = read("!I")
            for _ in range(entries_count):
                entry = OrderedDict()
                entry["ctime_seconds"], entry["ctime_nanoseconds"] = read("!I"), read("!I")
                entry["mtime_seconds"], entry["mtime_nanoseconds"] = read("!I"), read("!I")
                entry["dev"], entry["ino"], entry["mode"], entry["uid"], entry["gid"], entry["size"] = read("!IIIIII")
                entry["sha1"] = binascii.hexlify(mmapped_file.read(20)).decode("ascii")
                entry["flags"] = read("!H")
                name_length = entry["flags"] & 0xFFF
                entry["name"] = mmapped_file.read(name_length).decode("utf-8", "replace")
                yield entry
    except FileNotFoundError:
        print(f"[ERROR] The file {filename} does not exist.")
    except ValueError as ve:
        print(f"[ERROR] {ve}")

class GitScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc.replace(':', '_')
        self.dest_dir = os.path.abspath(self.domain)
        os.makedirs(self.dest_dir, exist_ok=True)
        self.queue = Queue()
        self.lock = threading.Lock()
        self.thread_count = 10
        self.stop_flag = False

    def download_index(self):
        index_url = f"{self.base_url}/index"
        try:
            data = self._fetch_data(index_url)
            index_path = os.path.join(self.dest_dir, "index")
            with open(index_path, "wb") as f:
                f.write(data)
            return index_path
        except Exception as e:
            print(f"[ERROR] Failed to download index: {e}")
            return None

    def enqueue_files(self, index_path):
        if not os.path.exists(index_path):
            print(f"[ERROR] The directory {index_path} does not exist.")
            return

        for entry in parse_git_index(index_path):
            if entry:
                sha1, file_name = entry["sha1"], entry["name"]
                if self._is_valid_file_name(file_name):
                    self.queue.put((sha1, file_name))

    def _is_valid_file_name(self, file_name):
        abs_path = os.path.abspath(os.path.join(self.dest_dir, file_name))
        return ".." not in file_name and abs_path.startswith(self.dest_dir)

    def _fetch_data(self, url):
        request = Request(url, headers={'User-Agent': USER_AGENT})
        return urlopen(request, context=SSL_CONTEXT).read()

    def fetch_file(self):
        while not self.stop_flag:
            try:
                sha1, file_name = self.queue.get(timeout=0.5)
                folder = f"/objects/{sha1[:2]}/"
                file_data = self._fetch_data(f"{self.base_url}{folder}{sha1[2:]}")
                file_data = zlib.decompress(file_data)
                file_data = re.sub(rb"blob \d+\x00", b"", file_data)
                target_path = os.path.join(self.dest_dir, file_name)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "wb") as f:
                    f.write(file_data)
                with self.lock:
                    print(f"[OK] {file_name}")
            except Exception as e:
                with self.lock:
                    print(f"[ERROR] {e}")

    def run_threads(self):
        threads = [threading.Thread(target=self.fetch_file) for _ in range(self.thread_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <URL>")
        sys.exit(1)

    base_url = sys.argv[1]
    scanner = GitScanner(base_url)

    print("[+] Downloading and parsing index file...")
    index_path = scanner.download_index()
    if index_path and os.path.exists(index_path):
        scanner.enqueue_files(index_path)
        print("[+] Starting file recovery...")
        scanner.run_threads()
    else:
        print(f"[ERROR] The directory {index_path} does not exist.")

if __name__ == '__main__':
    main()
