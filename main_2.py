import requests
import re
from requests.exceptions import RequestException

def scan_actions_json_sensitive_info(target_domain):
    """
    扫描目标域名下的actions.json是否包含敏感信息
    
    参数:
        target_domain: 目标域名（如 'xxxx.com'，不含http/https）
    
    返回:
        dict: 扫描结果，包含是否存在文件、敏感信息列表等
    """
    # 构建可能的actions.json路径（常见路径枚举）
    paths = [
        f"https://{target_domain}/actions.json",
        f"http://{target_domain}/actions.json",
        f"https://{target_domain}/.github/actions.json",  # GitHub相关路径
        f"https://{target_domain}/api/actions.json",      # 可能的API配置路径
        f"https://{target_domain}/config/actions.json"    # 配置目录路径
    ]
    
    # 敏感信息模式（正则表达式）
    sensitive_patterns = {
        "api_key": re.compile(r"(api_key|api_secret|api_token|access_key)\s*[:=]\s*['\"][a-zA-Z0-9]+['\"]"),
        "password": re.compile(r"(password|pass|pwd)\s*[:=]\s*['\"][^'\"]+['\"]"),
        "token": re.compile(r"(token|auth_token|bearer)\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]"),
        "ssh_key": re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
        "database": re.compile(r"(db_host|db_user|db_pass|database_url)\s*[:=]\s*['\"][^'\"]+['\"]")
    }
    
    results = []
    
    for url in paths:
        try:
            # 发送请求（设置超时防止卡死）
            response = requests.get(url, timeout=10, allow_redirects=True)
            if response.status_code != 200:
                continue  # 只处理存在的文件（200状态码）
            
            content = response.text
            sensitive_info = []
            
            # 检查是否包含敏感信息
            for info_type, pattern in sensitive_patterns.items():
                matches = pattern.findall(content)
                if matches:
                    # 脱敏处理（隐藏部分字符）
                    redacted_matches = [
                        re.sub(r'(.{4})(.*)(.{4})', r'\1****\3', str(m)) 
                        for m in matches
                    ]
                    sensitive_info.append({
                        "type": info_type,
                        "matches": redacted_matches
                    })
            
            results.append({
                "url": url,
                "exists": True,
                "sensitive_info": sensitive_info,
                "has_sensitive": len(sensitive_info) > 0
            })
            
        except RequestException as e:
            results.append({
                "url": url,
                "exists": False,
                "error": str(e)
            })
    
    return {
        "target": target_domain,
        "scan_time": str(pd.Timestamp.now()),  # 需要import pandas as pd，或替换为datetime
        "results": results
    }

# 使用示例（请确保目标网站允许扫描，遵守法律法规）
if __name__ == "__main__":
    import pandas as pd  # 用于时间戳，可替换为datetime
    target = "xxx.com"  # 替换为目标域名
    scan_result = scan_actions_json_sensitive_info(target)
    
    # 打印结果
    for res in scan_result["results"]:
        if res["exists"]:
            print(f"发现文件: {res['url']}")
            if res["has_sensitive"]:
                print("  包含敏感信息:")
                for info in res["sensitive_info"]:
                    print(f"    - {info['type']}: {info['matches']}")
            else:
                print("  未发现敏感信息")
        else:
            print(f"文件不存在: {res['url']} (错误: {res['error']})")
