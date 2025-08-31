# github-sensitive-hack
> 仓库地址：[https://github.com/XiaomingX/github-sensitive-hack](https://github.com/XiaomingX/github-sensitive-hack)  
> 轻量高效的 **.git 泄露恢复工具**，自动下载泄露的 Git 仓库文件并重建源代码，支持多线程加速，适配各类场景。

## 如果你对网络安全感兴趣，如下开源代码不容错过：
 - rust实现的端口扫描器：
   - https://github.com/XiaomingX/RustProxyHunter
 - python实现的代理池检测：
   - https://github.com/XiaomingX/proxy-pool
 - golang实现的供应链安全，CVE-POC的全自动收集（注无人工审核，可能被投毒，仅限有基础的朋友）：
   - https://github.com/XiaomingX/data-cve-poc
 - python实现的检查.git泄漏的工具
   - https://github.com/XiaomingX/github-sensitive-hack
  
## 目录
- [项目简介](#项目简介)
- [快速开始](#快速开始)
- [使用说明](#使用说明)
- [常见问题](#常见问题)
- [安全与法律提示](#安全与法律提示)
- [许可证](#许可证)


## 项目简介
### 核心能力
- ✅ **URL自动补全**：用户输入无需手动加 `.git`，工具自动补全路径
- ✅ **多线程下载**：默认10线程并发，快速获取 Git 对象文件
- ✅ **智能重建**：自动解析 `.git/index`、解压对象、还原目录结构
- ✅ **安全防护**：过滤危险路径，避免路径遍历风险
- ✅ **兼容性强**：支持 Windows/Linux/macOS，适配自签 SSL 证书场景

### 适用场景
- 合法授权的渗透测试与代码审计
- 开发人员恢复意外丢失的项目源代码
- 安全研究（分析 .git 泄露风险）


## 快速开始
### 1. 环境准备
- **Python 版本**：3.6 及以上
- **依赖库**：仅需 `requests`（用于 HTTP 请求）

### 2. 安装依赖
```bash
pip install requests
```

### 3. 运行命令
#### 基础用法（支持两种 URL 格式）
```bash
# 格式1：直接输入域名（工具自动补全 /.git）
python3 main.py http://www.example.com

# 格式2：手动输入完整 .git 路径
python3 main.py http://www.example.com/.git
```

#### 示例输出
```
[+] 目标URL: http://www.example.com/.git
[+] 输出目录: /home/user/www_example_com
[+] 正在下载并解析.git/index文件...
[OK] src/main.py
[OK] config/database.ini
[OK] static/js/app.js
[+] 所有可恢复文件处理完成！
```


## 使用说明
### 1. 输出目录说明
工具会自动创建以 **目标域名为名** 的文件夹（冒号替换为下划线，避免路径错误），恢复的源代码直接存放在该目录下。  
例如：目标 `https://test.com:8080` → 输出目录 `test.com_8080`。

### 2. 恢复后操作
进入输出目录即可查看完整源代码：
```bash
# 进入恢复目录
cd www_example_com

# 查看文件结构
ls -l
```


## 常见问题
| 问题现象 | 可能原因 | 解决方案 |
|----------|----------|----------|
| 提示“下载index失败” | 1. 目标无 .git 泄露<br>2. 服务器拦截请求<br>3. 网络不通 | 1. 验证目标是否可访问 `.git/index`<br>2. 检查网络连接或代理设置 |
| 部分文件恢复失败 | 对应 Git 对象文件已被服务器删除 | 工具会自动跳过缺失文件，不影响其他文件恢复 |
| 文件名乱码 | 原始仓库使用非 UTF-8 编码 | 用文本工具（如 VS Code）手动指定编码打开 |
| SSL 证书错误 | 目标使用自签 SSL 证书 | 工具已默认禁用 SSL 验证，无需额外配置 |


## 安全与法律提示
### 1. 必须合法授权
**未获得书面授权，禁止用于任何非授权测试！**  
未经授权使用可能触犯《网络安全法》《刑法》第285/286条，需自行承担法律责任。

### 2. 操作规范
- 建议在 **虚拟机/容器** 中运行，避免本地环境感染恶意代码
- 恢复后若发现敏感信息（如密码、密钥），需立即删除，不得泄露
- 发现 .git 泄露后，应及时告知目标管理员协助修复




## 许可证
本项目采用 **MIT 许可证** 开源，允许自由使用、修改和分发，前提是保留原始许可证声明。

完整许可证内容见 [LICENSE](LICENSE) 文件。