# github-sensitive-hack
## 原理简介

GitHack is a .git folder disclosure exploit.

It rebuild source code from .git folder while keep directory structure unchanged.

GitHack是一个.git泄露利用脚本，通过泄露的.git文件夹下的文件，重建还原工程源代码。

渗透测试人员、攻击者，可以进一步审计代码，挖掘：文件上传，SQL注射等web安全漏洞。

## 运行说明
```bash
python3 main.py http://www.example.com/.git/
```