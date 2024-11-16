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

## 原理说明

### 基础恢复步骤

#### 准备工作
1. 创建一个新的空文件夹。
2. 将泄露的`.git`文件夹复制到这个新文件夹中。

#### 方法一：直接恢复所有文件
1. 打开终端，进入包含`.git`文件夹的目录。
2. 执行以下命令：
   ```bash
   git status  # 查看状态，确认哪些文件被删除了
   git reset --hard  # 强制恢复所有文件
   ```
   这样可以直接恢复项目的所有文件。

#### 方法二：从特定提交恢复
1. 使用 `git log` 查看提交历史，找到需要恢复的版本。
   ```bash
   git log
   ```
2. 使用 `git checkout` 命令检出特定提交的版本。
   ```bash
   git checkout <commit_hash>
   ```
   `<commit_hash>` 是想要恢复的版本的哈希值。

### 进阶恢复技巧

#### 处理裸仓库

如果泄露的`.git`目录是一个裸仓库（没有工作目录的仓库），可以用以下命令恢复：
```bash
git clone <.git目录路径> <新目录>
cd <新目录>
git checkout master
```
这会创建一个完整的项目工作副本。

#### 恢复被删除的文件
1. 使用以下命令查找被删除文件的提交：
   ```bash
   git log --diff-filter=D --summary | grep delete
   ```
2. 找到包含该文件的最后一次提交记录。
3. 使用 `git checkout` 恢复该文件：
   ```bash
   git checkout <commit_hash> -- <文件路径>
   ```
   这样就能找回指定被删除的文件。

### 安全提示
在恢复泄露的`.git`文件夹时，请注意以下几点：
- 尽量在隔离的环境中进行操作，避免泄露敏感信息。
- 恢复后检查项目是否包含任何敏感数据。
- 不要轻易执行不明来源的脚本或命令，以免造成安全风险。

这样，你可以通过简单的步骤来恢复丢失的项目源代码。
