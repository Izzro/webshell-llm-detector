"""
T1.4 · 良性样本收集脚本

从开源项目源码中抽取正常的 PHP/Python 脚本作为良性样本。
样本来源：
  - WordPress 核心 PHP 文件（wp-includes, wp-admin 中的核心文件）
  - ThinkPHP 框架源码（控制器、路由、中间件）
  - Laravel 框架源码（框架核心类）
  - Python Web 脚本（Flask/Django 业务代码）

所有样本仅做静态文本存储，不执行。

使用方式：
    python scripts/collect_benign.py
    python scripts/collect_benign.py --max-per-source 30  # 限制每个来源的最大样本数
"""

import os
import sys
import shutil
import random
import logging
import tempfile
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

# 良性样本输出目录
OUTPUT_DIR = os.path.join(project_root, "data", "samples", "benign")

# 临时下载目录
TEMP_DIR = os.path.join(project_root, "data", "_temp_benign")

# 样本来源配置：owner/repo, branch, 子目录过滤, 文件扩展名, 来源标签
SOURCES = [
    {
        "name": "wordpress",
        "owner": "WordPress",
        "repo": "wordpress-develop",
        "branch": "trunk",
        "subdirs": ["src/wp-includes", "src/wp-admin"],
        "exclude_dirs": ["tests", "js", "css", "images", "fonts"],
        "extensions": [".php"],
        "max_files": 120,
        "min_size": 200,
        "max_size": 50000,
    },
    {
        "name": "thinkphp",
        "owner": "top-think",
        "repo": "framework",
        "branch": "master",
        "subdirs": [""],  # 搜索整个仓库（目录结构可能随版本变化）
        "exclude_dirs": ["tests", "test", ".github", "config", "route", "docs"],
        "extensions": [".php"],
        "max_files": 60,
        "min_size": 200,
        "max_size": 50000,
    },
    {
        "name": "laravel",
        "owner": "laravel",
        "repo": "framework",
        "branch": "master",
        "subdirs": ["src/Illuminate"],
        "exclude_dirs": ["tests", "stubs"],
        "extensions": [".php"],
        "max_files": 60,
        "min_size": 200,
        "max_size": 50000,
    },
    {
        "name": "flask_examples",
        "owner": "pallets",
        "repo": "flask",
        "branch": "main",
        "subdirs": ["examples", "src/flask"],
        "exclude_dirs": ["tests", "test"],
        "extensions": [".py"],
        "max_files": 40,
        "min_size": 100,
        "max_size": 30000,
    },
]


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
        # 下载 tarball
        response = requests.get(tarball_url, stream=True, timeout=120)
        response.raise_for_status()

        # 计算下载大小
        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0
        tarball_path = os.path.join(dest_dir, "_download.tar.gz")

        with open(tarball_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)

        total_mb = downloaded / (1024 * 1024)
        logger.info(f"下载完成: {total_mb:.1f} MB")

        # 解压 tarball（逐文件解压，跳过隐藏文件和被锁定的文件）
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

        # 删除 tarball 文件
        try:
            os.remove(tarball_path)
        except PermissionError:
            logger.warning(f"删除 tarball 失败（文件被锁定），忽略")

        # tarball 解压后会有一个顶层目录（如 WordPress-wordpress-develop-abc123）
        # 需要把内容移到 dest_dir 下
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
        # 如果指定分支失败，尝试 main 分支
        if branch == "master":
            logger.warning(f"master 分支失败，尝试 main 分支...")
            source["branch"] = "main"
            # 清理并重试
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

    Args:
        repo_dir: 仓库目录
        subdirs: 要搜索的子目录列表
        exclude_dirs: 要排除的目录名
        extensions: 要收集的文件扩展名
        max_files: 最大文件数
        min_size: 最小文件大小（字节）
        max_size: 最大文件大小（字节）

    Returns:
        符合条件的文件路径列表
    """
    collected = []
    exclude_set = set(exclude_dirs)

    for subdir in subdirs:
        search_path = os.path.join(repo_dir, subdir)
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

                # 过滤文件大小
                if fsize < min_size or fsize > max_size:
                    continue

                collected.append(fpath)

                if len(collected) >= max_files:
                    return collected

    return collected


def copy_samples(file_list: list[str], source_name: str, output_dir: str) -> int:
    """
    将收集的文件复制到输出目录，文件名加上来源前缀避免冲突。

    Args:
        file_list: 源文件路径列表
        source_name: 来源名称（用作文件名前缀）
        output_dir: 输出目录

    Returns:
        成功复制的文件数
    """
    count = 0
    for fpath in file_list:
        # 生成唯一文件名：来源_原始文件名
        orig_name = os.path.basename(fpath)
        # 去掉扩展名后加来源前缀，再加回扩展名
        name_parts = os.path.splitext(orig_name)
        new_name = f"{source_name}_{name_parts[0]}{name_parts[1]}"

        # 避免重名
        dest_path = os.path.join(output_dir, new_name)
        counter = 1
        while os.path.exists(dest_path):
            new_name = f"{source_name}_{name_parts[0]}_{counter}{name_parts[1]}"
            dest_path = os.path.join(output_dir, new_name)
            counter += 1

        try:
            shutil.copy2(fpath, dest_path)
            count += 1
        except Exception as e:
            logger.warning(f"复制失败 {fpath}: {e}")

    return count


def main():
    import argparse

    parser = argparse.ArgumentParser(description="T1.4 · 良性样本收集")
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
    print("  T1.4 · 良性样本收集")
    print("=" * 60)

    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    total_collected = 0
    stats = {}

    for source in SOURCES:
        source_name = source["name"]
        print(f"\n{'─'*60}")
        print(f"  来源: {source_name} ({source['repo']})")
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

        # 随机采样（如果收集的文件超过限制）
        if len(files) > max_files:
            random.seed(42)  # 固定随机种子保证可复现
            files = random.sample(files, max_files)

        print(f"  收集到 {len(files)} 个文件")

        # 复制到输出目录
        copied = copy_samples(files, source_name, OUTPUT_DIR)
        print(f"  成功复制 {copied} 个样本到 {OUTPUT_DIR}")

        stats[source_name] = copied
        total_collected += copied

    # 清理临时目录
    if not args.keep_temp:
        print(f"\n  清理临时目录: {TEMP_DIR}")
        shutil.rmtree(TEMP_DIR, ignore_errors=True)

    # 汇总
    print(f"\n{'='*60}")
    print("  良性样本收集完成")
    print(f"{'='*60}")
    for name, count in stats.items():
        print(f"  {name:20s}: {count:4d} 个")
    print(f"  {'─'*30}")
    print(f"  {'总计':20s}: {total_collected:4d} 个")
    print(f"\n  输出目录: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
