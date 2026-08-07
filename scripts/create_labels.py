"""
T1.8 · 标签文件生成脚本

扫描 data/samples/ 目录，为所有样本生成标签文件 labels.csv。
标签文件是后续实验的样本索引，记录每个样本的路径、类别、子类别、标签等。

标签定义：
  - label=0：良性样本（benign）
  - label=1：恶意样本（webshell, sqli, obfuscated/*）

使用方式：
    python scripts/create_labels.py
"""

import os
import sys
import csv
import logging
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

# 样本根目录
SAMPLES_DIR = os.path.join(project_root, "data", "samples")

# 标签文件输出路径
LABELS_PATH = os.path.join(project_root, "data", "labels.csv")

# CSV 列头
CSV_HEADERS = [
    "file_path",        # 相对于项目根目录的文件路径
    "filename",         # 文件名
    "category",         # 主类别：benign / webshell / sqli / obfuscated
    "subcategory",      # 子类别：wordpress / thinkphp / ... / base64 / xor / ...
    "label",            # 标签：0=良性，1=恶意
    "language",         # 语言：PHP / Python / Text / Other
    "file_size",        # 文件大小（字节）
]


def detect_language(filename: str) -> str:
    """根据文件扩展名检测语言"""
    ext = os.path.splitext(filename)[1].lower()
    if ext == ".php":
        return "PHP"
    elif ext == ".py":
        return "Python"
    elif ext == ".txt":
        return "Text"
    elif ext in (".jsp",):
        return "JSP"
    elif ext in (".asp", ".aspx"):
        return "ASP"
    return "Other"


def scan_directory(dir_path: str, category: str, subcategory: str, label: int) -> list[dict]:
    """
    扫描目录中的所有样本文件，生成标签记录。

    Args:
        dir_path: 目录路径
        category: 主类别
        subcategory: 子类别
        label: 标签（0=良性，1=恶意）

    Returns:
        标签记录列表
    """
    records = []
    if not os.path.exists(dir_path):
        return records

    for fname in sorted(os.listdir(dir_path)):
        fpath = os.path.join(dir_path, fname)
        if not os.path.isfile(fpath):
            continue
        if fname.startswith("."):
            continue

        rel_path = os.path.relpath(fpath, project_root)
        file_size = os.path.getsize(fpath)

        records.append({
            "file_path": rel_path,
            "filename": fname,
            "category": category,
            "subcategory": subcategory,
            "label": label,
            "language": detect_language(fname),
            "file_size": file_size,
        })

    return records


def main():
    print("=" * 60)
    print("  T1.8 · 标签文件生成")
    print("=" * 60)

    all_records = []

    # 1. 良性样本 (label=0)
    benign_dir = os.path.join(SAMPLES_DIR, "benign")
    print(f"\n  扫描良性样本: {benign_dir}")
    # 良性样本的子类别通过文件名前缀识别
    benign_files = scan_directory(benign_dir, "benign", "benign", 0)
    # 根据文件名前缀细分来源
    for record in benign_files:
        fname = record["filename"]
        if fname.startswith("wordpress_"):
            record["subcategory"] = "wordpress"
        elif fname.startswith("thinkphp_"):
            record["subcategory"] = "thinkphp"
        elif fname.startswith("laravel_"):
            record["subcategory"] = "laravel"
        elif fname.startswith("flask_examples_"):
            record["subcategory"] = "flask"
        else:
            record["subcategory"] = "other_benign"
    all_records.extend(benign_files)
    print(f"    良性样本: {len(benign_files)} 个")

    # 2. WebShell 样本 (label=1)
    webshell_dir = os.path.join(SAMPLES_DIR, "webshell")
    print(f"  扫描 WebShell 样本: {webshell_dir}")
    webshell_files = scan_directory(webshell_dir, "webshell", "webshell", 1)
    # 根据文件名前缀细分来源
    for record in webshell_files:
        fname = record["filename"]
        if fname.startswith("tennc_"):
            record["subcategory"] = "tennc_webshell"
        elif fname.startswith("johnTroony_"):
            record["subcategory"] = "johnTroony_webshell"
        else:
            record["subcategory"] = "other_webshell"
    all_records.extend(webshell_files)
    print(f"    WebShell 样本: {len(webshell_files)} 个")

    # 3. SQLi 样本 (label=1)
    sqli_dir = os.path.join(SAMPLES_DIR, "sqli")
    print(f"  扫描 SQLi 样本: {sqli_dir}")
    sqli_files = scan_directory(sqli_dir, "sqli", "sqli", 1)
    # 根据文件名前缀细分来源
    for record in sqli_files:
        fname = record["filename"]
        if fname.startswith("builtin_sqli"):
            record["subcategory"] = "builtin_sqli"
        elif fname.startswith("payloadbox_"):
            record["subcategory"] = "payloadbox_sqli"
        else:
            record["subcategory"] = "other_sqli"
    all_records.extend(sqli_files)
    print(f"    SQLi 样本: {len(sqli_files)} 个")

    # 4. 混淆变种样本 (label=1)
    obfuscated_dir = os.path.join(SAMPLES_DIR, "obfuscated")
    obfuscation_techniques = ["base64", "comment_bypass", "string_split", "xor"]
    print(f"  扫描混淆变种样本: {obfuscated_dir}")
    for tech in obfuscation_techniques:
        tech_dir = os.path.join(obfuscated_dir, tech)
        tech_files = scan_directory(tech_dir, "obfuscated", tech, 1)
        all_records.extend(tech_files)
        print(f"    {tech:15s}: {len(tech_files)} 个")

    # 写入 CSV
    print(f"\n  写入标签文件: {LABELS_PATH}")
    with open(LABELS_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        writer.writerows(all_records)

    # 汇总
    print(f"\n{'='*60}")
    print("  标签文件生成完成")
    print(f"{'='*60}")

    # 按类别统计
    category_stats = {}
    for record in all_records:
        cat = record["category"]
        category_stats[cat] = category_stats.get(cat, 0) + 1

    # 按标签统计
    benign_count = sum(1 for r in all_records if r["label"] == 0)
    malicious_count = sum(1 for r in all_records if r["label"] == 1)

    print(f"\n  按类别统计:")
    for cat, count in sorted(category_stats.items()):
        print(f"    {cat:20s}: {count:4d} 个")

    print(f"\n  按标签统计:")
    print(f"    {'良性 (label=0)':20s}: {benign_count:4d} 个")
    print(f"    {'恶意 (label=1)':20s}: {malicious_count:4d} 个")
    print(f"    {'总计':20s}: {len(all_records):4d} 个")
    print(f"\n  标签文件: {LABELS_PATH}")


if __name__ == "__main__":
    main()
