"""
T1.9 · 数据集统计报告脚本

读取 labels.csv，生成数据集统计报告。
报告包含：样本总数、类别分布、语言分布、文件大小统计、来源分布等。

使用方式：
    python scripts/dataset_stats.py
    python scripts/dataset_stats.py --output report.txt  # 指定输出文件
"""

import os
import sys
import csv
import logging
from collections import Counter, defaultdict
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

# 标签文件路径
LABELS_PATH = os.path.join(project_root, "data", "labels.csv")

# 报告输出路径
REPORT_PATH = os.path.join(project_root, "data", "dataset_stats_report.txt")


def load_labels(labels_path: str) -> list[dict]:
    """加载标签文件"""
    records = []
    with open(labels_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["label"] = int(row["label"])
            row["file_size"] = int(row["file_size"])
            records.append(row)
    return records


def format_size(size_bytes: int) -> str:
    """格式化文件大小"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def generate_report(records: list[dict]) -> str:
    """生成统计报告"""
    lines = []
    sep = "=" * 60
    sub_sep = "─" * 45

    lines.append(sep)
    lines.append("  数据集统计报告")
    lines.append(f"  生成时间: {os.path.getmtime(LABELS_PATH)}")
    lines.append(sep)

    # 1. 总体统计
    total = len(records)
    benign = sum(1 for r in records if r["label"] == 0)
    malicious = sum(1 for r in records if r["label"] == 1)
    total_size = sum(r["file_size"] for r in records)

    lines.append(f"\n  【1. 总体统计】")
    lines.append(f"  {sub_sep}")
    lines.append(f"  样本总数:          {total}")
    lines.append(f"  良性样本 (label=0): {benign}")
    lines.append(f"  恶意样本 (label=1): {malicious}")
    lines.append(f"  良性/恶意比:        {benign}:{malicious}")
    if total > 0:
        lines.append(f"  恶意样本占比:      {malicious / total * 100:.1f}%")
    lines.append(f"  数据集总大小:      {format_size(total_size)}")
    if total > 0:
        lines.append(f"  平均文件大小:      {format_size(total_size // total)}")

    # 2. 按类别统计
    category_counts = Counter(r["category"] for r in records)
    category_sizes = defaultdict(int)
    for r in records:
        category_sizes[r["category"]] += r["file_size"]

    lines.append(f"\n  【2. 按类别统计】")
    lines.append(f"  {sub_sep}")
    lines.append(f"  {'类别':<20s} {'数量':>6s} {'占比':>8s} {'总大小':>10s}")
    lines.append(f"  {'─'*48}")
    for cat in sorted(category_counts.keys()):
        count = category_counts[cat]
        pct = count / total * 100 if total > 0 else 0
        size = format_size(category_sizes[cat])
        lines.append(f"  {cat:<20s} {count:>6d} {pct:>7.1f}% {size:>10s}")

    # 3. 按子类别统计
    subcategory_counts = Counter(r["subcategory"] for r in records)
    lines.append(f"\n  【3. 按子类别统计】")
    lines.append(f"  {sub_sep}")
    lines.append(f"  {'子类别':<25s} {'数量':>6s} {'占比':>8s}")
    lines.append(f"  {'─'*42}")
    for subcat in sorted(subcategory_counts.keys()):
        count = subcategory_counts[subcat]
        pct = count / total * 100 if total > 0 else 0
        lines.append(f"  {subcat:<25s} {count:>6d} {pct:>7.1f}%")

    # 4. 按语言统计
    language_counts = Counter(r["language"] for r in records)
    lines.append(f"\n  【4. 按语言统计】")
    lines.append(f"  {sub_sep}")
    lines.append(f"  {'语言':<15s} {'数量':>6s} {'占比':>8s}")
    lines.append(f"  {'─'*32}")
    for lang in sorted(language_counts.keys()):
        count = language_counts[lang]
        pct = count / total * 100 if total > 0 else 0
        lines.append(f"  {lang:<15s} {count:>6d} {pct:>7.1f}%")

    # 5. 文件大小分布
    sizes = [r["file_size"] for r in records]
    if sizes:
        min_size = min(sizes)
        max_size = max(sizes)
        median_size = sorted(sizes)[len(sizes) // 2]

        # 大小区间统计
        ranges = [
            ("< 500 B", lambda s: s < 500),
            ("500 B - 1 KB", lambda s: 500 <= s < 1024),
            ("1 KB - 5 KB", lambda s: 1024 <= s < 5 * 1024),
            ("5 KB - 20 KB", lambda s: 5 * 1024 <= s < 20 * 1024),
            ("20 KB - 50 KB", lambda s: 20 * 1024 <= s < 50 * 1024),
            ("> 50 KB", lambda s: s >= 50 * 1024),
        ]

        lines.append(f"\n  【5. 文件大小分布】")
        lines.append(f"  {sub_sep}")
        lines.append(f"  最小: {format_size(min_size)}  |  最大: {format_size(max_size)}  |  中位数: {format_size(median_size)}")
        lines.append(f"  {'区间':<15s} {'数量':>6s} {'占比':>8s}")
        lines.append(f"  {'─'*32}")
        for label, func in ranges:
            count = sum(1 for s in sizes if func(s))
            pct = count / total * 100 if total > 0 else 0
            lines.append(f"  {label:<15s} {count:>6d} {pct:>7.1f}%")

    # 6. 实验设计建议
    lines.append(f"\n  【6. 实验设计建议】")
    lines.append(f"  {sub_sep}")
    if benign > 0 and malicious > 0:
        ratio = benign / malicious if malicious > 0 else 0
        lines.append(f"  良性/恶意比: {ratio:.2f}:1")
        if ratio > 3:
            lines.append(f"  [建议] 良性样本过多，考虑下采样或增加恶意样本")
        elif ratio < 0.5:
            lines.append(f"  [建议] 恶意样本过多，考虑增加良性样本")
        else:
            lines.append(f"  [良好] 良性/恶意比例合理")

    obfuscated_count = category_counts.get("obfuscated", 0)
    if obfuscated_count > 0:
        lines.append(f"  混淆变种: {obfuscated_count} 个（用于测试 LLM 对混淆代码的识别能力）")

    lines.append(f"\n  数据集结构:")
    lines.append(f"    data/samples/benign/        - 良性样本")
    lines.append(f"    data/samples/webshell/      - WebShell 恶意样本")
    lines.append(f"    data/samples/sqli/          - SQL 注入载荷")
    lines.append(f"    data/samples/obfuscated/    - 混淆变种（4种技术）")
    lines.append(f"    data/labels.csv             - 样本标签索引")

    lines.append(f"\n{sep}")
    lines.append(f"  报告结束")
    lines.append(f"{sep}")

    return "\n".join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="T1.9 · 数据集统计报告")
    parser.add_argument(
        "--output", type=str, default=REPORT_PATH,
        help=f"报告输出路径（默认: {REPORT_PATH}）"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  T1.9 · 数据集统计报告")
    print("=" * 60)

    # 检查标签文件
    if not os.path.exists(LABELS_PATH):
        print(f"  [错误] 标签文件不存在: {LABELS_PATH}")
        print(f"  请先运行 create_labels.py 生成标签文件")
        sys.exit(1)

    # 加载标签
    print(f"\n  加载标签文件: {LABELS_PATH}")
    records = load_labels(LABELS_PATH)
    print(f"  已加载 {len(records)} 条记录")

    # 生成报告
    report = generate_report(records)

    # 输出到控制台
    print(report)

    # 写入文件
    output_path = args.output
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n  报告已保存: {output_path}")


if __name__ == "__main__":
    main()
