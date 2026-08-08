"""
样本加载器模块

批量读取样本文件，解析元数据（标签、类型、混淆方式），返回样本列表。

功能：
- 从 data/labels.csv 加载标签索引
- 批量读取样本文件内容
- 支持按类别、混淆方式筛选样本
- 返回标准化的样本数据结构

使用方式（阶段二实现）：
    from src.sample_loader import SampleLoader
    loader = SampleLoader("data/labels.csv")
    samples = loader.load_samples(category="webshell")
"""

import os
import csv
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Sample:
    """样本数据结构。"""
    file_path: str               # 样本文件相对路径
    category: str                # 主类别：benign / webshell / sqli / obfuscated
    label: str                   # benign | malicious
    malware_type: str            # webshell | backdoor | sqli | none
    subtype: str                 # 具体子类型（来源/混淆技术）
    obfuscation: str             # none | base64 | string_split | xor | comment_bypass
    source: str                  # 样本来源
    code_text: str = ""          # 样本代码文本（加载后填充）
    language: str = ""           # 代码语言（php | python | sql）
    file_size: int = 0           # 文件大小（字节）


class SampleLoader:
    """样本加载器，从 labels.csv 加载样本索引并读取文件内容。"""

    def __init__(self, labels_file: str = "data/labels.csv", base_dir: str = "."):
        """
        Args:
            labels_file: labels.csv 文件路径
            base_dir: 项目根目录，用于解析相对路径
        """
        self.labels_file = labels_file
        self.base_dir = base_dir
        self.samples: list[Sample] = []

    def load_labels(self) -> list[Sample]:
        """
        从 labels.csv 加载样本标签索引。

        CSV 列：file_path, filename, category, subcategory, label, language, file_size
        映射规则：
          - label 0/1 → benign/malicious
          - category → malware_type（obfuscated 归为 webshell）
          - category=obfuscated 时 obfuscation=subcategory，否则 none
          - language 大写 → 小写（Text → sql，因 .txt 均为 SQLi 载荷）

        Returns:
            样本列表（不含代码文本，code_text 为空字符串）

        Raises:
            FileNotFoundError: labels.csv 不存在
        """
        # 已加载过则直接返回缓存
        if self.samples:
            return self.samples

        csv_path = self.labels_file
        if not os.path.isabs(csv_path):
            csv_path = os.path.join(self.base_dir, csv_path)

        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"标签文件不存在: {csv_path}")

        self.samples = []

        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                category = row.get("category", "")
                label_int = int(row["label"])
                subcategory = row.get("subcategory", "")

                # 映射 label: 0 → benign, 1 → malicious
                label_str = "benign" if label_int == 0 else "malicious"

                # 映射 malware_type
                if category == "benign":
                    malware_type = "none"
                elif category == "webshell":
                    malware_type = "webshell"
                elif category == "sqli":
                    malware_type = "sqli"
                elif category == "obfuscated":
                    malware_type = "webshell"  # 混淆变种源自 webshell
                else:
                    malware_type = "unknown"

                # 映射 obfuscation
                if category == "obfuscated":
                    obfuscation = subcategory
                else:
                    obfuscation = "none"

                # 映射 language
                language = self._map_language(row.get("language", ""))

                # 解析 file_size
                try:
                    file_size = int(row.get("file_size", 0))
                except (ValueError, TypeError):
                    file_size = 0

                sample = Sample(
                    file_path=row["file_path"],
                    category=category,
                    label=label_str,
                    malware_type=malware_type,
                    subtype=subcategory,
                    obfuscation=obfuscation,
                    source=subcategory,
                    language=language,
                    file_size=file_size,
                )
                self.samples.append(sample)

        logger.info(f"已加载 {len(self.samples)} 条样本标签")
        return self.samples

    def load_samples(
        self,
        category: Optional[str] = None,
        obfuscation: Optional[str] = None,
    ) -> list[Sample]:
        """
        加载样本并读取文件内容。

        先确保标签索引已加载，再按 category / obfuscation 筛选，
        最后读取每条样本的文件内容填充 code_text。

        Args:
            category: 按类别筛选（benign/webshell/obfuscated/sqli），None 为全部
            obfuscation: 按混淆方式筛选，None 为全部

        Returns:
            样本列表（含代码文本）
        """
        # 如果还没有加载标签，先加载
        if not self.samples:
            self.load_labels()

        # 按条件筛选
        filtered = []
        for sample in self.samples:
            if category is not None and sample.category != category:
                continue
            if obfuscation is not None and sample.obfuscation != obfuscation:
                continue
            filtered.append(sample)

        # 读取文件内容
        loaded = 0
        failed = 0
        for sample in filtered:
            # file_path 是相对于项目根目录的路径
            file_path = sample.file_path
            if not os.path.isabs(file_path):
                file_path = os.path.join(self.base_dir, file_path)

            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    sample.code_text = f.read()
                loaded += 1
            except Exception as e:
                logger.warning(f"读取样本失败: {sample.file_path}: {e}")
                sample.code_text = ""
                failed += 1

        logger.info(
            f"已加载 {loaded} 条样本内容"
            f"（category={category}, obfuscation={obfuscation}"
            f"{f', 失败 {failed} 条' if failed else ''}）"
        )
        return filtered

    def _detect_language(self, file_path: str) -> str:
        """根据文件扩展名推断代码语言。"""
        if file_path.endswith(".php"):
            return "php"
        elif file_path.endswith(".py"):
            return "python"
        elif file_path.endswith(".sql") or file_path.endswith(".txt"):
            return "sql"
        return "unknown"

    @staticmethod
    def _map_language(lang: str) -> str:
        """
        将 CSV 中的语言标注映射为统一的小写格式。

        映射规则：
          - PHP → php
          - Python → python
          - Text → sql（.txt 文件均为 SQLi 载荷）
          - JSP → jsp, ASP/ASPX → asp
          - 其他 → unknown
        """
        mapping = {
            "php": "php",
            "python": "python",
            "text": "sql",
            "jsp": "jsp",
            "asp": "asp",
            "aspx": "asp",
        }
        return mapping.get(lang.strip().lower(), "unknown")
