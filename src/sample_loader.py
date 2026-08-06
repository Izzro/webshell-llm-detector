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
    label: str                   # benign | malicious
    malware_type: str            # webshell | backdoor | sqli | none
    subtype: str                 # 具体子类型
    obfuscation: str             # none | base64 | string_split | xor | comment_bypass
    source: str                  # 样本来源
    code_text: str = ""          # 样本代码文本（加载后填充）
    language: str = ""           # 代码语言（php | python | sql）


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

        Returns:
            样本列表（不含代码文本）
        """
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def load_samples(
        self,
        category: Optional[str] = None,
        obfuscation: Optional[str] = None,
    ) -> list[Sample]:
        """
        加载样本并读取文件内容。

        Args:
            category: 按类别筛选（benign/webshell/obfuscated/sqli），None 为全部
            obfuscation: 按混淆方式筛选，None 为全部

        Returns:
            样本列表（含代码文本）
        """
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _detect_language(self, file_path: str) -> str:
        """根据文件扩展名推断代码语言。"""
        if file_path.endswith(".php"):
            return "php"
        elif file_path.endswith(".py"):
            return "python"
        elif file_path.endswith(".sql") or file_path.endswith(".txt"):
            return "sql"
        return "unknown"
