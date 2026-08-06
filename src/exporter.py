"""
数据导出模块

导出实验结果数据，支持 CSV 和 JSON 两种格式。
按实验名称和时间戳组织输出目录，确保实验可复现。

使用方式（阶段二实现）：
    from src.exporter import Exporter
    exporter = Exporter()
    exporter.export_results(results, experiment_name="E1_zero_shot_deepseek")
"""

import os
import csv
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class Exporter:
    """实验数据导出器。"""

    def __init__(self, output_dir: str = "results"):
        """
        Args:
            output_dir: 结果输出根目录
        """
        self.output_dir = output_dir

    def export_results(
        self,
        results: list[dict],
        experiment_name: str,
        metrics: dict | None = None,
    ) -> str:
        """
        导出实验结果，自动生成带时间戳的目录。

        Args:
            results: 每条样本的检测结果列表
            experiment_name: 实验名称（如 E1_zero_shot_deepseek）
            metrics: 汇总指标字典（可选）

        Returns:
            输出目录路径
        """
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _export_raw_json(self, results: list[dict], run_dir: str) -> str:
        """导出逐条原始结果（JSON 格式，含 API 响应原文）。"""
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _export_summary_csv(self, results: list[dict], run_dir: str) -> str:
        """导出汇总 CSV（每行一个样本的判定）。"""
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _export_metrics_json(self, metrics: dict, run_dir: str) -> str:
        """导出指标汇总 JSON。"""
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")
