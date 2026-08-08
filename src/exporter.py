"""
数据导出模块

导出实验结果数据，支持 CSV 和 JSON 两种格式。
按实验名称和时间戳组织输出目录，确保实验可复现。

功能：
- raw_results.json：逐条原始结果（含 API 响应原文、预测详情、真实标签）
- summary.csv：汇总表（每行一个样本，便于 Excel 分析）
- metrics.json：汇总指标（accuracy/precision/recall/f1/混淆识别率等）

输出目录结构：
    results/{experiment_name}_{YYYYMMDD_HHMMSS}/
        ├── raw_results.json
        ├── summary.csv
        └── metrics.json

使用方式：
    from src.exporter import Exporter
    exporter = Exporter()
    run_dir = exporter.export_results(results, "E1_zero_shot_deepseek", metrics)
"""

import os
import csv
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class Exporter:
    """实验数据导出器。"""

    # CSV 汇总表的列定义（顺序即输出顺序）
    CSV_COLUMNS = [
        "file_path",
        "filename",
        "category",
        "true_label",
        "true_malware_type",
        "true_obfuscation",
        "pred_label",
        "pred_malware_type",
        "pred_subtype",
        "pred_obfuscation",
        "pred_confidence",
        "pred_risk_level",
        "indicators",
        "reason",
        "parse_error",
        "latency_ms",
        "total_tokens",
        "prompt_tokens",
        "completion_tokens",
        "correct",             # 1=预测正确, 0=预测错误, ""=无法判断
    ]

    def __init__(self, output_dir: str = "results"):
        """
        Args:
            output_dir: 结果输出根目录（相对于项目根目录或绝对路径）
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

        生成三类文件：
        1. raw_results.json — 逐条原始结果（含 API 响应原文）
        2. summary.csv     — 汇总表（每行一个样本）
        3. metrics.json    — 汇总指标（metrics 为 None 时跳过）

        Args:
            results: 每条样本的检测结果列表
            experiment_name: 实验名称（如 E1_zero_shot_deepseek）
            metrics: 汇总指标字典（可选）

        Returns:
            输出目录路径
        """
        # 生成带时间戳的输出目录
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_name = f"{experiment_name}_{timestamp}"
        run_dir = os.path.join(self.output_dir, run_name)
        os.makedirs(run_dir, exist_ok=True)

        logger.info(f"开始导出实验结果: {experiment_name} ({len(results)} 条样本)")

        # 1. 导出原始 JSON
        raw_path = self._export_raw_json(results, run_dir)

        # 2. 导出汇总 CSV
        csv_path = self._export_summary_csv(results, run_dir)

        # 3. 导出指标 JSON（如果提供）
        metrics_path = None
        if metrics is not None:
            metrics_path = self._export_metrics_json(metrics, run_dir)

        logger.info(
            f"导出完成 → {run_dir}\n"
            f"  raw_results.json ({len(results)} 条)\n"
            f"  summary.csv\n"
            + (f"  metrics.json" if metrics_path else "")
        )

        return run_dir

    def _export_raw_json(self, results: list[dict], run_dir: str) -> str:
        """
        导出逐条原始结果（JSON 格式，含 API 响应原文）。

        JSON 结构：
        {
            "export_time": "2026-08-07T20:00:00",
            "total_samples": 515,
            "results": [ {每条样本的完整信息}, ... ]
        }

        Args:
            results: 检测结果列表
            run_dir: 输出目录

        Returns:
            JSON 文件路径
        """
        raw_path = os.path.join(run_dir, "raw_results.json")

        export_data = {
            "export_time": datetime.now().isoformat(),
            "total_samples": len(results),
            "results": results,
        }

        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        logger.debug(f"raw_results.json 已写入: {raw_path}")
        return raw_path

    def _export_summary_csv(self, results: list[dict], run_dir: str) -> str:
        """
        导出汇总 CSV（每行一个样本的判定）。

        列包含：文件路径、真实标签、预测标签、置信度、延迟、Token 等。
        使用 utf-8-sig 编码以确保 Excel 正确显示中文。
        indicators 列表转为分号分隔的字符串。

        Args:
            results: 检测结果列表
            run_dir: 输出目录

        Returns:
            CSV 文件路径
        """
        csv_path = os.path.join(run_dir, "summary.csv")

        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=self.CSV_COLUMNS,
                extrasaction="ignore",
            )
            writer.writeheader()

            for r in results:
                row = {}
                for col in self.CSV_COLUMNS:
                    val = r.get(col, "")

                    # indicators 列表 → 分号分隔字符串
                    if col == "indicators" and isinstance(val, list):
                        val = "; ".join(str(i) for i in val)

                    row[col] = val

                writer.writerow(row)

        logger.debug(f"summary.csv 已写入: {csv_path} ({len(results)} 行)")
        return csv_path

    def _export_metrics_json(self, metrics: dict, run_dir: str) -> str:
        """
        导出指标汇总 JSON。

        包含 accuracy, precision, recall, f1, 混淆矩阵,
        混淆识别率, 分类一致性, 延迟和 Token 统计等。

        Args:
            metrics: 指标字典
            run_dir: 输出目录

        Returns:
            JSON 文件路径
        """
        metrics_path = os.path.join(run_dir, "metrics.json")

        # 添加导出时间戳
        export_data = {
            "export_time": datetime.now().isoformat(),
            **metrics,
        }

        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        logger.debug(f"metrics.json 已写入: {metrics_path}")
        return metrics_path
