"""
指标计算模块

计算检测实验的各项评估指标。

功能：
- 准确率 Accuracy
- 精确率 Precision
- 召回率 Recall
- F1 分数
- 混淆识别率（对混淆变种的识别能力）
- 分类一致性（恶意类型标注准确性）

使用方式（阶段二实现）：
    from src.metrics import MetricsCalculator
    calc = MetricsCalculator()
    metrics = calc.calculate(predictions, true_labels)
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class MetricsCalculator:
    """实验评估指标计算器。"""

    def calculate(
        self,
        predictions: list[dict],
        true_labels: list[dict],
    ) -> dict:
        """
        计算全部评估指标。

        Args:
            predictions: 每条样本的预测结果列表
            true_labels: 每条样本的真实标签列表

        Returns:
            指标字典，包含 accuracy, precision, recall, f1, obfuscation_recall 等
        """
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _calc_accuracy(self, tp: int, tn: int, fp: int, fn: int) -> float:
        """准确率 = (TP+TN) / (TP+TN+FP+FN)"""
        total = tp + tn + fp + fn
        return (tp + tn) / total if total > 0 else 0.0

    def _calc_precision(self, tp: int, fp: int) -> float:
        """精确率 = TP / (TP+FP)"""
        denom = tp + fp
        return tp / denom if denom > 0 else 0.0

    def _calc_recall(self, tp: int, fn: int) -> float:
        """召回率 = TP / (TP+FN)"""
        denom = tp + fn
        return tp / denom if denom > 0 else 0.0

    def _calc_f1(self, precision: float, recall: float) -> float:
        """F1 = 2·P·R / (P+R)"""
        denom = precision + recall
        return 2 * precision * recall / denom if denom > 0 else 0.0
