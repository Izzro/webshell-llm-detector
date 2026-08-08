"""
指标计算模块

计算检测实验的各项评估指标。

功能：
- 准确率 Accuracy
- 精确率 Precision
- 召回率 Recall
- F1 分数
- 混淆识别率（对混淆变种的识别能力，可按混淆类型分组）
- 分类一致性（恶意类型标注准确性）
- 平均延迟和 Token 消耗统计

使用方式：
    from src.metrics import MetricsCalculator
    calc = MetricsCalculator()
    metrics = calc.calculate(predictions, true_labels)

predictions 每条包含: label, malware_type, obfuscation, confidence,
    parse_error, latency_ms, total_tokens
true_labels 每条包含: label, malware_type, obfuscation, category
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

        二分类统计规则：
          - TP: 真实恶意 + 预测恶意
          - TN: 真实良性 + 预测良性
          - FP: 真实良性 + 预测恶意（误报）
          - FN: 真实恶意 + 预测良性（漏报）
          - unknown 处理：真实恶意→计FN（漏报），真实良性→计TN（未误报）
            同时单独统计 unclassified 数量

        Args:
            predictions: 每条样本的预测结果列表，每条包含 label, malware_type,
                         obfuscation, confidence, latency_ms, total_tokens 等
            true_labels: 每条样本的真实标签列表，每条包含 label, malware_type,
                         obfuscation, category

        Returns:
            指标字典，包含 accuracy, precision, recall, f1, obfuscation_recall,
            type_consistency, avg_latency_ms, total_tokens 等
        """
        # 长度校验
        if len(predictions) != len(true_labels):
            logger.warning(
                f"predictions({len(predictions)}) 与 true_labels({len(true_labels)}) "
                f"长度不一致，按较短长度计算"
            )

        # 初始化计数器
        tp = tn = fp = fn = un = 0
        type_correct = 0          # malware_type 预测正确数
        obf_total = 0              # 混淆样本总数
        obf_correct = 0            # 混淆样本正确检出数
        obf_by_type = {}           # 按混淆类型分组: {type: {"total": n, "correct": n}}
        latencies = []
        tokens = []

        for pred, true in zip(predictions, true_labels):
            pred_label = pred.get("label", "unknown")
            true_label = true.get("label", "unknown")

            # 延迟和 Token 统计
            if "latency_ms" in pred:
                latencies.append(pred["latency_ms"])
            if "total_tokens" in pred:
                tokens.append(pred["total_tokens"])

            # ---- 二分类统计 ----
            if pred_label == "unknown":
                un += 1
                # unknown: 真实恶意→FN（漏报），真实良性→TN（未误报）
                if true_label == "malicious":
                    fn += 1
                else:
                    tn += 1
            elif pred_label == "malicious" and true_label == "malicious":
                tp += 1
            elif pred_label == "benign" and true_label == "benign":
                tn += 1
            elif pred_label == "malicious" and true_label == "benign":
                fp += 1
            elif pred_label == "benign" and true_label == "malicious":
                fn += 1

            # ---- 分类一致性：malware_type 预测正确 ----
            if true_label == "malicious" and pred_label == "malicious":
                if pred.get("malware_type") == true.get("malware_type"):
                    type_correct += 1

            # ---- 混淆识别率 ----
            true_obf = true.get("obfuscation", "none")
            if true_obf != "none":
                obf_total += 1
                is_correct = (pred_label == "malicious")
                if is_correct:
                    obf_correct += 1

                # 按混淆类型分组
                if true_obf not in obf_by_type:
                    obf_by_type[true_obf] = {"total": 0, "correct": 0}
                obf_by_type[true_obf]["total"] += 1
                if is_correct:
                    obf_by_type[true_obf]["correct"] += 1

        # ---- 基础指标 ----
        accuracy = self._calc_accuracy(tp, tn, fp, fn)
        precision = self._calc_precision(tp, fp)
        recall = self._calc_recall(tp, fn)
        f1 = self._calc_f1(precision, recall)

        # ---- 混淆识别率 ----
        obfuscation_recall = obf_correct / obf_total if obf_total > 0 else 0.0

        # 按混淆类型分组的识别率
        obf_by_type_recall = {}
        for obf_type, counts in obf_by_type.items():
            obf_by_type_recall[obf_type] = round(
                counts["correct"] / counts["total"], 4
            ) if counts["total"] > 0 else 0.0

        # ---- 分类一致性 ----
        malicious_total = tp + fn  # 所有真实恶意样本（含漏报）
        type_consistency = type_correct / malicious_total if malicious_total > 0 else 0.0

        # ---- 延迟和 Token ----
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        max_latency = max(latencies) if latencies else 0
        min_latency = min(latencies) if latencies else 0
        total_tokens = sum(tokens)
        avg_tokens = sum(tokens) / len(tokens) if tokens else 0.0

        return {
            "total_samples": len(predictions),
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "unclassified": un,
            "obfuscation_recall": round(obfuscation_recall, 4),
            "obf_total": obf_total,
            "obf_correct": obf_correct,
            "obf_by_type": obf_by_type_recall,
            "type_consistency": round(type_consistency, 4),
            "avg_latency_ms": round(avg_latency, 1),
            "max_latency_ms": max_latency,
            "min_latency_ms": min_latency,
            "total_tokens": total_tokens,
            "avg_tokens": round(avg_tokens, 1),
        }

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
