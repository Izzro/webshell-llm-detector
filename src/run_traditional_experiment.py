"""
传统工具对照实验运行脚本

使用 TraditionalScanner 对全量 515 条样本进行检测，
计算与 LLM 实验相同的评估指标，并导出对照实验结果。

使用方式：
    python -m src.run_traditional_experiment
"""

import os
import sys
import json
import time
import logging
import argparse

# 添加项目根目录到路径
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.traditional_scanner import TraditionalScanner, ScanResult
from src.sample_loader import SampleLoader, Sample
from src.metrics import MetricsCalculator
from src.exporter import Exporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def scan_result_to_dict(result: ScanResult, sample: Sample) -> dict:
    """将 TraditionalScanner 的 ScanResult 转换为与 LLM 实验一致的字典格式。"""
    pred_label = result.label
    true_label = sample.label

    correct = ""
    if pred_label != "unknown":
        correct = 1 if pred_label == true_label else 0

    return {
        "file_path": sample.file_path,
        "filename": os.path.basename(sample.file_path),
        "category": sample.category,
        "true_label": true_label,
        "true_malware_type": sample.malware_type,
        "true_obfuscation": sample.obfuscation,
        "pred_label": pred_label,
        "pred_malware_type": result.malware_type,
        "pred_subtype": result.subtype,
        "pred_obfuscation": result.obfuscation,
        "pred_confidence": result.confidence,
        "pred_risk_level": result.risk_level,
        "reason": result.reason,
        "indicators": result.indicators,
        "parse_error": "",
        "latency_ms": 0,          # 传统扫描器无网络延迟
        "total_tokens": 0,        # 无 Token 消耗
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "correct": correct,
        "rules_triggered": result.rules_triggered,
    }


def run_traditional_experiment() -> dict:
    """运行传统扫描器全量实验。"""
    start_time = time.time()

    # 1. 加载样本
    logger.info("=" * 60)
    logger.info("传统工具对照实验 - 开始")
    logger.info("=" * 60)

    labels_file = os.path.join(PROJECT_ROOT, "data", "labels.csv")
    loader = SampleLoader(labels_file=labels_file, base_dir=PROJECT_ROOT)
    samples = loader.load_samples()
    logger.info(f"已加载 {len(samples)} 条样本")

    # 2. 初始化扫描器
    scanner = TraditionalScanner()
    logger.info("传统扫描器初始化完成")

    # 3. 逐条扫描
    results = []
    for i, sample in enumerate(samples):
        # 推断语言
        if sample.language:
            language = sample.language
        else:
            ext = os.path.splitext(sample.file_path)[1].lower()
            language = {".php": "php", ".py": "python", ".txt": "sql"}.get(ext, "unknown")

        scan_result = scanner.scan(sample.code_text, language=language)
        result_dict = scan_result_to_dict(scan_result, sample)
        results.append(result_dict)

        if (i + 1) % 100 == 0:
            logger.info(f"扫描进度: {i + 1}/{len(samples)}")

    logger.info(f"扫描完成，共 {len(results)} 条结果")

    # 4. 计算指标
    calc = MetricsCalculator()

    # 构造 predictions 和 true_labels
    predictions = []
    true_labels = []
    for r in results:
        predictions.append({
            "label": r["pred_label"],
            "malware_type": r["pred_malware_type"],
            "obfuscation": r["pred_obfuscation"],
            "confidence": r["pred_confidence"],
            "latency_ms": r["latency_ms"],
            "total_tokens": r["total_tokens"],
        })
        true_labels.append({
            "label": r["true_label"],
            "malware_type": r["true_malware_type"],
            "obfuscation": r["true_obfuscation"],
            "category": r["category"],
        })

    metrics = calc.calculate(predictions, true_labels)

    # 添加传统扫描器特有指标
    metrics["scanner_type"] = "traditional_rule_based"
    metrics["scan_time_s"] = round(time.time() - start_time, 2)

    # 统计规则触发情况
    total_rules_triggered = 0
    for r in results:
        total_rules_triggered += len(r.get("rules_triggered", []))
    metrics["total_rules_triggered"] = total_rules_triggered
    metrics["avg_rules_per_sample"] = round(total_rules_triggered / len(results), 2)

    logger.info(f"指标计算完成:")
    logger.info(f"  准确率:     {metrics['accuracy']:.4f}")
    logger.info(f"  精确率:     {metrics['precision']:.4f}")
    logger.info(f"  召回率:     {metrics['recall']:.4f}")
    logger.info(f"  F1 分数:    {metrics['f1']:.4f}")
    logger.info(f"  混淆识别率: {metrics['obfuscation_recall']:.4f}")

    # 5. 导出结果
    output_dir = os.path.join(PROJECT_ROOT, "results")
    exporter = Exporter(output_dir=output_dir)
    run_dir = exporter.export_results(
        results=results,
        experiment_name="E_traditional_scanner",
        metrics=metrics,
    )

    elapsed = time.time() - start_time
    logger.info(f"实验完成，耗时 {elapsed:.1f}s")
    logger.info(f"结果已导出至: {run_dir}")

    return {
        "run_dir": run_dir,
        "metrics": metrics,
        "results": results,
    }


if __name__ == "__main__":
    run_traditional_experiment()
