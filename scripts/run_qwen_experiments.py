"""
补全通义千问3组独立实验（zero_shot / few_shot / cot）

使用 ConcurrentDetector 并发执行，显著加速实验。
每组实验独立运行，不共享缓存，确保实验独立性。

用法：
    python scripts/run_qwen_experiments.py                    # 运行全部3组
    python scripts/run_qwen_experiments.py --only zero_shot    # 只运行指定策略
    python scripts/run_qwen_experiments.py --only cot --resume results/E_cot_qwen_20260811_021620
"""

import os
import sys
import time
import json
import logging
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


def load_env_file(env_path: str | None = None) -> None:
    """从 .env 文件加载环境变量（不覆盖已有的环境变量）。"""
    env_path = env_path or os.path.join(PROJECT_ROOT, ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip("'\"")
                if key and value and key not in os.environ:
                    os.environ[key] = value


# 启动时自动加载 .env 文件
load_env_file()

from src.llm_client import LLMClient, load_config
from src.sample_loader import SampleLoader
from src.prompt_templates import PromptTemplate
from src.result_parser import ResultParser
from src.metrics import MetricsCalculator
from src.exporter import Exporter
from src.optimized_pipeline import ConcurrentDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

STRATEGIES = ["zero_shot", "few_shot", "cot"]


def load_previous_results(run_dir: str) -> dict:
    """从之前的实验目录加载已完成的结果。

    Returns:
        filename -> result dict 的映射（仅包含成功检测的样本）
    """
    raw_path = os.path.join(run_dir, "raw_results.json")
    if not os.path.exists(raw_path):
        logger.warning(f"未找到之前的结果文件: {raw_path}")
        return {}

    with open(raw_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", []) if isinstance(data, dict) else data
    prev = {}
    for r in results:
        if r.get("pred_label") in ("malicious", "benign"):
            fname = r.get("filename", os.path.basename(r.get("file_path", "")))
            prev[fname] = r

    logger.info(f"从 {run_dir} 加载了 {len(prev)} 条成功结果")
    return prev


def run_single_strategy(strategy, provider="qwen", concurrency=5, resume_dir=None):
    """运行单组独立实验（不使用缓存，确保独立性）

    Args:
        resume_dir: 如果指定，从该目录加载已完成的结果，仅重新运行失败的样本
    """
    logger.info("=" * 60)
    logger.info(f"实验: {provider} + {strategy}")
    logger.info("=" * 60)

    config = load_config()
    start_time = time.time()

    # 初始化组件
    llm_client = LLMClient(provider=provider, config=config)
    sample_loader = SampleLoader(
        labels_file=config.get("dataset", {}).get("labels_file", "data/labels.csv"),
        base_dir=PROJECT_ROOT,
    )
    prompt_template = PromptTemplate(strategy=strategy)
    result_parser = ResultParser()
    metrics_calc = MetricsCalculator()

    output_dir = config.get("output", {}).get("root_dir", "results")
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(PROJECT_ROOT, output_dir)
    exporter = Exporter(output_dir=output_dir)

    # 加载全部样本
    all_samples = sample_loader.load_samples()
    logger.info(f"共 {len(all_samples)} 条样本")

    # 加载之前的成功结果（如果指定了 resume_dir）
    prev_results = {}
    if resume_dir:
        if not os.path.isabs(resume_dir):
            resume_dir = os.path.join(PROJECT_ROOT, resume_dir)
        prev_results = load_previous_results(resume_dir)

    # 分离已完成的样本和需要重新运行的样本
    samples_to_run = []
    cached_results = []
    for s in all_samples:
        fname = os.path.basename(s.file_path)
        if fname in prev_results:
            cached_results.append(prev_results[fname])
        else:
            samples_to_run.append(s)

    logger.info(f"已完成: {len(cached_results)} 条，需检测: {len(samples_to_run)} 条")

    # 并发检测（不使用缓存，确保实验独立性）
    detector = ConcurrentDetector(
        llm_client=llm_client,
        prompt_template=prompt_template,
        result_parser=result_parser,
        concurrency=concurrency,
    )

    if samples_to_run:
        new_results = detector.detect_batch(
            samples=samples_to_run,
            strategy=strategy,
            provider=provider,
            cache=None,  # 不使用缓存
            progress_label=f"[{strategy}] ",
        )
    else:
        new_results = []
        logger.info("所有样本已完成，无需重新检测")

    # 合并结果：保持原始样本顺序
    cached_by_name = {}
    for r in cached_results:
        fname = r.get("filename", os.path.basename(r.get("file_path", "")))
        cached_by_name[fname] = r

    new_by_name = {}
    for r in new_results:
        fname = r.get("filename", os.path.basename(r.get("file_path", "")))
        new_by_name[fname] = r

    results = []
    for s in all_samples:
        fname = os.path.basename(s.file_path)
        if fname in cached_by_name:
            results.append(cached_by_name[fname])
        elif fname in new_by_name:
            results.append(new_by_name[fname])
        else:
            logger.warning(f"样本 {fname} 的结果未找到，使用原始样本作为占位符")
            results.append(s)

    logger.info(f"合并后结果总数: {len(results)}")

    # 计算指标
    predictions = []
    true_labels = []
    for r in results:
        predictions.append({
            "label": r.get("pred_label", "unknown"),
            "malware_type": r.get("pred_malware_type", "unknown"),
            "obfuscation": r.get("pred_obfuscation", "unknown"),
            "confidence": r.get("pred_confidence", 0.0),
            "latency_ms": r.get("latency_ms", 0),
            "total_tokens": r.get("total_tokens", 0),
        })
        true_labels.append({
            "label": r.get("true_label", "unknown"),
            "malware_type": r.get("true_malware_type", "unknown"),
            "obfuscation": r.get("true_obfuscation", "none"),
            "category": r.get("category", ""),
        })

    metrics = metrics_calc.calculate(predictions, true_labels)

    elapsed = time.time() - start_time
    logger.info(
        f"实验完成: {strategy}\n"
        f"  准确率: {metrics['accuracy']}\n"
        f"  精确率: {metrics['precision']}\n"
        f"  召回率: {metrics['recall']}\n"
        f"  F1: {metrics['f1']}\n"
        f"  未分类: {metrics['unclassified']}\n"
        f"  耗时: {elapsed:.1f}s ({elapsed/60:.1f}分钟)"
    )

    # 导出结果
    experiment_name = f"E_{strategy}_{provider}"
    run_dir = exporter.export_results(
        results=results,
        experiment_name=experiment_name,
        metrics=metrics,
    )
    logger.info(f"结果已导出至: {run_dir}")

    return {
        "strategy": strategy,
        "provider": provider,
        "metrics": metrics,
        "elapsed_seconds": round(elapsed, 1),
        "run_dir": run_dir,
    }


def main():
    parser = argparse.ArgumentParser(description="LLM独立实验（支持DeepSeek/Qwen）")
    parser.add_argument(
        "--provider", choices=["deepseek", "qwen"], default="qwen",
        help="API提供商（默认qwen）"
    )
    parser.add_argument(
        "--only", choices=STRATEGIES,
        help="只运行指定策略"
    )
    parser.add_argument(
        "--concurrency", type=int, default=5,
        help="最大并发数（默认5）"
    )
    parser.add_argument(
        "--resume", type=str, default=None,
        help="从之前的实验目录恢复（仅重新运行失败的样本）"
    )
    args = parser.parse_args()

    strategies = [args.only] if args.only else STRATEGIES

    logger.info(f"{args.provider} 独立实验启动，共 {len(strategies)} 组")
    logger.info(f"策略列表: {strategies}")
    logger.info(f"并发数: {args.concurrency}")
    if args.resume:
        logger.info(f"恢复模式: 从 {args.resume} 加载已完成结果")

    results_summary = []
    total_start = time.time()

    for strategy in strategies:
        result = run_single_strategy(
            strategy,
            provider=args.provider,
            concurrency=args.concurrency,
            resume_dir=args.resume,
        )
        results_summary.append(result)

    total_elapsed = time.time() - total_start

    logger.info("=" * 60)
    logger.info("全部实验完成")
    logger.info("=" * 60)
    for r in results_summary:
        m = r["metrics"]
        logger.info(
            f"  {r['strategy']:12s}: "
            f"acc={m['accuracy']:.4f} "
            f"f1={m['f1']:.4f} "
            f"unclassified={m['unclassified']} "
            f"({r['elapsed_seconds']/60:.1f}min)"
        )
    logger.info(f"  总耗时: {total_elapsed/60:.1f}分钟")


if __name__ == "__main__":
    main()
