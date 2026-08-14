"""
批量检测主流程模块

串联样本加载、提示词组装、API 调用、结果解析、指标计算、数据导出，
实现完整的检测管道。支持命令行参数指定提示词策略、API 提供商、样本范围。

管道流程：
    SampleLoader → PromptTemplate → LLMClient → ResultParser
        → MetricsCalculator → Exporter

使用方式：
    python -m src.batch_runner --strategy cot --provider deepseek
    python -m src.batch_runner --strategy few_shot --provider qwen --category obfuscated
    python -m src.batch_runner --strategy zero_shot --provider deepseek --max-samples 10
"""

import os
import sys
import time
import logging
import argparse
from collections import Counter

from src.llm_client import LLMClient, load_config
from src.sample_loader import SampleLoader, Sample
from src.prompt_templates import PromptTemplate
from src.result_parser import ResultParser
from src.metrics import MetricsCalculator
from src.exporter import Exporter

logger = logging.getLogger(__name__)

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class BatchRunner:
    """批量检测主流程控制器。"""

    # 策略与 JSON 模式映射（三组策略统一使用 JSON 模式，确保输出可解析）
    JSON_MODE_STRATEGIES = {"zero_shot", "few_shot", "cot"}

    def __init__(
        self,
        provider: str = "deepseek",
        strategy: str = "zero_shot",
        config_path: str | None = None,
    ):
        """
        初始化各管道组件。

        Args:
            provider: API 提供商（deepseek / qwen）
            strategy: 提示词策略（zero_shot / few_shot / cot）
            config_path: 配置文件路径，为 None 时使用默认 config.yaml
        """
        self.provider = provider
        self.strategy = strategy
        self.config_path = config_path

        # 加载配置
        config = load_config(config_path)
        self.config = config

        # 初始化各组件
        self.llm_client = LLMClient(provider=provider, config=config)
        self.sample_loader = SampleLoader(
            labels_file=config.get("dataset", {}).get("labels_file", "data/labels.csv"),
            base_dir=PROJECT_ROOT,
        )
        self.prompt_template = PromptTemplate(strategy=strategy)
        self.result_parser = ResultParser()
        self.metrics_calc = MetricsCalculator()

        output_dir = config.get("output", {}).get("root_dir", "results")
        if not os.path.isabs(output_dir):
            output_dir = os.path.join(PROJECT_ROOT, output_dir)
        self.exporter = Exporter(output_dir=output_dir)

        # 速率限制
        self.rate_limit_delay = config.get("detection", {}).get("rate_limit_delay", 0.5)

        # JSON 模式
        self.use_json = strategy in self.JSON_MODE_STRATEGIES

        logger.info(
            f"BatchRunner 初始化: provider={provider}, strategy={strategy}, "
            f"use_json={self.use_json}, rate_limit={self.rate_limit_delay}s"
        )

    def run(
        self,
        category: str | None = None,
        obfuscation: str | None = None,
        max_samples: int | None = None,
        repeats: int = 1,
    ) -> str:
        """
        执行批量检测。

        流程：
        1. 加载样本（按 category / obfuscation 筛选）
        2. 对每条样本执行检测（支持 repeats 次重复 + 多数投票）
        3. 计算评估指标
        4. 导出结果

        Args:
            category: 按类别筛选样本（benign/webshell/obfuscated/sqli）
            obfuscation: 按混淆方式筛选样本
            max_samples: 最大检测样本数（调试用）
            repeats: 每条样本重复运行次数（取多数投票）

        Returns:
            结果输出目录路径
        """
        # ---- 1. 加载样本 ----
        logger.info(f"开始批量检测: category={category}, obfuscation={obfuscation}, "
                     f"max_samples={max_samples}, repeats={repeats}")

        samples = self.sample_loader.load_samples(
            category=category,
            obfuscation=obfuscation,
        )

        # 限制样本数
        if max_samples is not None and max_samples > 0:
            samples = samples[:max_samples]
            logger.info(f"限制为前 {max_samples} 条样本")

        total = len(samples)
        if total == 0:
            logger.warning("没有匹配的样本，退出")
            return ""

        logger.info(f"共 {total} 条样本待检测，每条重复 {repeats} 次")

        # ---- 2. 逐条检测 ----
        results = []
        for i, sample in enumerate(samples, 1):
            logger.info(f"[{i}/{total}] 检测: {sample.file_path}")

            # 重复检测 + 多数投票
            if repeats > 1:
                repeat_results = []
                for r in range(repeats):
                    result = self._detect_single(sample)
                    repeat_results.append(result)
                    if r < repeats - 1:
                        time.sleep(self.rate_limit_delay)

                final_result = self._majority_vote(repeat_results)
                # 记录重复次数
                final_result["repeats"] = repeats
            else:
                final_result = self._detect_single(sample)

            results.append(final_result)

            # 速率限制（非最后一条）
            if i < total:
                time.sleep(self.rate_limit_delay)

        # ---- 3. 计算指标 ----
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

        metrics = self.metrics_calc.calculate(predictions, true_labels)

        logger.info(
            f"检测完成: accuracy={metrics['accuracy']}, "
            f"precision={metrics['precision']}, recall={metrics['recall']}, "
            f"f1={metrics['f1']}"
        )

        # ---- 4. 导出结果 ----
        experiment_name = f"E_{self.strategy}_{self.provider}"
        if category:
            experiment_name += f"_{category}"
        if obfuscation:
            experiment_name += f"_{obfuscation}"

        run_dir = self.exporter.export_results(
            results=results,
            experiment_name=experiment_name,
            metrics=metrics,
        )

        return run_dir

    def _detect_single(self, sample: Sample) -> dict:
        """
        检测单条样本。

        流程：
        1. 组装提示词消息
        2. 调用 LLM API
        3. 解析响应为 DetectionResult
        4. 组装结果字典（含真实标签、预测、用量）

        异常处理：API 调用失败时记录错误，返回 label=unknown 的结果。

        Args:
            sample: 样本对象（含 code_text, language 等）

        Returns:
            结果字典，包含 file_path, true_label, pred_label, latency_ms 等
        """
        # 组装提示词
        messages = self.prompt_template.build_messages(
            code_text=sample.code_text,
            language=sample.language,
        )

        # 基础结果字段（真实标签 + 样本信息）
        base = {
            "file_path": sample.file_path,
            "filename": os.path.basename(sample.file_path),
            "category": sample.category,
            "true_label": sample.label,
            "true_malware_type": sample.malware_type,
            "true_obfuscation": sample.obfuscation,
            "pred_label": "unknown",
            "pred_malware_type": "unknown",
            "pred_subtype": "unknown",
            "pred_obfuscation": "unknown",
            "pred_confidence": 0.0,
            "pred_risk_level": "unknown",
            "reason": "",
            "indicators": [],
            "parse_error": "",
            "latency_ms": 0,
            "total_tokens": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "correct": "",
        }

        try:
            # 调用 API
            raw_result, usage = self.llm_client.detect(
                messages=messages,
                use_json=self.use_json,
            )

            # 解析响应
            detection = self.result_parser.parse(raw_result, strategy=self.strategy)

            # 填充预测字段
            base["pred_label"] = detection.label
            base["pred_malware_type"] = detection.malware_type
            base["pred_subtype"] = detection.subtype
            base["pred_obfuscation"] = detection.obfuscation
            base["pred_confidence"] = detection.confidence
            base["pred_risk_level"] = detection.risk_level
            base["reason"] = detection.reason
            base["indicators"] = detection.indicators or []
            base["parse_error"] = detection.parse_error

            # 填充用量
            base["latency_ms"] = usage.get("latency_ms", 0)
            base["total_tokens"] = usage.get("total_tokens", 0)
            base["prompt_tokens"] = usage.get("prompt_tokens", 0)
            base["completion_tokens"] = usage.get("completion_tokens", 0)

        except Exception as e:
            logger.error(
                f"样本检测失败: {sample.file_path}: "
                f"{type(e).__name__}: {e}"
            )
            base["parse_error"] = f"{type(e).__name__}: {str(e)[:200]}"

        # 判定是否正确
        if base["pred_label"] != "unknown":
            base["correct"] = 1 if base["pred_label"] == base["true_label"] else 0

        return base

    def _majority_vote(self, results: list[dict]) -> dict:
        """
        对多次运行结果取多数投票。

        投票规则：
        1. 统计 label 出现次数，取最多的作为最终 label
        2. 在多数 label 组中，取 confidence 最高的那条结果
        3. 如果 label 出现次数相同，优先 malicious（保守策略）
        4. 聚合延迟和 Token（取平均值）

        Args:
            results: 多次检测的结果列表

        Returns:
            投票后的最终结果字典
        """
        if len(results) == 1:
            return results[0]

        # 统计 label 出现次数
        label_counts = Counter(r["pred_label"] for r in results)

        # 取出现最多的 label（平局时优先 malicious）
        sorted_labels = sorted(
            label_counts.items(),
            key=lambda x: (-x[1], 0 if x[0] == "malicious" else 1),
        )
        majority_label = sorted_labels[0][0]

        # 在多数组中取 confidence 最高的
        majority_results = [
            r for r in results if r["pred_label"] == majority_label
        ]
        best = max(majority_results, key=lambda r: r.get("pred_confidence", 0.0))

        # 聚合延迟和 Token（取平均值）
        latencies = [r.get("latency_ms", 0) for r in results]
        tokens = [r.get("total_tokens", 0) for r in results]
        best = dict(best)  # 浅拷贝，不修改原始
        best["latency_ms"] = round(sum(latencies) / len(latencies), 1)
        best["total_tokens"] = sum(tokens)
        best["prompt_tokens"] = round(
            sum(r.get("prompt_tokens", 0) for r in results) / len(results), 1
        )
        best["completion_tokens"] = round(
            sum(r.get("completion_tokens", 0) for r in results) / len(results), 1
        )
        best["vote_label"] = majority_label
        best["vote_distribution"] = dict(label_counts)

        logger.debug(
            f"多数投票: {dict(label_counts)} → {majority_label} "
            f"(confidence={best.get('pred_confidence', 0.0)})"
        )

        return best


def main():
    """命令行入口。"""
    parser = argparse.ArgumentParser(
        description="WebShell LLM Detector - 批量检测"
    )
    parser.add_argument(
        "--strategy", choices=["zero_shot", "few_shot", "cot"],
        default="zero_shot", help="提示词策略"
    )
    parser.add_argument(
        "--provider", choices=["deepseek", "qwen"],
        default="deepseek", help="API 提供商"
    )
    parser.add_argument(
        "--category", choices=["benign", "webshell", "obfuscated", "sqli"],
        default=None, help="按类别筛选样本"
    )
    parser.add_argument(
        "--obfuscation",
        choices=["base64", "string_split", "xor", "comment_bypass"],
        default=None, help="按混淆方式筛选样本"
    )
    parser.add_argument(
        "--max-samples", type=int, default=None,
        help="最大检测样本数（调试用）"
    )
    parser.add_argument(
        "--repeats", type=int, default=1,
        help="每条样本重复运行次数"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="日志级别"
    )
    args = parser.parse_args()

    # 配置日志
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    runner = BatchRunner(
        provider=args.provider,
        strategy=args.strategy,
    )
    output_dir = runner.run(
        category=args.category,
        obfuscation=args.obfuscation,
        max_samples=args.max_samples,
        repeats=args.repeats,
    )
    print(f"\n实验完成，结果已导出至: {output_dir}")


if __name__ == "__main__":
    main()
