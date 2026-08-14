"""
优化检测管道模块

实现「并发 + 缓存 + 两段式」加速方案：
  1. 并发层：ThreadPoolExecutor 并行调用 LLM API，绕过串行速率限制
  2. 缓存层：基于文件内容 MD5 哈希缓存检测结果，重复文件直接命中
  3. 两段式：Stage1 Few-shot 快速初筛 → Stage2 CoT 复核低置信度样本

管道流程：
    SampleLoader → [缓存命中?] → ConcurrentDetector(Few-shot)
        → [confidence < 阈值?] → ConcurrentDetector(CoT) → 结果融合
        → MetricsCalculator → Exporter

使用方式：
    python -m src.optimized_pipeline --max-samples 30 --concurrency 5
    python -m src.optimized_pipeline --provider deepseek --confidence-threshold 0.9
"""

import os
import sys
import time
import json
import logging
import argparse
import hashlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.llm_client import LLMClient, load_config
from src.sample_loader import SampleLoader, Sample
from src.prompt_templates import PromptTemplate
from src.result_parser import ResultParser
from src.metrics import MetricsCalculator
from src.exporter import Exporter

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ================================================================
# 缓存管理器
# ================================================================

class CacheManager:
    """基于文件内容哈希的检测结果缓存，支持磁盘持久化以实现断点续跑。"""

    def __init__(self, cache_file: str | None = None):
        self._cache: dict[str, dict] = {}
        self.hits = 0
        self.misses = 0
        self.cache_file = cache_file
        self._load_from_disk()

    def _load_from_disk(self):
        """从磁盘加载缓存（断点续跑）。"""
        if self.cache_file and os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
                logger.info(f"从磁盘加载缓存: {len(self._cache)} 条 ({self.cache_file})")
            except Exception as e:
                logger.warning(f"加载缓存失败: {e}")
                self._cache = {}

    def save_to_disk(self):
        """保存缓存到磁盘。"""
        if not self.cache_file:
            return
        try:
            cache_dir = os.path.dirname(self.cache_file)
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False)
            logger.debug(f"缓存已保存到磁盘: {len(self._cache)} 条")
        except Exception as e:
            logger.warning(f"保存缓存失败: {e}")

    def _make_key(self, code_text: str, strategy: str, provider: str) -> str:
        """生成缓存键：MD5(代码内容 + 策略 + 提供商)。"""
        content = f"{strategy}:{provider}:{code_text}"
        return hashlib.md5(content.encode("utf-8")).hexdigest()

    def get(self, code_text: str, strategy: str, provider: str) -> dict | None:
        """查询缓存，命中返回结果字典，未命中返回 None。"""
        key = self._make_key(code_text, strategy, provider)
        if key in self._cache:
            self.hits += 1
            result = dict(self._cache[key])
            result["cache_hit"] = True
            return result
        self.misses += 1
        return None

    def put(self, code_text: str, strategy: str, provider: str, result: dict) -> None:
        """存入缓存结果（仅缓存无错误的结果）。"""
        if result.get("parse_error"):
            return  # 有错误的样本不缓存，以便下次重试
        key = self._make_key(code_text, strategy, provider)
        cached = {k: v for k, v in result.items() if k != "cache_hit"}
        self._cache[key] = cached

    def stats(self) -> dict:
        """返回缓存统计信息。"""
        total = self.hits + self.misses
        return {
            "cache_hits": self.hits,
            "cache_misses": self.misses,
            "cache_hit_rate": self.hits / total if total > 0 else 0.0,
            "cache_size": len(self._cache),
        }


# ================================================================
# 并发检测器
# ================================================================

class ConcurrentDetector:
    """并发 LLM 检测器，使用线程池并行调用 API。"""

    # JSON 模式策略（三组策略统一使用 JSON 模式）
    JSON_MODE_STRATEGIES = {"zero_shot", "few_shot", "cot"}

    def __init__(
        self,
        llm_client: LLMClient,
        prompt_template: PromptTemplate,
        result_parser: ResultParser,
        concurrency: int = 5,
    ):
        """
        Args:
            llm_client: LLM API 客户端
            prompt_template: 提示词模板
            result_parser: 结果解析器
            concurrency: 最大并发数
        """
        self.llm_client = llm_client
        self.prompt_template = prompt_template
        self.result_parser = result_parser
        self.concurrency = concurrency

    def detect_batch(
        self,
        samples: list[Sample],
        strategy: str,
        provider: str,
        cache: CacheManager | None = None,
        progress_label: str = "",
    ) -> list[dict]:
        """
        并发批量检测样本。

        流程：
        1. 先查缓存，命中则直接返回
        2. 未命中的样本提交到线程池并发执行
        3. 收集结果并写入缓存
        4. 按原始顺序返回结果

        Args:
            samples: 待检测样本列表
            strategy: 提示词策略
            provider: API 提供商
            cache: 缓存管理器，None 表示不缓存
            progress_label: 进度日志前缀

        Returns:
            结果列表（与输入样本顺序一致）
        """
        use_json = strategy in self.JSON_MODE_STRATEGIES
        total = len(samples)
        results: list[dict | None] = [None] * total

        # 1. 查缓存
        to_detect: list[tuple[int, Sample]] = []
        cache_hits = 0
        for i, sample in enumerate(samples):
            if cache:
                cached = cache.get(sample.code_text, strategy, provider)
                if cached:
                    results[i] = cached
                    cache_hits += 1
                    continue
            to_detect.append((i, sample))

        logger.info(
            f"{progress_label}共 {total} 条，缓存命中 {cache_hits} 条，"
            f"需检测 {len(to_detect)} 条（并发={self.concurrency}）"
        )

        if not to_detect:
            return [r for r in results if r is not None]

        # 2. 并发检测
        completed = 0
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {}
            for idx, sample in to_detect:
                future = executor.submit(
                    self._detect_one,
                    sample=sample,
                    strategy=strategy,
                    use_json=use_json,
                )
                futures[future] = (idx, sample)

            for future in as_completed(futures):
                idx, sample = futures[future]
                try:
                    result = future.result()
                    results[idx] = result
                    if cache:
                        cache.put(sample.code_text, strategy, provider, result)
                except Exception as e:
                    logger.error(f"检测失败: {sample.file_path}: {e}")
                    results[idx] = self._make_error_result(sample, str(e))

                completed += 1
                if completed % 10 == 0 or completed == len(to_detect):
                    logger.info(
                        f"{progress_label}进度: {completed}/{len(to_detect)}"
                    )
                # 每 10 条或最后一条或小批量时每条保存缓存
                if cache and hasattr(cache, "save_to_disk") and (
                    completed % 10 == 0
                    or completed == len(to_detect)
                    or len(to_detect) <= 10
                ):
                    cache.save_to_disk()

        return [r for r in results if r is not None]

    def _detect_one(
        self,
        sample: Sample,
        strategy: str,
        use_json: bool,
    ) -> dict:
        """检测单条样本（线程安全，每个线程独立调用）。"""
        messages = self.prompt_template.build_messages(
            code_text=sample.code_text,
            language=sample.language,
        )

        base = self._make_base_result(sample)

        try:
            raw_result, usage = self.llm_client.detect(
                messages=messages,
                use_json=use_json,
            )

            detection = self.result_parser.parse(raw_result, strategy=strategy)

            base["pred_label"] = detection.label
            base["pred_malware_type"] = detection.malware_type
            base["pred_subtype"] = detection.subtype
            base["pred_obfuscation"] = detection.obfuscation
            base["pred_confidence"] = detection.confidence
            base["pred_risk_level"] = detection.risk_level
            base["reason"] = detection.reason
            base["indicators"] = detection.indicators or []
            base["parse_error"] = detection.parse_error
            base["latency_ms"] = usage.get("latency_ms", 0)
            base["total_tokens"] = usage.get("total_tokens", 0)
            base["prompt_tokens"] = usage.get("prompt_tokens", 0)
            base["completion_tokens"] = usage.get("completion_tokens", 0)

        except Exception as e:
            base["parse_error"] = f"{type(e).__name__}: {str(e)[:200]}"

        if base["pred_label"] != "unknown":
            base["correct"] = 1 if base["pred_label"] == base["true_label"] else 0

        return base

    @staticmethod
    def _make_base_result(sample: Sample) -> dict:
        """构造基础结果字段。"""
        return {
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
            "cache_hit": False,
        }

    @staticmethod
    def _make_error_result(sample: Sample, error_msg: str) -> dict:
        """构造错误结果。"""
        base = ConcurrentDetector._make_base_result(sample)
        base["parse_error"] = f"并发检测异常: {error_msg[:200]}"
        return base


# ================================================================
# 两段式管道
# ================================================================

class TwoStagePipeline:
    """两段式检测管道：Few-shot 快速初筛 + CoT 复核可疑样本。"""

    def __init__(
        self,
        provider: str = "deepseek",
        concurrency: int = 5,
        confidence_threshold: float = 0.9,
        config_path: str | None = None,
        use_cache: bool = True,
    ):
        """
        Args:
            provider: API 提供商
            concurrency: 并发数
            confidence_threshold: Stage2 复核的置信度阈值
            config_path: 配置文件路径
            use_cache: 是否启用缓存（禁用可确保实验独立性）
        """
        self.provider = provider
        self.concurrency = concurrency
        self.confidence_threshold = confidence_threshold
        self.use_cache = use_cache

        config = load_config(config_path)
        self.config = config

        # 初始化组件
        self.llm_client = LLMClient(provider=provider, config=config)
        self.sample_loader = SampleLoader(
            labels_file=config.get("dataset", {}).get("labels_file", "data/labels.csv"),
            base_dir=PROJECT_ROOT,
        )
        self.result_parser = ResultParser()
        self.metrics_calc = MetricsCalculator()

        output_dir = config.get("output", {}).get("root_dir", "results")
        if not os.path.isabs(output_dir):
            output_dir = os.path.join(PROJECT_ROOT, output_dir)
        self.exporter = Exporter(output_dir=output_dir)

        # 两个策略的提示词模板
        self.fs_prompt = PromptTemplate(strategy="few_shot")
        self.cot_prompt = PromptTemplate(strategy="cot")

        # 缓存（带磁盘持久化，支持断点续跑）；禁用缓存时设为 None
        if use_cache:
            cache_file = os.path.join(PROJECT_ROOT, "results", "cache", f"cache_{provider}.json")
            self.cache = CacheManager(cache_file=cache_file)
            logger.info(f"缓存已启用: {cache_file}")
        else:
            self.cache = None
            logger.info("缓存已禁用，所有样本将通过 API 实时检测")

        # 并发检测器（Stage1 用 Few-shot JSON 模式）
        self.fs_detector = ConcurrentDetector(
            llm_client=self.llm_client,
            prompt_template=self.fs_prompt,
            result_parser=self.result_parser,
            concurrency=concurrency,
        )

        # CoT 检测器（Stage2 用 CoT 文本模式）
        self.cot_detector = ConcurrentDetector(
            llm_client=self.llm_client,
            prompt_template=self.cot_prompt,
            result_parser=self.result_parser,
            concurrency=max(concurrency - 2, 1),  # CoT 更重，减少并发
        )

        logger.info(
            f"TwoStagePipeline 初始化: provider={provider}, "
            f"concurrency={concurrency}, threshold={confidence_threshold}"
        )

    def run(
        self,
        category: str | None = None,
        max_samples: int | None = None,
    ) -> dict:
        """
        执行两段式检测。

        流程：
        1. 加载样本
        2. Stage1: Few-shot 并发检测全部样本
        3. Stage2: 对 confidence < 阈值的样本用 CoT 复核
        4. 融合结果，计算指标，导出

        Args:
            category: 按类别筛选
            max_samples: 最大样本数

        Returns:
            包含 run_dir 和统计信息的字典
        """
        pipeline_start = time.time()

        # ---- 1. 加载样本 ----
        samples = self.sample_loader.load_samples(category=category)
        if max_samples and max_samples > 0:
            samples = self._balanced_sample(samples, max_samples)
            logger.info(f"限制为 {max_samples} 条平衡采样")

        total = len(samples)
        if total == 0:
            logger.warning("没有匹配的样本")
            return {}

        logger.info(f"两段式管道启动: {total} 条样本")

        # ---- 2. Stage1: Few-shot 并发检测 ----
        logger.info("=" * 50)
        logger.info("Stage 1: Few-shot 并发检测")
        logger.info("=" * 50)

        stage1_start = time.time()
        stage1_results = self.fs_detector.detect_batch(
            samples=samples,
            strategy="few_shot",
            provider=self.provider,
            cache=self.cache if self.use_cache else None,
            progress_label="[Stage1] ",
        )
        stage1_time = time.time() - stage1_start

        # Stage1 结束后保存缓存（仅缓存启用时）
        if self.use_cache and self.cache:
            self.cache.save_to_disk()

        # 统计 Stage1 结果
        s1_correct = sum(1 for r in stage1_results if r.get("correct") == 1)
        s1_total = len(stage1_results)
        s1_accuracy = s1_correct / s1_total if s1_total > 0 else 0

        logger.info(
            f"Stage1 完成: {s1_total} 条, 耗时 {stage1_time:.1f}s, "
            f"准确率 {s1_accuracy*100:.1f}%"
        )

        # ---- 3. Stage2: CoT 复核低置信度样本 ----
        logger.info("=" * 50)
        logger.info("Stage 2: CoT 复核低置信度样本")
        logger.info("=" * 50)

        # 筛选需要复核的样本
        review_indices = []
        review_samples = []
        for i, result in enumerate(stage1_results):
            conf = result.get("pred_confidence", 0.0)
            if conf < self.confidence_threshold:
                review_indices.append(i)
                # 找到对应的原始样本
                if i < len(samples):
                    review_samples.append(samples[i])

        logger.info(
            f"需复核: {len(review_samples)} 条 "
            f"(confidence < {self.confidence_threshold})"
        )

        stage2_time = 0.0
        cot_corrections = 0
        if review_samples:
            stage2_start = time.time()
            stage2_results = self.cot_detector.detect_batch(
                samples=review_samples,
                strategy="cot",
                provider=self.provider,
                cache=self.cache if self.use_cache else None,
                progress_label="[Stage2] ",
            )
            stage2_time = time.time() - stage2_start

            # 融合 Stage2 结果
            for idx_in_review, stage2_result in enumerate(stage2_results):
                original_idx = review_indices[idx_in_review]
                old_label = stage1_results[original_idx]["pred_label"]
                new_label = stage2_result["pred_label"]

                # 标记 Stage2 复核
                stage2_result["reviewed_by_cot"] = True
                stage2_result["stage1_label"] = old_label
                stage2_result["stage1_confidence"] = stage1_results[original_idx].get("pred_confidence", 0.0)

                if old_label != new_label:
                    cot_corrections += 1
                    logger.info(
                        f"  CoT 纠正: {stage2_result['filename']} "
                        f"{old_label} → {new_label}"
                    )

                # 用 Stage2 结果替换 Stage1 结果
                stage1_results[original_idx] = stage2_result

        # ---- 4. 计算指标 ----
        predictions = []
        true_labels = []
        for r in stage1_results:
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

        pipeline_time = time.time() - pipeline_start

        logger.info("=" * 50)
        logger.info("两段式管道完成")
        logger.info("=" * 50)
        _cache_hits = self.cache.hits if (self.use_cache and self.cache) else 0
        logger.info(
            f"总耗时: {pipeline_time:.1f}s ({pipeline_time/60:.1f}分钟)\n"
            f"  Stage1 (Few-shot 并发): {stage1_time:.1f}s\n"
            f"  Stage2 (CoT 复核): {stage2_time:.1f}s\n"
            f"  准确率: {metrics['accuracy']*100:.1f}%\n"
            f"  F1: {metrics['f1']:.4f}\n"
            f"  CoT 纠正: {cot_corrections} 条\n"
            f"  缓存命中: {_cache_hits} 条"
        )

        # ---- 5. 导出 ----
        # 最终保存缓存（仅缓存启用时）
        if self.use_cache and self.cache:
            self.cache.save_to_disk()

        # 添加管道统计信息到 metrics
        cache_stats = self.cache.stats() if (self.use_cache and self.cache) else {
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_hit_rate": 0.0,
            "cache_size": 0,
        }
        metrics["pipeline"] = {
            "total_time_s": round(pipeline_time, 1),
            "stage1_time_s": round(stage1_time, 1),
            "stage2_time_s": round(stage2_time, 1),
            "stage1_samples": s1_total,
            "stage2_reviewed": len(review_samples),
            "cot_corrections": cot_corrections,
            "concurrency": self.concurrency,
            "confidence_threshold": self.confidence_threshold,
            "cache_stats": cache_stats,
            "cache_enabled": self.use_cache,
        }

        experiment_name = f"E_two_stage_{self.provider}"
        if category:
            experiment_name += f"_{category}"

        run_dir = self.exporter.export_results(
            results=stage1_results,
            experiment_name=experiment_name,
            metrics=metrics,
        )

        return {
            "run_dir": run_dir,
            "metrics": metrics,
            "total_time_s": pipeline_time,
            "stage1_time_s": stage1_time,
            "stage2_time_s": stage2_time,
            "stage1_samples": s1_total,
            "stage2_reviewed": len(review_samples),
            "cot_corrections": cot_corrections,
            "cache_stats": cache_stats,
        }

    @staticmethod
    def _balanced_sample(samples: list[Sample], max_n: int) -> list[Sample]:
        """按类别均衡采样，确保各类别都有代表性。"""
        by_category: dict[str, list[Sample]] = {}
        for s in samples:
            by_category.setdefault(s.category, []).append(s)

        # 按类别比例分配
        total = len(samples)
        result = []
        for cat, cat_samples in by_category.items():
            n = max(1, round(len(cat_samples) / total * max_n))
            n = min(n, len(cat_samples))
            result.extend(cat_samples[:n])

        return result[:max_n]


# ================================================================
# 命令行入口
# ================================================================

def main():
    parser = argparse.ArgumentParser(
        description="优化检测管道 - 并发+缓存+两段式"
    )
    parser.add_argument(
        "--provider", choices=["deepseek", "qwen"],
        default="deepseek", help="API 提供商"
    )
    parser.add_argument(
        "--concurrency", type=int, default=5,
        help="最大并发数（默认 5）"
    )
    parser.add_argument(
        "--confidence-threshold", type=float, default=0.9,
        help="Stage2 CoT 复核的置信度阈值（默认 0.9）"
    )
    parser.add_argument(
        "--category", choices=["benign", "webshell", "obfuscated", "sqli"],
        default=None, help="按类别筛选样本"
    )
    parser.add_argument(
        "--max-samples", type=int, default=None,
        help="最大样本数（调试用）"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="日志级别"
    )
    parser.add_argument(
        "--no-cache", action="store_true", default=False,
        help="禁用缓存，确保实验独立性（所有样本通过 API 实时检测）"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    pipeline = TwoStagePipeline(
        provider=args.provider,
        concurrency=args.concurrency,
        confidence_threshold=args.confidence_threshold,
        use_cache=not args.no_cache,
    )

    result = pipeline.run(
        category=args.category,
        max_samples=args.max_samples,
    )

    if result:
        print(f"\n{'='*50}")
        print(f"优化管道完成")
        print(f"{'='*50}")
        print(f"  结果目录: {result['run_dir']}")
        print(f"  总耗时:   {result['total_time_s']:.1f}s ({result['total_time_s']/60:.1f}分钟)")
        print(f"  Stage1:  {result['stage1_time_s']:.1f}s ({result['stage1_samples']} 条)")
        print(f"  Stage2:  {result['stage2_time_s']:.1f}s ({result['stage2_reviewed']} 条复核)")
        print(f"  CoT纠正: {result['cot_corrections']} 条")
        print(f"  缓存命中: {result['cache_stats']['cache_hits']} 条")
        m = result["metrics"]
        print(f"  准确率:  {m['accuracy']*100:.1f}%")
        print(f"  F1:      {m['f1']:.4f}")


if __name__ == "__main__":
    main()
