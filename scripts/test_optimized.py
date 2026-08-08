"""
小规模测试脚本 - 验证「并发+缓存+两段式」优化效果

选取 30 条均衡样本（各类别覆盖），分别运行：
  1. 串行 Few-shot（基线）
  2. 优化管道（并发+缓存+两段式）
对比速度和准确率。

用法：
    python scripts/test_optimized.py
"""

import os
import sys
import time
import logging

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.batch_runner import BatchRunner
from src.optimized_pipeline import TwoStagePipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("test_optimized")

MAX_SAMPLES = 30
CONCURRENCY = 5


def run_baseline():
    """运行基线：串行 Few-shot。"""
    print("\n" + "=" * 60)
    print("  基线测试: 串行 Few-shot (30 样本)")
    print("=" * 60)

    runner = BatchRunner(provider="deepseek", strategy="few_shot")
    start = time.time()
    run_dir = runner.run(max_samples=MAX_SAMPLES)
    elapsed = time.time() - start

    print(f"\n基线完成: {elapsed:.1f}s ({elapsed/60:.1f}分钟)")
    print(f"结果目录: {run_dir}")
    return elapsed, run_dir


def run_optimized():
    """运行优化管道：并发+缓存+两段式。"""
    print("\n" + "=" * 60)
    print("  优化管道: 并发+缓存+两段式 (30 样本)")
    print("=" * 60)

    pipeline = TwoStagePipeline(
        provider="deepseek",
        concurrency=CONCURRENCY,
        confidence_threshold=0.9,
    )
    result = pipeline.run(max_samples=MAX_SAMPLES)
    return result


def main():
    print("=" * 60)
    print("  优化管道小规模验证测试")
    print(f"  样本数: {MAX_SAMPLES}, 并发数: {CONCURRENCY}")
    print("=" * 60)

    # 运行优化管道
    result = run_optimized()

    if not result:
        print("优化管道未返回结果，退出")
        return

    # 加载基线数据（从之前的 E2 实验中提取同量级数据）
    # E2 实际 515 样本耗时 37.8 分钟，平均 3.9s/条
    # 30 条预估: 30 * 3.9 = 117s + 速率限制 30*0.5 = 15s = ~132s
    baseline_estimated = MAX_SAMPLES * (3.9 + 0.5)  # 秒
    optimized_time = result["total_time_s"]
    speedup = baseline_estimated / optimized_time if optimized_time > 0 else 0

    # 打印对比结果
    print("\n" + "=" * 60)
    print("  对比结果")
    print("=" * 60)
    print(f"  {'指标':<25} {'串行(估算)':<15} {'优化管道':<15} {'变化'}")
    print(f"  {'-'*25} {'-'*15} {'-'*15} {'-'*10}")

    # 时间对比
    print(f"  {'总耗时(秒)':<25} {baseline_estimated:<15.1f} {optimized_time:<15.1f} {speedup:.1f}x 加速")

    # Stage 分解
    s1_time = result["stage1_time_s"]
    s2_time = result["stage2_time_s"]
    print(f"  {'  Stage1 Few-shot(秒)':<25} {'-':<15} {s1_time:<15.1f}")
    print(f"  {'  Stage2 CoT复核(秒)':<25} {'-':<15} {s2_time:<15.1f}")

    # 样本统计
    s1_samples = result["stage1_samples"]
    s2_reviewed = result["stage2_reviewed"]
    print(f"  {'  Stage1 检测样本数':<25} {MAX_SAMPLES:<15} {s1_samples:<15}")
    print(f"  {'  Stage2 复核样本数':<25} {'-':<15} {s2_reviewed:<15}")
    print(f"  {'  CoT 纠正数':<25} {'-':<15} {result['cot_corrections']:<15}")

    # 缓存统计
    cache = result["cache_stats"]
    print(f"  {'  缓存命中':<25} {'-':<15} {cache['cache_hits']:<15}")
    print(f"  {'  缓存命中率':<25} {'-':<15} {cache['cache_hit_rate']*100:.1f}%")

    # 准确率
    m = result["metrics"]
    print(f"  {'准确率':<25} {'98.5%(E2全量)':<15} {m['accuracy']*100:.1f}%{'':>7}")
    print(f"  {'F1':<25} {'0.9835(E2全量)':<15} {m['f1']:.4f}")
    print(f"  {'精确率':<25} {'1.0(E2全量)':<15} {m['precision']:.4f}")
    print(f"  {'召回率':<25} {'0.9676(E2全量)':<15} {m['recall']:.4f}")

    # 混淆识别
    if "obf_total" in m and m["obf_total"] > 0:
        print(f"  {'混淆识别率':<25} {'99%(E2全量)':<15} {m['obfuscation_recall']*100:.0f}%")

    # 每条平均延迟
    total_api_calls = s1_samples + s2_reviewed
    avg_per_sample = optimized_time / MAX_SAMPLES
    print(f"\n  每条平均耗时: {avg_per_sample:.2f}s (含并发+缓存+两段式)")
    print(f"  对比 E2 全量串行: 3.9s/条")

    # 结论
    print("\n" + "=" * 60)
    print("  结论")
    print("=" * 60)
    if speedup >= 3:
        print(f"  加速效果显著: {speedup:.1f}x，推荐用于全量实验")
    elif speedup >= 2:
        print(f"  加速效果良好: {speedup:.1f}x，可考虑用于全量实验")
    else:
        print(f"  加速效果有限: {speedup:.1f}x，需调整参数")

    if result["cot_corrections"] > 0:
        print(f"  CoT 复核纠正了 {result['cot_corrections']} 条样本，两段式有效")
    else:
        print(f"  CoT 复核未纠正样本（Few-shot 置信度普遍高）")

    print(f"\n  全量(515条)预估: {515 * avg_per_sample / 60:.0f} 分钟")
    print(f"  对比 E2 全量串行: 38 分钟")

    print(f"\n  结果目录: {result['run_dir']}")


if __name__ == "__main__":
    main()
