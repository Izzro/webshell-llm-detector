"""
批量实验运行脚本

顺序执行 6 组实验（3策略 × 2提供商），每组 515 样本。
每组实验完成后立即导出结果，支持中断后从断点继续。

实验矩阵：
    E1: DeepSeek + zero_shot
    E2: DeepSeek + few_shot
    E3: DeepSeek + cot
    E4: Qwen + zero_shot
    E5: Qwen + few_shot
    E6: Qwen + cot

用法：
    python scripts/run_experiments.py                    # 运行全部
    python scripts/run_experiments.py --only 1 2 3        # 只运行指定编号
    python scripts/run_experiments.py --provider deepseek # 只运行 DeepSeek
"""

import os
import sys
import time
import json
import logging
import argparse
import subprocess
from datetime import datetime

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# 实验配置
EXPERIMENTS = [
    {"id": 1, "provider": "deepseek", "strategy": "zero_shot"},
    {"id": 2, "provider": "deepseek", "strategy": "few_shot"},
    {"id": 3, "provider": "deepseek", "strategy": "cot"},
    {"id": 4, "provider": "qwen", "strategy": "zero_shot"},
    {"id": 5, "provider": "qwen", "strategy": "few_shot"},
    {"id": 6, "provider": "qwen", "strategy": "cot"},
]

# 进度日志文件
PROGRESS_FILE = os.path.join(PROJECT_ROOT, "results", "experiment_progress.json")
LOG_DIR = os.path.join(PROJECT_ROOT, "results", "logs")


def setup_logging(log_file):
    """配置日志输出到文件和控制台。"""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # 文件日志
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # 控制台日志
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    # 清除已有 handlers
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


def load_progress():
    """加载已完成的实验进度。"""
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"completed": [], "current": None, "experiments": {}}


def save_progress(progress):
    """保存实验进度。"""
    os.makedirs(os.path.dirname(PROGRESS_FILE), exist_ok=True)
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump(progress, f, ensure_ascii=False, indent=2)


def run_experiment(exp_config, max_samples=None):
    """
    运行单组实验。

    通过 subprocess 调用 batch_runner CLI，确保进程隔离和日志捕获。
    """
    exp_id = exp_config["id"]
    provider = exp_config["provider"]
    strategy = exp_config["strategy"]

    logger = logging.getLogger(__name__)

    logger.info(f"{'='*60}")
    logger.info(f"实验 E{exp_id}: {provider} + {strategy}")
    logger.info(f"{'='*60}")

    start_time = time.time()
    start_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"开始时间: {start_str}")

    # 构建命令
    cmd = [
        sys.executable, "-m", "src.batch_runner",
        "--strategy", strategy,
        "--provider", provider,
        "--log-level", "INFO",
    ]
    if max_samples:
        cmd.extend(["--max-samples", str(max_samples)])

    logger.info(f"执行命令: {' '.join(cmd)}")

    # 运行实验（实时输出日志）
    try:
        result = subprocess.run(
            cmd,
            cwd=PROJECT_ROOT,
            capture_output=False,
            text=True,
            timeout=14400,  # 4 小时超时
        )

        elapsed = time.time() - start_time
        elapsed_min = elapsed / 60

        end_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if result.returncode == 0:
            logger.info(f"实验 E{exp_id} 完成！耗时 {elapsed_min:.1f} 分钟")
            logger.info(f"结束时间: {end_str}")
            return {
                "status": "completed",
                "start": start_str,
                "end": end_str,
                "elapsed_minutes": round(elapsed_min, 1),
            }
        else:
            logger.error(f"实验 E{exp_id} 失败 (exit code {result.returncode})")
            logger.error(f"耗时 {elapsed_min:.1f} 分钟")
            return {
                "status": "failed",
                "start": start_str,
                "end": end_str,
                "elapsed_minutes": round(elapsed_min, 1),
                "exit_code": result.returncode,
            }

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        logger.error(f"实验 E{exp_id} 超时（4小时限制）")
        return {
            "status": "timeout",
            "start": start_str,
            "end": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_minutes": round(elapsed / 60, 1),
        }
    except Exception as e:
        logger.error(f"实验 E{exp_id} 异常: {type(e).__name__}: {e}")
        return {
            "status": "error",
            "error": str(e),
            "start": start_str,
            "end": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }


def main():
    parser = argparse.ArgumentParser(description="批量实验运行")
    parser.add_argument(
        "--only", nargs="+", type=int,
        help="只运行指定编号的实验（如 --only 1 2 3）"
    )
    parser.add_argument(
        "--provider", choices=["deepseek", "qwen"],
        help="只运行指定提供商的实验"
    )
    parser.add_argument(
        "--max-samples", type=int, default=None,
        help="每组实验最大样本数（调试用）"
    )
    args = parser.parse_args()

    # 过滤要运行的实验
    experiments = EXPERIMENTS
    if args.only:
        experiments = [e for e in EXPERIMENTS if e["id"] in args.only]
    if args.provider:
        experiments = [e for e in experiments if e["provider"] == args.provider]

    if not experiments:
        print("没有匹配的实验")
        return

    # 设置日志
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(LOG_DIR, f"experiments_{timestamp}.log")
    setup_logging(log_file)

    logger = logging.getLogger(__name__)
    logger.info(f"批量实验启动，共 {len(experiments)} 组")
    logger.info(f"实验列表: {[e['id'] for e in experiments]}")
    logger.info(f"日志文件: {log_file}")

    # 加载进度
    progress = load_progress()
    total_start = time.time()

    # 顺序执行实验
    for exp in experiments:
        exp_id = exp["id"]

        # 跳过已完成的
        if str(exp_id) in progress.get("completed", []):
            logger.info(f"实验 E{exp_id} 已完成，跳过")
            continue

        # 运行实验
        result = run_experiment(exp, max_samples=args.max_samples)

        # 记录进度
        progress["experiments"][str(exp_id)] = {
            "provider": exp["provider"],
            "strategy": exp["strategy"],
            **result,
        }
        if result["status"] == "completed":
            if "completed" not in progress:
                progress["completed"] = []
            progress["completed"].append(str(exp_id))

        save_progress(progress)

        # 实验间间隔
        if exp != experiments[-1]:
            logger.info("实验间间隔 10 秒...")
            time.sleep(10)

    # 汇总
    total_elapsed = (time.time() - total_start) / 60
    completed_count = len([e for e in progress["experiments"].values()
                          if e.get("status") == "completed"])
    failed_count = len([e for e in progress["experiments"].values()
                       if e.get("status") != "completed"])

    logger.info(f"{'='*60}")
    logger.info(f"批量实验完成")
    logger.info(f"  成功: {completed_count} 组")
    logger.info(f"  失败: {failed_count} 组")
    logger.info(f"  总耗时: {total_elapsed:.1f} 分钟")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    main()
