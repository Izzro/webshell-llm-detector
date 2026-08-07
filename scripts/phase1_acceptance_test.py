"""
阶段一验收测试脚本

执行 5 项验收检查：
  1. API 连通性验证（DeepSeek + 通义千问）
  2. 数据集完整性检查（labels.csv 与实际文件一致性）
  3. 混淆变种质量检查（抽样验证混淆效果）
  4. 端到端流程测试（样本加载 -> LLM API 调用 -> JSON 结果解析）
  5. 生成验收报告

使用方式：
    python scripts/phase1_acceptance_test.py
    python scripts/phase1_acceptance_test.py --skip-api  # 跳过 API 测试（节省 Token）
"""

import os
import sys
import csv
import json
import time
import random
import logging
from pathlib import Path
from collections import Counter

# 将项目根目录加入 sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="  %(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# 路径常量
SAMPLES_DIR = os.path.join(project_root, "data", "samples")
LABELS_PATH = os.path.join(project_root, "data", "labels.csv")
BENIGN_DIR = os.path.join(SAMPLES_DIR, "benign")
WEBSHELL_DIR = os.path.join(SAMPLES_DIR, "webshell")
SQLI_DIR = os.path.join(SAMPLES_DIR, "sqli")
OBFUSCATED_DIR = os.path.join(SAMPLES_DIR, "obfuscated")


class TestResult:
    """单项测试结果"""
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.details = []
        self.errors = []
        self.warnings = []

    def add_detail(self, msg: str):
        self.details.append(msg)

    def add_error(self, msg: str):
        self.errors.append(msg)

    def add_warning(self, msg: str):
        self.warnings.append(msg)

    def pass_test(self):
        self.passed = True

    def __str__(self):
        status = "[PASS]" if self.passed else "[FAIL]"
        lines = [f"  {status} {self.name}"]
        for d in self.details:
            lines.append(f"    {d}")
        for w in self.warnings:
            lines.append(f"    [警告] {w}")
        for e in self.errors:
            lines.append(f"    [错误] {e}")
        return "\n".join(lines)


def test_1_api_connectivity(skip_api: bool = False) -> TestResult:
    """验收1: API 连通性验证"""
    result = TestResult("验收1: API 连通性验证")

    if skip_api:
        result.add_detail("已跳过（--skip-api）")
        result.pass_test()
        return result

    # 检查环境变量
    from src.llm_client import load_env, load_config, LLMClient

    load_env()

    deepseek_key = os.environ.get("DEEPSEEK_API_KEY")
    qwen_key = os.environ.get("DASHSCOPE_API_KEY")

    if not deepseek_key:
        result.add_error("DEEPSEEK_API_KEY 未设置")
    else:
        result.add_detail(f"DEEPSEEK_API_KEY: {deepseek_key[:4]}***{deepseek_key[-4:]}")

    if not qwen_key:
        result.add_error("DASHSCOPE_API_KEY 未设置")
    else:
        result.add_detail(f"DASHSCOPE_API_KEY: {qwen_key[:4]}***{qwen_key[-4:]}")

    if not deepseek_key or not qwen_key:
        return result

    # 测试 DeepSeek
    try:
        config = load_config()
        client = LLMClient(provider="deepseek", config=config)
        success, msg = client.verify_connection()
        if success:
            result.add_detail(f"DeepSeek: {msg}")
        else:
            result.add_error(f"DeepSeek 连接失败: {msg}")
    except Exception as e:
        result.add_error(f"DeepSeek 异常: {type(e).__name__}: {e}")

    # 测试通义千问
    try:
        client = LLMClient(provider="qwen", config=config)
        success, msg = client.verify_connection()
        if success:
            result.add_detail(f"通义千问: {msg}")
        else:
            result.add_error(f"通义千问 连接失败: {msg}")
    except Exception as e:
        result.add_error(f"通义千问 异常: {type(e).__name__}: {e}")

    if not result.errors:
        result.pass_test()
    return result


def test_2_dataset_integrity() -> TestResult:
    """验收2: 数据集完整性检查"""
    result = TestResult("验收2: 数据集完整性检查")

    # 检查 labels.csv 存在
    if not os.path.exists(LABELS_PATH):
        result.add_error(f"labels.csv 不存在: {LABELS_PATH}")
        return result

    # 加载 labels.csv
    with open(LABELS_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    result.add_detail(f"labels.csv 记录数: {len(records)}")

    # 检查每条记录的文件是否存在
    missing_files = 0
    for record in records:
        file_path = os.path.join(project_root, record["file_path"])
        if not os.path.exists(file_path):
            missing_files += 1
            if missing_files <= 5:
                result.add_error(f"文件缺失: {record['file_path']}")

    if missing_files > 0:
        result.add_error(f"共 {missing_files} 个文件缺失")
    else:
        result.add_detail("所有 labels.csv 中引用的文件均存在")

    # 反向检查：实际文件数 vs labels.csv 记录数
    actual_files = set()
    expected_dirs = [
        ("benign", BENIGN_DIR),
        ("webshell", WEBSHELL_DIR),
        ("sqli", SQLI_DIR),
    ]
    for tech in ["base64", "comment_bypass", "string_split", "xor"]:
        expected_dirs.append((f"obfuscated/{tech}", os.path.join(OBFUSCATED_DIR, tech)))

    for label, dir_path in expected_dirs:
        if os.path.exists(dir_path):
            for fname in os.listdir(dir_path):
                if os.path.isfile(os.path.join(dir_path, fname)) and not fname.startswith("."):
                    actual_files.add(os.path.relpath(os.path.join(dir_path, fname), project_root))

    labeled_files = set(r["file_path"] for r in records)

    unlabeled = actual_files - labeled_files
    phantom = labeled_files - actual_files

    if unlabeled:
        result.add_warning(f"{len(unlabeled)} 个实际文件未在 labels.csv 中（可能新增）")
        for f in list(unlabeled)[:3]:
            result.add_warning(f"  {f}")

    if phantom:
        result.add_error(f"{len(phantom)} 个 labels.csv 记录无对应文件")

    # 检查标签分布
    benign_count = sum(1 for r in records if int(r["label"]) == 0)
    malicious_count = sum(1 for r in records if int(r["label"]) == 1)
    result.add_detail(f"良性样本: {benign_count}, 恶意样本: {malicious_count}")

    # 检查比例
    if benign_count == 0 or malicious_count == 0:
        result.add_error("良性或恶意样本为 0，数据集不完整")
    else:
        ratio = min(benign_count, malicious_count) / max(benign_count, malicious_count)
        result.add_detail(f"良性/恶意比例: {benign_count}:{malicious_count} (均衡度: {ratio:.2f})")
        if ratio < 0.3:
            result.add_warning("样本比例严重不均衡")

    # 检查类别覆盖
    categories = Counter(r["category"] for r in records)
    for cat in ["benign", "webshell", "sqli", "obfuscated"]:
        if cat not in categories:
            result.add_error(f"缺少类别: {cat}")
        else:
            result.add_detail(f"类别 {cat}: {categories[cat]} 个")

    if not result.errors:
        result.pass_test()
    return result


def test_3_obfuscation_quality() -> TestResult:
    """验收3: 混淆变种质量检查"""
    result = TestResult("验收3: 混淆变种质量检查")

    techniques = ["base64", "comment_bypass", "string_split", "xor"]

    for tech in techniques:
        tech_dir = os.path.join(OBFUSCATED_DIR, tech)
        if not os.path.exists(tech_dir):
            result.add_error(f"混淆目录不存在: {tech}")
            continue

        files = [f for f in os.listdir(tech_dir) if not f.startswith(".") and os.path.isfile(os.path.join(tech_dir, f))]
        if not files:
            result.add_error(f"{tech}: 无混淆文件")
            continue

        # 抽样检查 3 个文件
        random.seed(42)
        samples = random.sample(files, min(3, len(files)))

        tech_ok = True
        for fname in samples:
            fpath = os.path.join(tech_dir, fname)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if not content.strip():
                result.add_error(f"{tech}/{fname}: 文件为空")
                tech_ok = False
                continue

            # 检查混淆特征
            if tech == "base64":
                if "base64_decode" not in content and "base64.b64decode" not in content:
                    result.add_error(f"{tech}/{fname}: 缺少 base64 解码特征")
                    tech_ok = False
            elif tech == "comment_bypass":
                if "/**/" not in content and '""+' not in content:
                    result.add_warning(f"{tech}/{fname}: 未检测到注释绕过特征（可能原始样本无目标函数）")
            elif tech == "string_split":
                if "'.'" not in content and '"+"' not in content:
                    result.add_warning(f"{tech}/{fname}: 未检测到字符串分割特征（可能原始样本无目标函数）")
            elif tech == "xor":
                if "eval" not in content and "exec" not in content:
                    result.add_error(f"{tech}/{fname}: 缺少 eval/exec 执行特征")
                    tech_ok = False

        if tech_ok:
            result.add_detail(f"{tech}: {len(files)} 个文件，抽样检查通过")

    if not result.errors:
        result.pass_test()
    return result


def test_4_end_to_end(skip_api: bool = False) -> TestResult:
    """验收4: 端到端流程测试"""
    result = TestResult("验收4: 端到端流程测试")

    # 步骤 1: 从 labels.csv 加载样本
    if not os.path.exists(LABELS_PATH):
        result.add_error("labels.csv 不存在")
        return result

    with open(LABELS_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    result.add_detail(f"步骤1 - 加载 {len(records)} 条样本记录")

    # 随机选取 1 个良性 + 1 个恶意样本
    random.seed(42)
    benign_records = [r for r in records if int(r["label"]) == 0 and r["language"] in ("PHP", "Python")]
    malicious_records = [r for r in records if int(r["label"]) == 1 and r["language"] in ("PHP", "Python")]

    if not benign_records or not malicious_records:
        result.add_error("无法选取测试样本")
        return result

    benign_sample = random.choice(benign_records)
    malicious_sample = random.choice(malicious_records)

    result.add_detail(f"步骤2 - 选取测试样本:")
    result.add_detail(f"  良性: {benign_sample['filename']} ({benign_sample['subcategory']})")
    result.add_detail(f"  恶意: {malicious_sample['filename']} ({malicious_sample['subcategory']})")

    # 读取样本内容
    benign_path = os.path.join(project_root, benign_sample["file_path"])
    malicious_path = os.path.join(project_root, malicious_sample["file_path"])

    with open(benign_path, "r", encoding="utf-8", errors="ignore") as f:
        benign_code = f.read()
    with open(malicious_path, "r", encoding="utf-8", errors="ignore") as f:
        malicious_code = f.read()

    result.add_detail(f"  良性代码长度: {len(benign_code)} 字符")
    result.add_detail(f"  恶意代码长度: {len(malicious_code)} 字符")

    # 步骤 3: 截取前 2000 字符构造提示词
    max_chars = 2000
    benign_excerpt = benign_code[:max_chars]
    malicious_excerpt = malicious_code[:max_chars]

    # 构造检测提示词（简化版，用于验收）
    system_prompt = (
        "你是一个网络安全专家，请分析给定的代码片段是否为恶意代码。"
        "请以 JSON 格式返回结果，包含以下字段："
        '{"is_malicious": true/false, "confidence": 0.0-1.0, "reason": "简要说明"}'
    )

    result.add_detail(f"步骤3 - 构造提示词（system + user）")

    if skip_api:
        result.add_detail("步骤4 - 已跳过 API 调用（--skip-api）")
        result.pass_test()
        return result

    # 步骤 4: 调用 DeepSeek API
    from src.llm_client import load_env, load_config, LLMClient

    load_env()
    config = load_config()

    try:
        client = LLMClient(provider="deepseek", config=config)

        # 测试良性样本
        benign_messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"请分析以下代码：\n\n```\n{benign_excerpt}\n```"},
        ]
        benign_result, benign_usage = client.detect(benign_messages, use_json=True)
        result.add_detail(
            f"步骤4 - 良性样本检测结果: "
            f"is_malicious={benign_result.get('is_malicious')}, "
            f"confidence={benign_result.get('confidence')}, "
            f"tokens={benign_usage['total_tokens']}, "
            f"latency={benign_usage['latency_ms']}ms"
        )

        # 检查良性样本是否被正确识别为非恶意
        if benign_result.get("is_malicious") == False:
            result.add_detail("  [正确] 良性样本被识别为非恶意")
        else:
            result.add_warning(f"  [误报] 良性样本被识别为恶意: {benign_result.get('reason', '')}")

    except Exception as e:
        result.add_error(f"良性样本 API 调用失败: {type(e).__name__}: {e}")
        return result

    # 测试恶意样本
    try:
        malicious_messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"请分析以下代码：\n\n```\n{malicious_excerpt}\n```"},
        ]
        malicious_result, malicious_usage = client.detect(malicious_messages, use_json=True)
        result.add_detail(
            f"步骤5 - 恶意样本检测结果: "
            f"is_malicious={malicious_result.get('is_malicious')}, "
            f"confidence={malicious_result.get('confidence')}, "
            f"tokens={malicious_usage['total_tokens']}, "
            f"latency={malicious_usage['latency_ms']}ms"
        )

        # 检查恶意样本是否被正确识别为恶意
        if malicious_result.get("is_malicious") == True:
            result.add_detail("  [正确] 恶意样本被识别为恶意")
        else:
            result.add_warning(f"  [漏报] 恶意样本被识别为非恶意: {malicious_result.get('reason', '')}")

        # 步骤 6: 验证 JSON 结构化输出
        required_fields = ["is_malicious", "confidence", "reason"]
        for field in required_fields:
            if field not in malicious_result:
                result.add_error(f"JSON 输出缺少字段: {field}")
            if field not in benign_result:
                result.add_error(f"JSON 输出缺少字段: {field}")

        if all(f in benign_result and f in malicious_result for f in required_fields):
            result.add_detail("步骤6 - JSON 结构化输出格式验证通过")

    except Exception as e:
        result.add_error(f"恶意样本 API 调用失败: {type(e).__name__}: {e}")
        return result

    if not result.errors:
        result.pass_test()
    return result


def generate_report(results: list[TestResult], skip_api: bool) -> str:
    """生成验收报告"""
    lines = []
    sep = "=" * 60

    lines.append(sep)
    lines.append("  阶段一验收测试报告")
    lines.append(f"  时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  API 测试: {'跳过' if skip_api else '执行'}")
    lines.append(sep)

    passed = sum(1 for r in results if r.passed)
    total = len(results)

    for r in results:
        lines.append("")
        lines.append(str(r))

    lines.append("")
    lines.append(sep)
    lines.append(f"  验收结果: {passed}/{total} 通过")
    lines.append(sep)

    if passed == total:
        lines.append("  [结论] 阶段一验收全部通过，可以进入阶段二")
    else:
        lines.append("  [结论] 部分验收项未通过，请检查上述错误")

    lines.append(sep)

    return "\n".join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="阶段一验收测试")
    parser.add_argument("--skip-api", action="store_true", help="跳过 API 测试（节省 Token）")
    args = parser.parse_args()

    print("=" * 60)
    print("  阶段一验收测试")
    print("=" * 60)

    results = []

    # 验收1: API 连通性
    print("\n[运行] 验收1: API 连通性验证...")
    results.append(test_1_api_connectivity(skip_api=args.skip_api))
    print(results[-1])

    # 验收2: 数据集完整性
    print("\n[运行] 验收2: 数据集完整性检查...")
    results.append(test_2_dataset_integrity())
    print(results[-1])

    # 验收3: 混淆变种质量
    print("\n[运行] 验收3: 混淆变种质量检查...")
    results.append(test_3_obfuscation_quality())
    print(results[-1])

    # 验收4: 端到端流程
    print("\n[运行] 验收4: 端到端流程测试...")
    results.append(test_4_end_to_end(skip_api=args.skip_api))
    print(results[-1])

    # 生成报告
    report = generate_report(results, args.skip_api)
    print("\n" + report)

    # 保存报告
    report_path = os.path.join(project_root, "data", "phase1_acceptance_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n  报告已保存: {report_path}")

    # 返回退出码
    passed = sum(1 for r in results if r.passed)
    if passed == len(results):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
