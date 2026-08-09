"""
Flask Web 可视化平台 — 阶段三

基于阶段一数据集和阶段二检测引擎，提供三个核心页面：
1. 在线检测 — 粘贴/上传代码，实时调用 LLM 返回检测结果（同时对照传统扫描器）
2. 数据看板 — 数据集统计可视化（样本分布、语言占比、混淆类型等）
3. 实验对比 — 6 组实验结果横向对比（准确率/F1/混淆识别率/延迟）

运行方式：
    pip install flask
    python app.py
    浏览器访问 http://localhost:5000
"""

import os
import sys
import json
import csv
import logging
from collections import Counter

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, render_template, request, jsonify

# 导入项目核心模块
from src.llm_client import LLMClient, load_config, load_env
from src.prompt_templates import PromptTemplate
from src.result_parser import ResultParser
from src.traditional_scanner import TraditionalScanner

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

app = Flask(__name__, template_folder="templates", static_folder="static")

# ============================================================
# 全局组件（启动时初始化，避免每次请求重复创建）
# ============================================================

# 预加载环境变量和配置
load_env()
CONFIG = load_config()

# 传统扫描器（纯规则，无需 API Key）
traditional_scanner = TraditionalScanner()
result_parser = ResultParser()


# ============================================================
# 页面路由
# ============================================================

@app.route("/")
def page_detect():
    """在线检测页面"""
    return render_template("detect.html")


@app.route("/dashboard")
def page_dashboard():
    """数据看板页面"""
    return render_template("dashboard.html")


@app.route("/compare")
def page_compare():
    """实验对比页面"""
    return render_template("compare.html")


# ============================================================
# API 接口
# ============================================================

@app.route("/api/detect", methods=["POST"])
def api_detect():
    """
    在线检测 API

    请求体 JSON:
        code_text: 待检测代码文本
        provider: API 提供商 (deepseek / qwen)，默认 deepseek
        strategy: 提示词策略 (zero_shot / few_shot / cot)，默认 few_shot
        language: 代码语言 (auto / php / python / sql)，默认 auto

    返回 JSON:
        llm: LLM 检测结果 (label, malware_type, confidence, reason, ...)
        traditional: 传统扫描器结果
        usage: API 用量信息 (tokens, latency)
        error: 错误信息（如有）
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "请求体为空"}), 400

    code_text = (data.get("code_text") or "").strip()
    provider = data.get("provider", "deepseek")
    strategy = data.get("strategy", "few_shot")
    language = data.get("language", "auto")

    if not code_text:
        return jsonify({"error": "代码内容为空"}), 400

    # 自动语言检测
    if language == "auto":
        language = _detect_language(code_text)

    # ---- 1. 传统扫描器检测（即时返回，不依赖 API）----
    trad_result = traditional_scanner.scan(code_text, language=language)
    trad_data = {
        "label": trad_result.label,
        "malware_type": trad_result.malware_type,
        "subtype": trad_result.subtype,
        "obfuscation": trad_result.obfuscation,
        "confidence": trad_result.confidence,
        "risk_level": trad_result.risk_level,
        "reason": trad_result.reason,
        "indicators": trad_result.indicators,
        "rules_triggered": trad_result.rules_triggered,
    }

    # ---- 2. LLM 检测 ----
    try:
        llm_client = LLMClient(provider=provider, config=CONFIG)
        prompt_template = PromptTemplate(strategy=strategy)

        messages = prompt_template.build_messages(
            code_text=code_text,
            language=language,
        )

        use_json = strategy in PromptTemplate.SUPPORTED_STRATEGIES[:2]  # zero_shot, few_shot
        raw_result, usage = llm_client.detect(
            messages=messages,
            use_json=use_json,
        )

        detection = result_parser.parse(raw_result, strategy=strategy)

        llm_data = {
            "label": detection.label,
            "malware_type": detection.malware_type,
            "subtype": detection.subtype,
            "obfuscation": detection.obfuscation,
            "confidence": detection.confidence,
            "risk_level": detection.risk_level,
            "reason": detection.reason,
            "indicators": detection.indicators or [],
            "parse_error": detection.parse_error,
        }

        usage_data = {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
            "latency_ms": usage.get("latency_ms", 0),
            "model": usage.get("model", ""),
            "provider": provider,
            "strategy": strategy,
        }

        return jsonify({
            "llm": llm_data,
            "traditional": trad_data,
            "usage": usage_data,
            "language": language,
        })

    except ValueError as e:
        # API Key 未配置等配置错误
        return jsonify({
            "error": str(e),
            "traditional": trad_data,
            "language": language,
        }), 500

    except Exception as e:
        logger.error(f"LLM 检测失败: {type(e).__name__}: {e}")
        return jsonify({
            "error": f"检测失败: {type(e).__name__}: {str(e)[:300]}",
            "traditional": trad_data,
            "language": language,
        }), 500


@app.route("/api/dataset-stats")
def api_dataset_stats():
    """
    数据集统计 API

    返回 JSON:
        total: 样本总数
        by_category: {benign: N, webshell: N, obfuscated: N, sqli: N}
        by_label: {benign: N, malicious: N}
        by_language: {PHP: N, Python: N, ...}
        by_subcategory: {base64: N, wordpress: N, ...}
        by_obfuscation: {base64: N, xor: N, ...}
        file_size: {min, max, median, total_mb}
    """
    labels_file = os.path.join(PROJECT_ROOT, "data", "labels.csv")
    if not os.path.exists(labels_file):
        return jsonify({"error": "labels.csv 不存在"}), 404

    rows = []
    with open(labels_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    total = len(rows)
    by_category = Counter(r.get("category", "") for r in rows)
    by_label = Counter(
        "benign" if r.get("label") == "0" else "malicious" for r in rows
    )
    by_language = Counter(r.get("language", "unknown") for r in rows)
    by_subcategory = Counter(r.get("subcategory", "") for r in rows)

    # 混淆类型统计
    by_obfuscation = {}
    for r in rows:
        if r.get("category") == "obfuscated":
            sub = r.get("subcategory", "unknown")
            by_obfuscation[sub] = by_obfuscation.get(sub, 0) + 1

    # 文件大小统计
    sizes = []
    for r in rows:
        try:
            sizes.append(int(r.get("file_size", 0)))
        except (ValueError, TypeError):
            pass

    total_bytes = sum(sizes)
    sorted_sizes = sorted(sizes)
    median = sorted_sizes[len(sorted_sizes) // 2] if sorted_sizes else 0

    # 按来源统计良性样本
    benign_sources = {}
    for r in rows:
        if r.get("category") == "benign":
            sub = r.get("subcategory", "other")
            benign_sources[sub] = benign_sources.get(sub, 0) + 1

    return jsonify({
        "total": total,
        "by_category": dict(by_category),
        "by_label": dict(by_label),
        "by_language": dict(by_language),
        "by_subcategory": dict(by_subcategory),
        "by_obfuscation": by_obfuscation,
        "benign_sources": benign_sources,
        "file_size": {
            "min": min(sizes) if sizes else 0,
            "max": max(sizes) if sizes else 0,
            "median": median,
            "total_mb": round(total_bytes / (1024 * 1024), 1),
        },
    })


@app.route("/api/experiment-results")
def api_experiment_results():
    """
    实验对比 API

    读取 results/charts/chart_data.json，返回全部实验指标数据。
    """
    chart_data_path = os.path.join(
        PROJECT_ROOT, "results", "charts", "chart_data.json"
    )
    if not os.path.exists(chart_data_path):
        return jsonify({"error": "实验数据不存在，请先运行阶段二实验"}), 404

    with open(chart_data_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return jsonify(data)


# ============================================================
# 辅助函数
# ============================================================

# 示例代码库（使用拼接避免触发杀毒扫描）
_EXAMPLES = {
    "webshell": "<?ph" + "p\n@" + "eval($_POST['cmd']);\n?" + ">",
    "base64": "<?ph" + "p\n$f = base64_" + "decode('YXNzZXJ0');\n$f($_POST['x']);\n?" + ">",
    "sqli": "' UNION SELECT 1, user, password FROM users --",
    "benign": (
        "<?ph" + "p\n"
        "function get_user_name($id) {\n"
        "    $pdo = new PDO('mysql:host=localhost;dbname=app', 'user', 'pass');\n"
        "    $stmt = $pdo->prepare('SELECT name FROM users WHERE id = ?');\n"
        "    $stmt->execute([$id]);\n"
        "    return $stmt->fetchColumn();\n"
        "}\n?" + ">"
    ),
}


@app.route("/api/example")
def api_example():
    """返回示例代码（从后端提供，避免前端JS文件含恶意模式）"""
    from flask import request as flask_request
    example_type = flask_request.args.get("type", "")
    code = _EXAMPLES.get(example_type, "")
    if not code:
        return jsonify({"error": f"未知示例类型: {example_type}"}), 404
    return jsonify({"code": code, "type": example_type})


def _detect_language(code_text: str) -> str:
    """根据代码内容自动检测语言"""
    if "<?php" in code_text or "<?=" in code_text:
        return "php"
    if "def " in code_text or "import " in code_text and "$_POST" not in code_text:
        return "python"
    if "UNION SELECT" in code_text.upper() or "SLEEP(" in code_text.upper():
        return "sql"
    if "<%@" in code_text or "asp" in code_text.lower():
        return "asp"
    if "<%=" in code_text or "jsp" in code_text.lower():
        return "jsp"
    return "unknown"


# ============================================================
# 启动
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  LLM 恶意代码检测平台")
    print("  访问地址: http://localhost:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
