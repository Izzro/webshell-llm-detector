"""
ResultParser 单元测试

测试要点：
- 正常 JSON 解析（字符串和 dict 输入）
- 带 reasoning 字段的 CoT JSON 解析
- 损坏 JSON 修复（尾逗号、截断）
- 非 JSON 输入处理
- 字段别名兼容和默认值填充
"""

import json
import pytest
from src.result_parser import ResultParser, DetectionResult


@pytest.fixture
def parser():
    """创建解析器实例。"""
    return ResultParser()


# ================================================================
# 正常 JSON 解析
# ================================================================

class TestNormalJsonParsing:
    """测试标准 JSON 输入的解析。"""

    def test_parse_json_string(self, parser):
        """测试 JSON 字符串解析。"""
        raw = json.dumps({
            "label": "malicious",
            "malware_type": "webshell",
            "subtype": "一句话木马",
            "obfuscation": "none",
            "confidence": 0.95,
            "risk_level": "high",
            "reason": "eval 执行用户输入",
            "indicators": ["eval", "$_POST"],
        }, ensure_ascii=False)
        result = parser.parse(raw)

        assert result.label == "malicious"
        assert result.malware_type == "webshell"
        assert result.obfuscation == "none"
        assert result.confidence == 0.95
        assert result.risk_level == "high"
        assert result.reason == "eval 执行用户输入"
        assert "eval" in result.indicators
        assert result.parse_error == ""

    def test_parse_dict_input(self, parser):
        """测试 dict 输入直接解析（use_json=True 模式）。"""
        data = {
            "label": "benign",
            "malware_type": "none",
            "confidence": 0.9,
            "risk_level": "none",
        }
        result = parser.parse(data)

        assert result.label == "benign"
        assert result.malware_type == "none"
        assert result.confidence == 0.9
        assert result.parse_error == ""

    def test_parse_benign_json(self, parser):
        """测试良性判定 JSON。"""
        raw = '{"label": "benign", "malware_type": "none", "confidence": 0.0}'
        result = parser.parse(raw)

        assert result.label == "benign"
        assert result.malware_type == "none"
        assert result.confidence == 0.0

    def test_parse_with_strategy_parameter(self, parser):
        """测试 strategy 参数不影响解析结果。"""
        raw = '{"label": "malicious", "malware_type": "sqli"}'
        for strategy in ("zero_shot", "few_shot", "cot"):
            result = parser.parse(raw, strategy=strategy)
            assert result.label == "malicious"
            assert result.malware_type == "sqli"


# ================================================================
# CoT JSON 解析（带 reasoning 字段）
# ================================================================

class TestCoTJsonParsing:
    """测试 CoT 模式下带 reasoning 字段的 JSON 解析。"""

    def test_parse_cot_json_with_reasoning(self, parser):
        """测试带 reasoning 字段的 JSON：reasoning 应被忽略，结论字段正确解析。"""
        raw = json.dumps({
            "reasoning": "第一步·代码结构概览：PHP代码\\n第二步·敏感函数识别：发现eval\\n第三步·数据流追踪：$_POST直达eval\\n第四步·混淆分析：无混淆\\n第五步·综合判定：恶意",
            "label": "malicious",
            "malware_type": "webshell",
            "subtype": "一句话木马",
            "obfuscation": "none",
            "confidence": 0.99,
            "risk_level": "high",
            "reason": "eval 直接执行用户输入",
            "indicators": ["eval", "$_POST"],
        }, ensure_ascii=False)
        result = parser.parse(raw, strategy="cot")

        assert result.label == "malicious"
        assert result.malware_type == "webshell"
        assert result.confidence == 0.99
        assert result.reason == "eval 直接执行用户输入"
        # DetectionResult 不包含 reasoning 字段，但其他字段应正确
        assert not hasattr(result, "reasoning")

    def test_parse_cot_json_in_code_block(self, parser):
        """测试 CoT 模式：分析文本 + ```json 代码块中的 JSON。"""
        raw = (
            "让我分析这段代码...\n\n"
            "第一步·代码结构概览：这是一段 PHP 代码。\n"
            "第二步·敏感函数识别：发现了 eval 函数。\n"
            "第三步·数据流追踪：$_POST 直达 eval。\n"
            "第四步·混淆分析：未发现混淆。\n"
            "第五步·综合判定：这是一句话木马。\n\n"
            "```json\n"
            '{"label": "malicious", "malware_type": "webshell", '
            '"confidence": 0.95, "risk_level": "high", '
            '"reason": "eval 执行用户输入"}\n'
            "```"
        )
        result = parser.parse(raw, strategy="cot")

        assert result.label == "malicious"
        assert result.malware_type == "webshell"
        assert result.confidence == 0.95
        assert result.parse_error == ""

    def test_parse_cot_json_in_plain_code_block(self, parser):
        """测试 CoT 模式：JSON 在无语言标记的 ``` 代码块中。"""
        raw = (
            "分析过程省略...\n\n"
            "```\n"
            '{"label": "benign", "malware_type": "none", "confidence": 0.8}\n'
            "```"
        )
        result = parser.parse(raw, strategy="cot")

        assert result.label == "benign"
        assert result.confidence == 0.8


# ================================================================
# 损坏 JSON 修复
# ================================================================

class TestCorruptedJsonRepair:
    """测试损坏 JSON 的修复能力。"""

    def test_trailing_comma_repair(self, parser):
        """测试尾逗号修复：{"label": "malicious",} → 去除逗号。"""
        raw = '{"label": "malicious", "malware_type": "webshell",}'
        result = parser.parse(raw)

        assert result.label == "malicious"
        assert result.malware_type == "webshell"
        assert result.parse_error == ""

    def test_trailing_comma_in_nested_array(self, parser):
        """测试数组内尾逗号修复。"""
        raw = '{"label": "malicious", "indicators": ["eval", "system",]}'
        result = parser.parse(raw)

        assert result.label == "malicious"
        assert "eval" in result.indicators
        assert "system" in result.indicators

    def test_truncated_json_in_code_block(self, parser):
        """测试截断 JSON 修复：代码块内 JSON 缺少右括号。"""
        raw = (
            "分析结果如下：\n"
            "```json\n"
            '{"label": "malicious", "confidence": 0.9, "reason": "detected eval"\n'
            "```"
        )
        result = parser.parse(raw)

        # 截断的 JSON（缺少 }）应通过补全右括号修复
        assert result.label == "malicious"
        assert result.confidence == 0.9
        assert result.reason == "detected eval"

    def test_truncated_json_nested(self, parser):
        """测试嵌套 JSON 截断修复：label 在前，内层对象有闭合 }，外层缺少。"""
        # label 字段在内层 } 之前，确保提取后仍包含 label
        raw = '{"label": "malicious", "data": {"x": 1}'
        result = parser.parse(raw)

        # 应通过策略3（first { 到 last }）提取并补全外层 }
        assert result.label == "malicious"

    def test_single_quotes_inside_string_values(self, parser):
        """测试 JSON 字符串值中的单引号（合法 JSON）。"""
        raw = json.dumps({
            "label": "malicious",
            "reason": "it's a webshell",
        }, ensure_ascii=False)
        result = parser.parse(raw)

        assert result.label == "malicious"
        assert "webshell" in result.reason

    def test_python_style_single_quoted_dict(self, parser):
        """测试 Python 风格单引号字典：解析器不支持单引号转双引号修复。"""
        raw = "{'label': 'malicious', 'malware_type': 'webshell'}"
        result = parser.parse(raw)

        # JSON 标准要求双引号，单引号字典无法被 json.loads 解析
        # 解析器不具备单引号→双引号的修复能力，应返回 parse_error
        assert result.label == "unknown"
        assert result.parse_error != ""

    def test_json_with_extra_text(self, parser):
        """测试 JSON 后跟额外文本的提取。"""
        raw = '{"label": "malicious", "confidence": 0.9} 这是额外文本'
        result = parser.parse(raw)

        assert result.label == "malicious"
        assert result.confidence == 0.9

    def test_json_with_extra_prefix_text(self, parser):
        """测试 JSON 前有额外文本的提取。"""
        raw = '根据分析，结论如下：{"label": "benign", "confidence": 0.85}'
        result = parser.parse(raw)

        assert result.label == "benign"
        assert result.confidence == 0.85


# ================================================================
# 非 JSON 输入处理
# ================================================================

class TestNonJsonInput:
    """测试非 JSON 输入的处理。"""

    def test_plain_text(self, parser):
        """测试纯文本输入。"""
        result = parser.parse("This is not JSON at all")

        assert result.label == "unknown"
        assert result.parse_error != ""
        assert "无法" in result.parse_error or "JSON" in result.parse_error

    def test_empty_string(self, parser):
        """测试空字符串输入。"""
        result = parser.parse("")

        assert result.label == "unknown"
        assert result.parse_error != ""

    def test_integer_input(self, parser):
        """测试整数输入。"""
        result = parser.parse(42)

        assert result.label == "unknown"
        assert "不支持" in result.parse_error

    def test_list_input(self, parser):
        """测试列表输入（非 dict）。"""
        raw = json.dumps(["item1", "item2"])
        result = parser.parse(raw)

        # JSON 数组不是 dict，应返回 parse_error
        assert result.parse_error != ""

    def test_none_input(self, parser):
        """测试 None 输入。"""
        result = parser.parse(None)

        assert result.label == "unknown"
        assert result.parse_error != ""


# ================================================================
# 字段别名和默认值
# ================================================================

class TestFieldAliases:
    """测试字段别名兼容和默认值填充。"""

    def test_is_malicious_alias(self, parser):
        """测试 is_malicious 字段别名。"""
        raw = '{"is_malicious": true, "malware_type": "webshell"}'
        result = parser.parse(raw)

        assert result.label == "malicious"

    def test_verdict_alias(self, parser):
        """测试 verdict 字段别名。"""
        raw = '{"verdict": "benign"}'
        result = parser.parse(raw)

        assert result.label == "benign"

    def test_classification_alias(self, parser):
        """测试 classification 字段别名。"""
        raw = '{"classification": "malicious"}'
        result = parser.parse(raw)

        assert result.label == "malicious"

    def test_score_alias_for_confidence(self, parser):
        """测试 score 字段作为 confidence 别名。"""
        raw = '{"label": "malicious", "score": 0.88}'
        result = parser.parse(raw)

        assert result.confidence == 0.88

    def test_explanation_alias_for_reason(self, parser):
        """测试 explanation 字段作为 reason 别名。"""
        raw = '{"label": "malicious", "explanation": "found eval"}'
        result = parser.parse(raw)

        assert result.reason == "found eval"

    def test_flags_alias_for_indicators(self, parser):
        """测试 flags 字段作为 indicators 别名。"""
        raw = '{"label": "malicious", "flags": ["eval", "system"]}'
        result = parser.parse(raw)

        assert "eval" in result.indicators
        assert "system" in result.indicators

    def test_boolean_label_true(self, parser):
        """测试布尔值 true 转为 malicious。"""
        raw = '{"label": true}'
        result = parser.parse(raw)

        assert result.label == "malicious"

    def test_boolean_label_false(self, parser):
        """测试布尔值 false 转为 benign。"""
        raw = '{"label": false}'
        result = parser.parse(raw)

        assert result.label == "benign"

    def test_numeric_label_1(self, parser):
        """测试数字 1 转为 malicious。"""
        raw = '{"label": "1"}'
        result = parser.parse(raw)

        assert result.label == "malicious"

    def test_numeric_label_0(self, parser):
        """测试数字 0 转为 benign。"""
        raw = '{"label": "0"}'
        result = parser.parse(raw)

        assert result.label == "benign"

    def test_malware_label_alias(self, parser):
        """测试 'malware' 字符串转为 malicious。"""
        raw = '{"label": "malware"}'
        result = parser.parse(raw)

        assert result.label == "malicious"

    def test_clean_label_alias(self, parser):
        """测试 'clean' 字符串转为 benign。"""
        raw = '{"label": "clean"}'
        result = parser.parse(raw)

        assert result.label == "benign"

    def test_invalid_label_defaults_unknown(self, parser):
        """测试无效 label 值默认为 unknown。"""
        raw = '{"label": "maybe"}'
        result = parser.parse(raw)

        assert result.label == "unknown"

    def test_missing_fields_use_defaults(self, parser):
        """测试缺失字段使用默认值。"""
        raw = '{"label": "malicious"}'
        result = parser.parse(raw)

        assert result.label == "malicious"
        assert result.malware_type == "unknown"
        assert result.obfuscation == "unknown"
        assert result.confidence == 0.0
        assert result.risk_level == "unknown"
        assert result.indicators == []

    def test_indicators_as_string(self, parser):
        """测试 indicators 为字符串时转为单元素列表。"""
        raw = '{"label": "malicious", "indicators": "eval"}'
        result = parser.parse(raw)

        assert result.indicators == ["eval"]

    def test_invalid_malware_type_defaults_unknown(self, parser):
        """测试无效 malware_type 默认为 unknown。"""
        raw = '{"label": "malicious", "malware_type": "trojan"}'
        result = parser.parse(raw)

        assert result.malware_type == "unknown"

    def test_invalid_obfuscation_defaults_unknown(self, parser):
        """测试无效 obfuscation 默认为 unknown。"""
        raw = '{"label": "malicious", "obfuscation": "rot13"}'
        result = parser.parse(raw)

        assert result.obfuscation == "unknown"


# ================================================================
# Confidence 边界处理
# ================================================================

class TestConfidenceClamping:
    """测试 confidence 值的边界处理。"""

    def test_confidence_above_1_clamped(self, parser):
        """测试 confidence > 1.0 被限制为 1.0。"""
        raw = '{"label": "malicious", "confidence": 1.5}'
        result = parser.parse(raw)

        assert result.confidence == 1.0

    def test_confidence_below_0_clamped(self, parser):
        """测试 confidence < 0.0 被限制为 0.0。"""
        raw = '{"label": "benign", "confidence": -0.5}'
        result = parser.parse(raw)

        assert result.confidence == 0.0

    def test_confidence_invalid_string_defaults_0(self, parser):
        """测试 confidence 为无效字符串时默认为 0.0。"""
        raw = '{"label": "malicious", "confidence": "high"}'
        result = parser.parse(raw)

        assert result.confidence == 0.0

    def test_confidence_missing_defaults_0(self, parser):
        """测试 confidence 缺失时默认为 0.0。"""
        raw = '{"label": "benign"}'
        result = parser.parse(raw)

        assert result.confidence == 0.0


# ================================================================
# DetectionResult 结构验证
# ================================================================

class TestDetectionResultStructure:
    """测试 DetectionResult 数据结构。"""

    def test_result_has_all_fields(self, parser):
        """测试返回结果包含所有必需字段。"""
        result = parser.parse('{"label": "malicious"}')

        assert hasattr(result, "label")
        assert hasattr(result, "malware_type")
        assert hasattr(result, "subtype")
        assert hasattr(result, "obfuscation")
        assert hasattr(result, "confidence")
        assert hasattr(result, "risk_level")
        assert hasattr(result, "reason")
        assert hasattr(result, "indicators")
        assert hasattr(result, "parse_error")

    def test_indicators_default_empty_list(self, parser):
        """测试 indicators 默认为空列表。"""
        result = parser.parse('{"label": "benign"}')
        assert result.indicators == []

    def test_parse_error_default_empty(self, parser):
        """测试成功解析时 parse_error 为空。"""
        result = parser.parse('{"label": "benign"}')
        assert result.parse_error == ""
