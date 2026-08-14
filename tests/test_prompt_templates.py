"""
PromptTemplate 单元测试

测试要点：
- zero_shot / few_shot / cot 三种策略的提示词生成
- JSON 格式要求（所有策略均要求 JSON 输出）
- CoT 策略的 reasoning 字段和五步推理流程
- 语言标注（已知语言 / unknown）
- 空内容处理
- 无效策略处理
"""

import pytest
from src.prompt_templates import PromptTemplate


# ================================================================
# 策略初始化
# ================================================================

class TestStrategyInit:
    """测试策略初始化。"""

    def test_init_zero_shot(self):
        """测试 zero_shot 策略初始化。"""
        pt = PromptTemplate(strategy="zero_shot")
        assert pt.strategy == "zero_shot"

    def test_init_few_shot(self):
        """测试 few_shot 策略初始化。"""
        pt = PromptTemplate(strategy="few_shot")
        assert pt.strategy == "few_shot"

    def test_init_cot(self):
        """测试 cot 策略初始化。"""
        pt = PromptTemplate(strategy="cot")
        assert pt.strategy == "cot"

    def test_invalid_strategy_raises(self):
        """测试无效策略抛出 ValueError。"""
        with pytest.raises(ValueError, match="不支持"):
            PromptTemplate(strategy="invalid_strategy")

    def test_invalid_strategy_empty(self):
        """测试空策略抛出 ValueError。"""
        with pytest.raises(ValueError):
            PromptTemplate(strategy="")

    def test_default_strategy_is_zero_shot(self):
        """测试默认策略为 zero_shot。"""
        pt = PromptTemplate()
        assert pt.strategy == "zero_shot"


# ================================================================
# Zero-shot 策略
# ================================================================

class TestZeroShot:
    """测试 Zero-shot 策略的提示词生成。"""

    def test_message_count(self):
        """测试消息数量：system + user = 2 条。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("echo 'hello'", language="php")

        assert len(messages) == 2

    def test_message_roles(self):
        """测试消息角色顺序：system 在前，user 在后。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("echo 'hello'", language="php")

        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"

    def test_system_contains_role_definition(self):
        """测试系统消息包含角色定义。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test code", language="php")
        system_content = messages[0]["content"]

        assert "网络安全分析专家" in system_content

    def test_system_contains_judgment_criteria(self):
        """测试系统消息包含判定标准。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test code", language="php")
        system_content = messages[0]["content"]

        assert "webshell" in system_content
        assert "sqli" in system_content
        assert "backdoor" in system_content
        assert "benign" in system_content

    def test_system_contains_json_format(self):
        """测试系统消息包含 JSON 格式要求。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test code", language="php")
        system_content = messages[0]["content"]

        assert "JSON" in system_content or "json" in system_content
        assert "label" in system_content
        assert "malware_type" in system_content
        assert "confidence" in system_content

    def test_system_contains_safety_guidelines(self):
        """测试系统消息包含安全防护指引。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test code", language="php")
        system_content = messages[0]["content"]

        assert "空" in system_content or "无法" in system_content

    def test_user_contains_code(self):
        """测试用户消息包含代码文本。"""
        code = '<?php echo "test"; ?>'
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages(code, language="php")
        user_content = messages[1]["content"]

        assert code in user_content

    def test_no_reasoning_field(self):
        """测试 zero_shot 不包含 reasoning 字段要求。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test", language="php")
        system_content = messages[0]["content"]

        assert "reasoning" not in system_content


# ================================================================
# Few-shot 策略
# ================================================================

class TestFewShot:
    """测试 Few-shot 策略的提示词生成。"""

    def test_message_count(self):
        """测试消息数量：system + 10条示例 + user = 12 条。"""
        pt = PromptTemplate(strategy="few_shot")
        messages = pt.build_messages("test code", language="php")

        # 1 system + 5 pairs (10 messages) + 1 user = 12
        assert len(messages) == 12

    def test_message_roles_alternate(self):
        """测试示例消息角色交替（user/assistant）。"""
        pt = PromptTemplate(strategy="few_shot")
        messages = pt.build_messages("test code", language="php")

        assert messages[0]["role"] == "system"
        # 示例对话应交替 user/assistant
        for i in range(1, 11, 2):
            assert messages[i]["role"] == "user"
            assert messages[i + 1]["role"] == "assistant"
        assert messages[11]["role"] == "user"

    def test_examples_contain_json(self):
        """测试示例的 assistant 消息包含 JSON 格式响应。"""
        pt = PromptTemplate(strategy="few_shot")
        messages = pt.build_messages("test code", language="php")

        # 检查第一个示例的 assistant 响应
        assistant_msg = messages[2]["content"]
        assert "label" in assistant_msg
        assert "malware_type" in assistant_msg

    def test_examples_cover_different_scenarios(self):
        """测试示例覆盖不同场景（良性、恶意、SQLi、混淆、边界）。"""
        pt = PromptTemplate(strategy="few_shot")
        messages = pt.build_messages("test code", language="php")

        labels_found = set()
        for i in range(2, 11, 2):
            content = messages[i]["content"]
            if '"benign"' in content:
                labels_found.add("benign")
            if '"malicious"' in content:
                labels_found.add("malicious")

        assert "benign" in labels_found
        assert "malicious" in labels_found

    def test_last_message_is_user_with_code(self):
        """测试最后一条消息是 user 且包含待检测代码。"""
        pt = PromptTemplate(strategy="few_shot")
        code = "<?php echo 'test'; ?>"
        messages = pt.build_messages(code, language="php")

        assert messages[-1]["role"] == "user"
        assert code in messages[-1]["content"]

    def test_system_mentions_examples(self):
        """测试系统消息提及示例说明。"""
        pt = PromptTemplate(strategy="few_shot")
        messages = pt.build_messages("test", language="php")
        system_content = messages[0]["content"]

        assert "示例" in system_content


# ================================================================
# CoT 策略
# ================================================================

class TestCoT:
    """测试 CoT 思维链策略的提示词生成。"""

    def test_message_count(self):
        """测试消息数量：system + user = 2 条。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test code", language="php")

        assert len(messages) == 2

    def test_message_roles(self):
        """测试消息角色。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test code", language="php")

        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"

    def test_system_contains_reasoning_field(self):
        """测试系统消息包含 reasoning 字段要求。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test code", language="php")
        system_content = messages[0]["content"]

        assert "reasoning" in system_content

    def test_system_contains_five_steps(self):
        """测试系统消息包含五步推理流程。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test code", language="php")
        system_content = messages[0]["content"]

        assert "第一步" in system_content
        assert "第二步" in system_content
        assert "第三步" in system_content
        assert "第四步" in system_content
        assert "第五步" in system_content

    def test_system_contains_code_structure_step(self):
        """测试 CoT 包含代码结构概览步骤。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test", language="php")

        assert "代码结构" in messages[0]["content"]

    def test_system_contains_data_flow_step(self):
        """测试 CoT 包含数据流追踪步骤。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test", language="php")

        assert "数据流" in messages[0]["content"]

    def test_system_contains_obfuscation_analysis_step(self):
        """测试 CoT 包含混淆分析步骤。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test", language="php")

        assert "混淆" in messages[0]["content"]

    def test_system_contains_json_format_with_reasoning(self):
        """测试 CoT 的 JSON 格式描述包含 reasoning 字段。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test", language="php")
        system_content = messages[0]["content"]

        assert "JSON" in system_content or "json" in system_content
        assert "reasoning" in system_content
        assert "label" in system_content

    def test_cot_has_obfuscation_rules(self):
        """测试 CoT 系统消息包含混淆识别规则。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test", language="php")
        system_content = messages[0]["content"]

        assert "base64" in system_content
        assert "string_split" in system_content or "字符串拼接" in system_content
        assert "xor" in system_content or "异或" in system_content
        assert "comment_bypass" in system_content or "注释" in system_content


# ================================================================
# 语言标注
# ================================================================

class TestLanguageHint:
    """测试语言标注功能。"""

    def test_php_language_hint(self):
        """测试 PHP 语言标注。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test", language="php")
        user_content = messages[1]["content"]

        assert "PHP" in user_content

    def test_python_language_hint(self):
        """测试 Python 语言标注。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test", language="python")
        user_content = messages[1]["content"]

        assert "Python" in user_content

    def test_sql_language_hint(self):
        """测试 SQL 语言标注。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test", language="sql")
        user_content = messages[1]["content"]

        assert "SQL" in user_content

    def test_unknown_language_omits_hint(self):
        """测试 unknown 语言省略语言标注。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test code", language="unknown")
        user_content = messages[1]["content"]

        # unknown 时应使用"以下代码"而非"以下 XXX 代码"
        assert "以下代码" in user_content
        assert "PHP" not in user_content
        assert "Python" not in user_content

    def test_language_hint_in_all_strategies(self):
        """测试所有策略都支持语言标注。"""
        code = "test code"
        for strategy in ("zero_shot", "few_shot", "cot"):
            pt = PromptTemplate(strategy=strategy)
            messages = pt.build_messages(code, language="php")
            user_content = messages[-1]["content"]
            assert "PHP" in user_content, f"策略 {strategy} 未包含 PHP 语言标注"


# ================================================================
# 空内容处理
# ================================================================

class TestEmptyContent:
    """测试空代码内容的处理。"""

    def test_empty_code_marked(self):
        """测试空代码内容被标记为(空内容)。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("", language="php")
        user_content = messages[1]["content"]

        assert "空内容" in user_content

    def test_whitespace_only_marked(self):
        """测试纯空白代码被标记为(空内容)。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("   \n\t  ", language="php")
        user_content = messages[1]["content"]

        assert "空内容" in user_content

    def test_empty_code_in_cot(self):
        """测试 CoT 策略处理空代码。"""
        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("", language="php")

        assert len(messages) == 2
        assert "空内容" in messages[1]["content"]

    def test_empty_code_in_few_shot(self):
        """测试 Few-shot 策略处理空代码。"""
        pt = PromptTemplate(strategy="few_shot")
        messages = pt.build_messages("", language="php")

        assert "空内容" in messages[-1]["content"]


# ================================================================
# JSON 格式要求验证
# ================================================================

class TestJsonFormatRequirements:
    """测试所有策略的 JSON 格式要求。"""

    @pytest.mark.parametrize("strategy", ["zero_shot", "few_shot", "cot"])
    def test_all_strategies_require_json(self, strategy):
        """测试所有策略都要求 JSON 格式输出。"""
        pt = PromptTemplate(strategy=strategy)
        messages = pt.build_messages("test", language="php")
        system_content = messages[0]["content"]

        assert "JSON" in system_content or "json" in system_content

    @pytest.mark.parametrize("strategy", ["zero_shot", "few_shot", "cot"])
    def test_all_strategies_require_label_field(self, strategy):
        """测试所有策略都要求 label 字段。"""
        pt = PromptTemplate(strategy=strategy)
        messages = pt.build_messages("test", language="php")
        system_content = messages[0]["content"]

        assert '"label"' in system_content or "label" in system_content

    @pytest.mark.parametrize("strategy", ["zero_shot", "few_shot", "cot"])
    def test_all_strategies_require_confidence_field(self, strategy):
        """测试所有策略都要求 confidence 字段。"""
        pt = PromptTemplate(strategy=strategy)
        messages = pt.build_messages("test", language="php")
        system_content = messages[0]["content"]

        assert "confidence" in system_content

    @pytest.mark.parametrize("strategy", ["zero_shot", "few_shot", "cot"])
    def test_all_strategies_require_indicators_field(self, strategy):
        """测试所有策略都要求 indicators 字段。"""
        pt = PromptTemplate(strategy=strategy)
        messages = pt.build_messages("test", language="php")
        system_content = messages[0]["content"]

        assert "indicators" in system_content

    def test_cot_json_has_reasoning_but_others_dont(self):
        """测试只有 CoT 的 JSON 格式包含 reasoning 字段。"""
        for strategy in ("zero_shot", "few_shot"):
            pt = PromptTemplate(strategy=strategy)
            messages = pt.build_messages("test", language="php")
            system_content = messages[0]["content"]
            assert "reasoning" not in system_content, (
                f"策略 {strategy} 不应包含 reasoning 字段"
            )

        pt = PromptTemplate(strategy="cot")
        messages = pt.build_messages("test", language="php")
        system_content = messages[0]["content"]
        assert "reasoning" in system_content


# ================================================================
# 消息格式验证
# ================================================================

class TestMessageFormat:
    """测试消息格式符合 OpenAI API 规范。"""

    def test_all_messages_have_role_and_content(self):
        """测试所有消息都包含 role 和 content 字段。"""
        for strategy in ("zero_shot", "few_shot", "cot"):
            pt = PromptTemplate(strategy=strategy)
            messages = pt.build_messages("test code", language="php")

            for msg in messages:
                assert "role" in msg
                assert "content" in msg
                assert isinstance(msg["content"], str)
                assert len(msg["content"]) > 0

    def test_system_message_is_string(self):
        """测试系统消息内容为字符串。"""
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages("test", language="php")

        assert isinstance(messages[0]["content"], str)

    def test_user_message_contains_code_text(self):
        """测试用户消息包含完整的代码文本。"""
        code = "<?php\necho 'unique_marker_12345';\n?>"
        pt = PromptTemplate(strategy="zero_shot")
        messages = pt.build_messages(code, language="php")

        assert "unique_marker_12345" in messages[1]["content"]
