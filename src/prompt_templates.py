"""
提示词模板模块

管理三组提示词策略（Zero-shot / Few-shot / CoT），负责组装发送给 LLM 的 messages 列表。

功能：
- Zero-shot：仅任务描述和判定规则，无示例
- Few-shot：附加 5 个标注示例（覆盖良性、WebShell、SQLi、混淆、边界案例）
- CoT：五步思维链推理（代码结构概览 → 敏感函数识别 → 数据流追踪 → 混淆分析 → 综合判定）

设计要点：
- language="unknown" 时省略语言标注，让 LLM 自行从代码语法判断（方案A）
- 系统消息包含防护指引：空内容/乱码 → benign + confidence=0.0
- Zero-shot/Few-shot 使用 JSON 模式（use_json=True），CoT 使用文本模式（use_json=False）
- CoT 输出为分析过程 + ```json 代码块，由 result_parser._extract_json_from_text() 解析

使用方式：
    from src.prompt_templates import PromptTemplate
    prompt = PromptTemplate(strategy="cot")
    messages = prompt.build_messages(code_text, language="php")
"""

import json
import logging

logger = logging.getLogger(__name__)


class PromptTemplate:
    """提示词模板管理器，支持三组策略。"""

    SUPPORTED_STRATEGIES = ["zero_shot", "few_shot", "cot"]

    # 语言标注映射（unknown 时省略标注）
    LANGUAGE_LABELS = {
        "php": "PHP",
        "python": "Python",
        "sql": "SQL",
        "jsp": "JSP",
        "asp": "ASP",
    }

    # ================================================================
    # 公共提示词片段
    # ================================================================

    _ROLE = "你是一名网络安全分析专家，专精 Web 场景下的脚本类恶意代码检测。"

    _JUDGMENT_CRITERIA = """\
判定标准：
- webshell：通过 eval/assert/system/exec/passthru 等函数执行用户输入或系统命令；文件管理功能（上传/下载/列目录/编辑）；后门连接
- sqli：SQL 注入载荷，如 UNION SELECT、布尔盲注、时间盲注（SLEEP/BENCHMARK）、堆叠注入
- backdoor：反弹 shell（fsockopen/socket_connect）、隐藏连接、持久化驻留
- benign：正常框架代码或业务逻辑；即使包含危险函数但输入受控"""

    _OBFUSCATION_RULES = """\
混淆识别规则：
- base64：base64_decode/base64.b64decode 后接 eval/exec
- string_split：字符串拼接还原函数名（如 $a="ev";$b="al";$a.$b($_POST)）
- xor：异或运算还原字符串
- comment_bypass：注释穿插打断关键词（如 ev/**/al）"""

    _SAFETY_GUIDELINES = """\
注意事项：
- 如果代码内容为空、无法识别或无语法结构，请返回 label="benign", confidence=0.0, reason="代码内容无法分析"
- 不要将"无法理解的内容"判定为混淆或恶意，只有检测到明确的混淆技术（如 base64_decode+eval 组合）才标注 obfuscation
- 对于良性代码中合法使用 eval/system 等函数但输入受控的情况，应判定为 benign"""

    _JSON_FORMAT_DIRECT = """\
请严格按以下 JSON 格式输出，不要输出其他内容：
{
    "label": "malicious 或 benign",
    "malware_type": "webshell/backdoor/sqli/none 之一",
    "subtype": "具体子类型描述",
    "obfuscation": "none/base64/string_split/xor/comment_bypass 之一",
    "confidence": 0.0 到 1.0 的置信度,
    "risk_level": "high/medium/low/none 之一",
    "reason": "判定理由",
    "indicators": ["触发判定的关键函数或模式"]
}"""

    _JSON_FORMAT_COT = """\
在分析过程结束后，输出以下 JSON 格式的结论（用 ```json 代码块包裹）：
```json
{
    "label": "malicious 或 benign",
    "malware_type": "webshell/backdoor/sqli/none 之一",
    "subtype": "具体子类型描述",
    "obfuscation": "none/base64/string_split/xor/comment_bypass 之一",
    "confidence": 0.0 到 1.0 的置信度,
    "risk_level": "high/medium/low/none 之一",
    "reason": "判定理由",
    "indicators": ["触发判定的关键函数或模式"]
}
```"""

    # CoT 五步推理流程
    _COT_STEPS = """\
请按以下五步推理流程分析代码，先输出分析过程，最后输出 JSON 结论：

第一步 · 代码结构概览
  概述代码的整体功能和执行流程。

第二步 · 敏感函数识别
  列出代码中所有危险函数调用（eval/system/exec/passthru/base64_decode 等）。

第三步 · 数据流追踪
  追踪用户输入（$_GET/$_POST/$_REQUEST/stdin）是否能到达危险函数，判断中间是否有过滤或转义。

第四步 · 混淆分析
  检查是否存在 Base64 编码、字符串拆分、异或运算、注释绕过等混淆手段。

第五步 · 综合判定
  综合以上分析给出结论。"""

    # ================================================================
    # Few-shot 示例（5 个，覆盖核心场景）
    # ================================================================

    FEW_SHOT_EXAMPLES = [
        # 示例1: 良性（Laravel框架认证代码）
        {
            "role": "user",
            "content": (
                "请分析以下 PHP 代码是否为恶意代码：\n"
                "```php\n"
                "<?php\n"
                "namespace Illuminate\\Auth;\n"
                "use Illuminate\\Contracts\\Auth\\Gate;\n"
                "class GateEvaluator {\n"
                "    public function evaluate($ability, $arguments = []) {\n"
                "        return $this->denies($ability, $arguments) ? false : true;\n"
                "    }\n"
                "}\n"
                "?>\n"
                "```"
            ),
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "label": "benign",
                "malware_type": "none",
                "subtype": "框架认证代码",
                "obfuscation": "none",
                "confidence": 0.95,
                "risk_level": "none",
                "reason": "Laravel 框架的权限门面代码，denies 方法用于权限检查，无危险函数调用",
                "indicators": [],
            }, ensure_ascii=False),
        },
        # 示例2: 一句话木马
        {
            "role": "user",
            "content": (
                "请分析以下 PHP 代码是否为恶意代码：\n"
                "```php\n"
                "<?php @eval($_POST['cmd']); ?>\n"
                "```"
            ),
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "label": "malicious",
                "malware_type": "webshell",
                "subtype": "一句话木马",
                "obfuscation": "none",
                "confidence": 0.99,
                "risk_level": "high",
                "reason": "直接将用户 POST 输入传入 eval 执行，@ 抑制错误输出，是典型的一句话木马",
                "indicators": ["eval", "$_POST", "@error_suppression"],
            }, ensure_ascii=False),
        },
        # 示例3: SQL注入载荷
        {
            "role": "user",
            "content": (
                "请分析以下 SQL 代码是否为恶意代码：\n"
                "```\n"
                "' UNION SELECT user,pass FROM users-- \n"
                "```"
            ),
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "label": "malicious",
                "malware_type": "sqli",
                "subtype": "UNION注入",
                "obfuscation": "none",
                "confidence": 0.97,
                "risk_level": "high",
                "reason": "使用 UNION SELECT 拼接查询获取 users 表的用户名和密码字段，-- 注释掉后续SQL",
                "indicators": ["UNION SELECT", "column_enumeration", "comment_injection"],
            }, ensure_ascii=False),
        },
        # 示例4: Base64混淆
        {
            "role": "user",
            "content": (
                "请分析以下 PHP 代码是否为恶意代码：\n"
                "```php\n"
                "<?php $a=\"ZXZhbA==\";eval(base64_decode($a));?>\n"
                "```"
            ),
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "label": "malicious",
                "malware_type": "webshell",
                "subtype": "base64编码一句话木马",
                "obfuscation": "base64",
                "confidence": 0.95,
                "risk_level": "high",
                "reason": "base64_decode 解码 'ZXZhbA==' 得到 'eval'，再通过 eval 执行，是典型的 Base64 混淆",
                "indicators": ["base64_decode", "eval", "dynamic_execution"],
            }, ensure_ascii=False),
        },
        # 示例5: 边界（system但输入受控）
        {
            "role": "user",
            "content": (
                "请分析以下 PHP 代码是否为恶意代码：\n"
                "```php\n"
                "<?php\n"
                "$dir = config('app.log_dir');\n"
                "system('ls ' . escapeshellarg($dir));\n"
                "?>\n"
                "```"
            ),
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "label": "benign",
                "malware_type": "none",
                "subtype": "受控命令调用",
                "obfuscation": "none",
                "confidence": 0.85,
                "risk_level": "low",
                "reason": "虽然使用了 system 函数，但输入来自配置文件且经过 escapeshellarg 转义，不存在用户输入直达命令执行的路径",
                "indicators": ["system", "escapeshellarg"],
            }, ensure_ascii=False),
        },
    ]

    # ================================================================
    # 初始化
    # ================================================================

    def __init__(self, strategy: str = "zero_shot"):
        """
        Args:
            strategy: 提示词策略，zero_shot / few_shot / cot

        Raises:
            ValueError: 策略不支持时
        """
        if strategy not in self.SUPPORTED_STRATEGIES:
            raise ValueError(
                f"不支持的策略: {strategy}，可选: {self.SUPPORTED_STRATEGIES}"
            )
        self.strategy = strategy

    # ================================================================
    # 主入口
    # ================================================================

    def build_messages(
        self, code_text: str, language: str = "php"
    ) -> list[dict]:
        """
        组装发送给 LLM 的 messages 列表。

        根据 strategy 分发到对应的构建方法。每条策略返回的 messages
        都包含 system 消息（角色+规则+防护指引+JSON格式）和 user 消息（代码）。
        Few-shot 额外包含 5 个示例对话。

        Args:
            code_text: 待检测的代码文本
            language: 代码语言（php/python/sql/jsp/asp），unknown 时省略语言标注

        Returns:
            OpenAI 格式的 messages 列表
        """
        if self.strategy == "zero_shot":
            return self._build_zero_shot(code_text, language)
        elif self.strategy == "few_shot":
            return self._build_few_shot(code_text, language)
        elif self.strategy == "cot":
            return self._build_cot(code_text, language)
        # 不应该到达（__init__ 已校验）
        raise ValueError(f"未知策略: {self.strategy}")

    # ================================================================
    # 三组策略实现
    # ================================================================

    def _build_zero_shot(self, code_text: str, language: str) -> list[dict]:
        """
        构建 Zero-shot 提示词。

        消息结构：[system(角色+规则+防护指引+JSON格式), user(代码)]
        use_json=True，LLM 直接返回纯 JSON。
        """
        system_prompt = self._build_system_prompt(use_cot=False)
        user_prompt = self._build_user_prompt(code_text, language)
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

    def _build_few_shot(self, code_text: str, language: str) -> list[dict]:
        """
        构建 Few-shot 提示词。

        消息结构：[system(角色+规则+示例说明), 5轮示例对话, user(代码)]
        use_json=True，LLM 从示例学习格式后直接返回纯 JSON。
        """
        system_prompt = self._build_system_prompt(use_cot=False)
        system_prompt += "\n\n以下是几个分析示例，请参照示例的输出格式进行分析："

        messages = [{"role": "system", "content": system_prompt}]
        # 添加 5 个示例对话（每个示例包含 user + assistant 两条消息）
        messages.extend(self.FEW_SHOT_EXAMPLES)
        # 添加待检测代码
        messages.append(
            {"role": "user", "content": self._build_user_prompt(code_text, language)}
        )
        return messages

    def _build_cot(self, code_text: str, language: str) -> list[dict]:
        """
        构建 CoT 思维链提示词。

        消息结构：[system(角色+五步流程+规则+防护指引+JSON代码块格式), user(代码+引导语)]
        use_json=False，LLM 先输出分析过程，最后输出 ```json 代码块。
        解析由 result_parser._extract_json_from_text() 处理。
        """
        system_prompt = self._build_system_prompt(use_cot=True)
        user_prompt = self._build_user_prompt(code_text, language)
        user_prompt += "\n\n请按五步分析流程进行判定。"
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

    # ================================================================
    # 辅助方法
    # ================================================================

    def _build_system_prompt(self, use_cot: bool = False) -> str:
        """
        构建系统消息。

        公共部分：角色定义 + 判定标准 + 混淆规则 + 防护指引
        CoT 专属：五步推理流程 + 代码块包裹的 JSON 格式
        非 CoT：直接 JSON 格式约束

        Args:
            use_cot: 是否为 CoT 模式（影响 JSON 格式描述和推理流程）

        Returns:
            完整的系统消息文本
        """
        parts = [self._ROLE]

        if use_cot:
            parts.append(self._COT_STEPS)

        parts.append(self._JUDGMENT_CRITERIA)
        parts.append(self._OBFUSCATION_RULES)
        parts.append(self._SAFETY_GUIDELINES)

        if use_cot:
            parts.append(self._JSON_FORMAT_COT)
        else:
            parts.append(self._JSON_FORMAT_DIRECT)

        return "\n\n".join(parts)

    def _build_user_prompt(self, code_text: str, language: str) -> str:
        """
        构建用户消息。

        - 已知语言：标注"以下 PHP/Python/SQL 代码"
        - 未知语言（unknown）：省略语言标注，只写"以下代码"（方案A）
        - 空内容：标注"(空内容)"，让 LLM 知道这是异常输入

        Args:
            code_text: 代码文本
            language: 代码语言

        Returns:
            用户消息文本
        """
        lang_hint = self._build_language_hint(language)

        # 空内容预检
        if not code_text.strip():
            return f"请分析{lang_hint}是否为恶意代码：\n```\n(空内容)\n```"

        return f"请分析{lang_hint}是否为恶意代码：\n```\n{code_text}\n```"

    @staticmethod
    def _build_language_hint(language: str) -> str:
        """
        构建语言标注。

        已知语言返回"以下 PHP 代码"等，未知语言返回"以下代码"。
        这让 LLM 自行从代码语法（<?php、def、<%@ %>）判断语言。

        Args:
            language: 代码语言标识

        Returns:
            语言标注文本
        """
        label = PromptTemplate.LANGUAGE_LABELS.get(language)
        if label:
            return f"以下 {label} 代码"
        return "以下代码"
