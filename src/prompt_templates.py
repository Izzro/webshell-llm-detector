"""
提示词模板模块

管理三组提示词策略（Zero-shot / Few-shot / CoT），负责组装发送给 LLM 的 messages 列表。

功能：
- Zero-shot：仅任务描述和判定规则，无示例
- Few-shot：附加 3-5 个标注示例（覆盖良性、WebShell、SQLi、混淆、边界案例）
- CoT：五步思维链推理（代码结构概览 → 敏感函数识别 → 数据流追踪 → 混淆分析 → 综合判定）

使用方式（阶段二实现）：
    from src.prompt_templates import PromptTemplate
    prompt = PromptTemplate(strategy="cot")
    messages = prompt.build_messages(code_text, language="php")
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class PromptTemplate:
    """提示词模板管理器，支持三组策略。"""

    SUPPORTED_STRATEGIES = ["zero_shot", "few_shot", "cot"]

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

    def build_messages(
        self, code_text: str, language: str = "php"
    ) -> list[dict]:
        """
        组装发送给 LLM 的 messages 列表。

        Args:
            code_text: 待检测的代码文本
            language: 代码语言（php/python/sql）

        Returns:
            OpenAI 格式的 messages 列表
        """
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _build_zero_shot(self, code_text: str, language: str) -> list[dict]:
        """构建 Zero-shot 提示词。"""
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _build_few_shot(self, code_text: str, language: str) -> list[dict]:
        """构建 Few-shot 提示词。"""
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _build_cot(self, code_text: str, language: str) -> list[dict]:
        """构建 CoT 思维链提示词。"""
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")
