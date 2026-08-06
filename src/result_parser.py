"""
结果解析器模块

解析 LLM API 返回的 JSON 响应，容错处理格式异常，从混合文本中提取 JSON 块。

功能：
- JSON 解析（标准模式）
- 混合文本中 JSON 块提取（CoT 模式下 LLM 先输出分析过程再输出 JSON）
- 字段校验和默认值填充
- 异常记录

使用方式（阶段二实现）：
    from src.result_parser import ResultParser
    parser = ResultParser()
    result = parser.parse(raw_response, strategy="cot")
"""

import json
import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """标准化的检测结果。"""
    label: str = "unknown"           # malicious | benign | unknown
    malware_type: str = "unknown"    # webshell | backdoor | sqli | none | unknown
    subtype: str = "unknown"
    obfuscation: str = "unknown"     # none | base64 | string_split | xor | comment_bypass | unknown
    confidence: float = 0.0
    risk_level: str = "unknown"      # high | medium | low | none | unknown
    reason: str = ""
    indicators: list[str] = None
    parse_error: str = ""            # 解析异常时记录错误信息


class ResultParser:
    """LLM 响应结果解析器。"""

    # 合法值集合，用于校验
    VALID_LABELS = {"malicious", "benign"}
    VALID_MALWARE_TYPES = {"webshell", "backdoor", "sqli", "none"}
    VALID_OBFUSCATIONS = {"none", "base64", "string_split", "xor", "comment_bypass"}
    VALID_RISK_LEVELS = {"high", "medium", "low", "none"}

    def parse(self, raw_response: str | dict, strategy: str = "zero_shot") -> DetectionResult:
        """
        解析 LLM 返回的响应。

        Args:
            raw_response: API 返回的原始内容（字符串或已解析的 dict）
            strategy: 使用的提示词策略（影响解析方式）

        Returns:
            标准化的 DetectionResult 对象
        """
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _extract_json_from_text(self, text: str) -> dict | None:
        """
        从混合文本中提取 JSON 块（CoT 模式下使用）。
        先尝试 ```json ... ``` 代码块，再尝试裸 JSON。

        Args:
            text: 包含分析过程和 JSON 结论的混合文本

        Returns:
            解析后的 dict，失败返回 None
        """
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _validate_and_fill(self, data: dict) -> DetectionResult:
        """校验字段合法性并填充默认值。"""
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")
