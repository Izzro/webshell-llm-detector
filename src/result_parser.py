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

        处理流程：
        1. dict 输入（use_json=True 时 llm_client 已 json.loads）→ 直接校验填充
        2. str 输入 → 尝试直接 JSON 解析 → 失败则从混合文本提取 JSON（CoT）
        3. 全部失败 → 返回带 parse_error 的默认结果

        Args:
            raw_response: API 返回的原始内容（字符串或已解析的 dict）
            strategy: 使用的提示词策略（影响解析方式）

        Returns:
            标准化的 DetectionResult 对象
        """
        # 情况 1: 已是 dict（use_json=True 模式）
        if isinstance(raw_response, dict):
            return self._validate_and_fill(raw_response)

        # 情况 2: 字符串输入
        if isinstance(raw_response, str):
            text = raw_response.strip()

            # 2a: 尝试直接 JSON 解析
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    return self._validate_and_fill(data)
            except (json.JSONDecodeError, ValueError):
                pass

            # 2b: 从混合文本中提取 JSON（CoT 模式）
            data = self._extract_json_from_text(text)
            if data is not None:
                return self._validate_and_fill(data)

            # 2c: 全部失败，返回错误结果
            error_result = DetectionResult(
                parse_error=f"无法从响应中解析 JSON: {text[:200]}..."
            )
            logger.warning(f"JSON 解析失败: {text[:100]}")
            return error_result

        # 其他类型
        return DetectionResult(
            parse_error=f"不支持的响应类型: {type(raw_response).__name__}"
        )

    def _extract_json_from_text(self, text: str) -> dict | None:
        """
        从混合文本中提取 JSON 块（CoT 模式下使用）。

        CoT 模式下 LLM 会先输出分析推理过程，再输出 JSON 结论。
        提取策略（按优先级）：
        1. ```json ... ``` 代码块
        2. ``` ... ``` 代码块（无语言标记）
        3. 第一个 { 到最后一个 } 的子串（裸 JSON）
        4. 逐步修复后重试（去除尾逗号、补全括号）

        Args:
            text: 包含分析过程和 JSON 结论的混合文本

        Returns:
            解析后的 dict，失败返回 None
        """
        # 策略 1: ```json ... ``` 代码块
        match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if match:
            data = self._try_parse_json(match.group(1))
            if data is not None:
                return data

        # 策略 2: ``` ... ``` 代码块（无语言标记）
        match = re.search(r'```\s*(.*?)\s*```', text, re.DOTALL)
        if match:
            block = match.group(1).strip()
            # 去掉可能的 "json" 前缀
            if block.lower().startswith("json"):
                block = block[4:].strip()
            data = self._try_parse_json(block)
            if data is not None:
                return data

        # 策略 3: 第一个 { 到最后一个 } 的子串
        first_brace = text.find('{')
        last_brace = text.rfind('}')
        if first_brace != -1 and last_brace > first_brace:
            json_str = text[first_brace:last_brace + 1]
            data = self._try_parse_json(json_str)
            if data is not None:
                return data

        # 策略 4: 尝试从最后一个 { 开始提取（LLM 可能在 reasoning 中使用了 {）
        all_braces = [i for i, ch in enumerate(text) if ch == '{']
        for start_idx in reversed(all_braces):
            end_idx = text.rfind('}')
            if end_idx > start_idx:
                json_str = text[start_idx:end_idx + 1]
                data = self._try_parse_json(json_str)
                if data is not None:
                    return data

        return None

    def _try_parse_json(self, json_str: str) -> dict | None:
        """
        尝试解析 JSON 字符串，失败时尝试修复后重试。

        修复策略：
        1. 直接解析
        2. 去除尾逗号（trailing comma）
        3. 补全缺失的右括号
        4. 提取最后一个完整 JSON 对象

        Args:
            json_str: 待解析的 JSON 字符串

        Returns:
            解析后的 dict，失败返回 None
        """
        # 1. 直接解析
        try:
            data = json.loads(json_str)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, ValueError):
            pass

        # 2. 去除尾逗号
        repaired = re.sub(r',\s*([}\]])', r'\1', json_str)
        try:
            data = json.loads(repaired)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, ValueError):
            pass

        # 3. 补全缺失的右括号
        open_braces = json_str.count('{')
        close_braces = json_str.count('}')
        open_brackets = json_str.count('[')
        close_brackets = json_str.count(']')
        if open_braces > close_braces or open_brackets > close_brackets:
            suffix = '}' * max(0, open_braces - close_braces)
            suffix += ']' * max(0, open_brackets - close_brackets)
            try:
                data = json.loads(json_str + suffix)
                if isinstance(data, dict):
                    return data
            except (json.JSONDecodeError, ValueError):
                pass

        # 4. 尝试逐字符截断找到最后一个可解析的 JSON
        for i in range(len(json_str) - 1, 0, -1):
            if json_str[i] == '}':
                candidate = json_str[:i + 1]
                # 找到对应的起始 {
                start = candidate.rfind('{')
                if start >= 0:
                    sub = candidate[start:]
                    repaired = re.sub(r',\s*([}\]])', r'\1', sub)
                    try:
                        data = json.loads(repaired)
                        if isinstance(data, dict):
                            return data
                    except (json.JSONDecodeError, ValueError):
                        continue

        return None

    def _validate_and_fill(self, data: dict) -> DetectionResult:
        """
        校验字段合法性并填充默认值。

        支持字段名别名兼容（LLM 可能返回不同的键名）：
        - label / is_malicious / verdict / classification
        - malware_type / type / malware_category
        - confidence / confidence_score / score
        - reason / explanation / analysis / description
        - indicators / flags / suspicious_patterns

        值规范化：
        - label: 支持布尔值 true/false/1/0 转换
        - confidence: 转为 float 并限制在 [0.0, 1.0]
        - 所有字符串字段: strip + lower（枚举类）

        Args:
            data: 从 JSON 解析得到的字典

        Returns:
            标准化的 DetectionResult 对象
        """
        if not isinstance(data, dict):
            return DetectionResult(
                parse_error=f"期望 dict，得到 {type(data).__name__}"
            )

        def get_value(*keys, default=None):
            """从多个可能的键名中取第一个非空值。"""
            for key in keys:
                if key in data and data[key] is not None:
                    return data[key]
            return default

        # ---- label ----
        raw_label = str(get_value(
            "label", "is_malicious", "verdict", "classification",
            default=""
        )).strip().lower()
        if raw_label in self.VALID_LABELS:
            label = raw_label
        elif raw_label in ("true", "1", "yes", "malware"):
            label = "malicious"
        elif raw_label in ("false", "0", "no", "clean"):
            label = "benign"
        else:
            label = "unknown"

        # ---- malware_type ----
        raw_type = str(get_value(
            "malware_type", "type", "malware_category", "category",
            default=""
        )).strip().lower()
        malware_type = raw_type if raw_type in self.VALID_MALWARE_TYPES else "unknown"

        # ---- subtype ----
        subtype = str(get_value(
            "subtype", "sub_type", "variant", "family",
            default="unknown"
        )).strip()
        subtype = subtype if subtype else "unknown"

        # ---- obfuscation ----
        raw_obf = str(get_value(
            "obfuscation", "obfuscation_type", "obfuscation_method",
            default=""
        )).strip().lower()
        obfuscation = raw_obf if raw_obf in self.VALID_OBFUSCATIONS else "unknown"

        # ---- confidence ----
        try:
            confidence = float(get_value(
                "confidence", "confidence_score", "score",
                default=0.0
            ))
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.0

        # ---- risk_level ----
        raw_risk = str(get_value(
            "risk_level", "risk", "severity", "threat_level",
            default=""
        )).strip().lower()
        risk_level = raw_risk if raw_risk in self.VALID_RISK_LEVELS else "unknown"

        # ---- reason ----
        reason = str(get_value(
            "reason", "explanation", "analysis", "description", "summary",
            default=""
        )).strip()

        # ---- indicators ----
        raw_indicators = get_value(
            "indicators", "flags", "suspicious_patterns", "suspicious_functions",
            default=[]
        )
        if isinstance(raw_indicators, list):
            indicators = [str(i).strip() for i in raw_indicators if i]
        elif isinstance(raw_indicators, str) and raw_indicators.strip():
            indicators = [raw_indicators.strip()]
        else:
            indicators = []

        return DetectionResult(
            label=label,
            malware_type=malware_type,
            subtype=subtype,
            obfuscation=obfuscation,
            confidence=confidence,
            risk_level=risk_level,
            reason=reason,
            indicators=indicators,
        )
