"""
LLM API 客户端封装模块

统一封装 DeepSeek 和通义千问（阿里云百炼）的 API 调用。
两个平台均兼容 OpenAI SDK，通过切换 base_url 和 api_key 实现多平台支持。

功能：
- 统一的检测调用接口
- JSON 结构化输出模式
- temperature 可控（默认 0.1 保证可复现性）
- 指数退避重试机制
- Token 用量和延迟记录

使用方式：
    from src.llm_client import LLMClient
    client = LLMClient(provider="deepseek")
    result, usage = client.detect("待检测代码", messages)
"""

import os
import time
import logging
from typing import Any

import yaml
from openai import OpenAI

logger = logging.getLogger(__name__)

# config.yaml 的默认路径（相对于项目根目录）
DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config.yaml"
)


def load_config(config_path: str | None = None) -> dict:
    """
    加载 config.yaml 配置文件。

    Args:
        config_path: 配置文件路径，为 None 时使用默认路径

    Returns:
        配置字典
    """
    path = config_path or DEFAULT_CONFIG_PATH
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class LLMClient:
    """LLM API 统一客户端，支持 DeepSeek 和通义千问。"""

    def __init__(self, provider: str = "deepseek", config: dict | None = None):
        """
        初始化 LLM 客户端。

        Args:
            provider: API 提供商，"deepseek" 或 "qwen"
            config: 配置字典，为 None 时自动加载 config.yaml

        Raises:
            ValueError: provider 不支持或 API Key 未配置时
        """
        if config is None:
            config = load_config()

        self.provider = provider
        providers_cfg = config.get("providers", {})

        if provider not in providers_cfg:
            raise ValueError(
                f"不支持的提供商: {provider}，可选: {list(providers_cfg.keys())}"
            )

        cfg = providers_cfg[provider]

        # 从环境变量读取 API Key
        api_key = os.environ.get(cfg["api_key_env"])
        if not api_key:
            raise ValueError(
                f"环境变量 {cfg['api_key_env']} 未设置，"
                f"请先配置 API Key 环境变量"
            )

        self.base_url = cfg["base_url"]
        self.api_key = api_key
        self.model = cfg["model"]
        self.max_tokens = cfg.get("max_tokens", 4096)
        self.temperature = cfg.get("temperature", 0.1)

        # 检测参数
        detection_cfg = config.get("detection", {})
        self.retry_max = detection_cfg.get("retry_max", 3)
        self.retry_delay = detection_cfg.get("retry_delay", 2.0)

        # 创建 OpenAI 兼容客户端
        self.client = OpenAI(base_url=self.base_url, api_key=self.api_key)

        logger.info(
            f"LLMClient 初始化完成: provider={provider}, model={self.model}"
        )

    def detect(
        self,
        messages: list[dict],
        use_json: bool = True,
        temperature: float | None = None,
    ) -> tuple[dict | str, dict]:
        """
        调用 LLM 进行恶意代码检测。

        Args:
            messages: OpenAI 格式的消息列表
            use_json: 是否启用 JSON 结构化输出模式
            temperature: 采样温度，为 None 时使用配置默认值

        Returns:
            (result, usage) 元组：
            - result: use_json=True 时为解析后的 dict，否则为原始文本
            - usage: 包含 prompt_tokens, completion_tokens, total_tokens, latency_ms 的字典

        Raises:
            RuntimeError: 重试次数用尽后仍失败
        """
        temp = temperature if temperature is not None else self.temperature

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": self.max_tokens,
        }

        if use_json:
            kwargs["response_format"] = {"type": "json_object"}

        last_error = None
        for attempt in range(1, self.retry_max + 1):
            try:
                start_time = time.time()
                response = self.client.chat.completions.create(**kwargs)
                latency_ms = int((time.time() - start_time) * 1000)

                content = response.choices[0].message.content
                usage_info = {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                    "latency_ms": latency_ms,
                    "model": self.model,
                    "provider": self.provider,
                }

                if use_json:
                    import json
                    result = json.loads(content)
                else:
                    result = content

                logger.debug(
                    f"API 调用成功: attempt={attempt}, "
                    f"tokens={usage_info['total_tokens']}, "
                    f"latency={latency_ms}ms"
                )
                return result, usage_info

            except Exception as e:
                last_error = e
                wait_time = self.retry_delay * (2 ** (attempt - 1))
                logger.warning(
                    f"API 调用失败 (attempt {attempt}/{self.retry_max}): "
                    f"{type(e).__name__}: {e}, "
                    f"{wait_time:.1f}s 后重试..."
                )
                if attempt < self.retry_max:
                    time.sleep(wait_time)

        raise RuntimeError(
            f"API 调用失败，已重试 {self.retry_max} 次。"
            f"最后错误: {type(last_error).__name__}: {last_error}"
        )

    def verify_connection(self) -> tuple[bool, str]:
        """
        验证 API 连通性，发送一个简单请求检查密钥和网络是否正常。

        Returns:
            (success, message) 元组
        """
        test_messages = [
            {
                "role": "system",
                "content": "你是一个助手，请用 JSON 格式回复。",
            },
            {
                "role": "user",
                "content": '请回复 {"status": "ok", "message": "连通性验证成功"}',
            },
        ]

        try:
            result, usage = self.detect(test_messages, use_json=True)
            return True, (
                f"连接成功 | 模型: {self.model} | "
                f"Token: {usage['total_tokens']} | "
                f"延迟: {usage['latency_ms']}ms | "
                f"响应: {result}"
            )
        except Exception as e:
            return False, f"连接失败: {type(e).__name__}: {e}"
