"""
批量检测主流程模块

串联样本加载、提示词组装、API 调用、结果解析、指标计算、数据导出，
实现完整的检测管道。支持命令行参数指定提示词策略、API 提供商、样本范围。

使用方式（阶段二实现）：
    python -m src.batch_runner --strategy cot --provider deepseek
    python -m src.batch_runner --strategy few_shot --provider qwen --category obfuscated
"""

import logging
import argparse

logger = logging.getLogger(__name__)


class BatchRunner:
    """批量检测主流程控制器。"""

    def __init__(
        self,
        provider: str = "deepseek",
        strategy: str = "zero_shot",
        config_path: str | None = None,
    ):
        """
        Args:
            provider: API 提供商（deepseek / qwen）
            strategy: 提示词策略（zero_shot / few_shot / cot）
            config_path: 配置文件路径
        """
        self.provider = provider
        self.strategy = strategy
        self.config_path = config_path
        # 阶段二实现：初始化各模块
        # self.llm_client = LLMClient(provider, config)
        # self.sample_loader = SampleLoader(...)
        # self.prompt_template = PromptTemplate(strategy)
        # self.result_parser = ResultParser()
        # self.exporter = Exporter(...)

    def run(
        self,
        category: str | None = None,
        obfuscation: str | None = None,
        max_samples: int | None = None,
        repeats: int = 1,
    ) -> str:
        """
        执行批量检测。

        Args:
            category: 按类别筛选样本
            obfuscation: 按混淆方式筛选样本
            max_samples: 最大检测样本数（调试用）
            repeats: 每条样本重复运行次数（取多数投票）

        Returns:
            结果输出目录路径
        """
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _detect_single(self, code_text: str, language: str) -> dict:
        """检测单条样本。"""
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")

    def _majority_vote(self, results: list[dict]) -> dict:
        """对多次运行结果取多数投票。"""
        # 阶段二实现
        raise NotImplementedError("将在阶段二实现")


def main():
    """命令行入口。"""
    parser = argparse.ArgumentParser(
        description="WebShell LLM Detector - 批量检测"
    )
    parser.add_argument(
        "--strategy", choices=["zero_shot", "few_shot", "cot"],
        default="zero_shot", help="提示词策略"
    )
    parser.add_argument(
        "--provider", choices=["deepseek", "qwen"],
        default="deepseek", help="API 提供商"
    )
    parser.add_argument(
        "--category", choices=["benign", "webshell", "obfuscated", "sqli"],
        default=None, help="按类别筛选样本"
    )
    parser.add_argument(
        "--obfuscation",
        choices=["base64", "string_split", "xor", "comment_bypass"],
        default=None, help="按混淆方式筛选样本"
    )
    parser.add_argument(
        "--max-samples", type=int, default=None,
        help="最大检测样本数（调试用）"
    )
    parser.add_argument(
        "--repeats", type=int, default=1,
        help="每条样本重复运行次数"
    )
    args = parser.parse_args()

    runner = BatchRunner(
        provider=args.provider,
        strategy=args.strategy,
    )
    output_dir = runner.run(
        category=args.category,
        obfuscation=args.obfuscation,
        max_samples=args.max_samples,
        repeats=args.repeats,
    )
    print(f"实验完成，结果已导出至: {output_dir}")


if __name__ == "__main__":
    main()
