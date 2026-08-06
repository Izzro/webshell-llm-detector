"""
T1.1 · API 连通性验证脚本

验证 DeepSeek 和通义千问（阿里云百炼）的 API 连通性。
检查环境变量是否配置、密钥是否有效、模型是否可用。

使用方式：
    python scripts/verify_api.py

前置条件：
    设置环境变量 DEEPSEEK_API_KEY 和 DASHSCOPE_API_KEY
"""

import sys
import os
import time

# 将项目根目录加入 sys.path，使 src 模块可导入
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.llm_client import LLMClient, load_config


def check_env_var(var_name: str) -> bool:
    """检查环境变量是否已设置。"""
    value = os.environ.get(var_name)
    if not value:
        print(f"  [缺失] 环境变量 {var_name} 未设置")
        print(f"         请运行以下命令设置（PowerShell 临时生效）：")
        print(f'         $env:{var_name} = "你的API密钥"')
        print(f"         或永久设置：")
        print(f'         [System.Environment]::SetEnvironmentVariable("{var_name}", "你的密钥", "User")')
        return False
    # 脱敏显示（只显示前4位和后4位）
    masked = value[:4] + "*" * (len(value) - 8) + value[-4:] if len(value) > 8 else "****"
    print(f"  [已设置] {var_name} = {masked}")
    return True


def verify_provider(provider: str, config: dict) -> bool:
    """
    验证单个 API 提供商的连通性。

    Args:
        provider: 提供商名称（deepseek / qwen）
        config: 配置字典

    Returns:
        是否验证成功
    """
    print(f"\n{'='*60}")
    print(f"  验证 {provider.upper()} API 连通性")
    print(f"{'='*60}")

    cfg = config["providers"][provider]
    print(f"  Base URL : {cfg['base_url']}")
    print(f"  Model    : {cfg['model']}")
    print(f"  Temp     : {cfg.get('temperature', 0.1)}")

    try:
        print(f"\n  正在创建客户端并发送测试请求...")
        client = LLMClient(provider=provider, config=config)
        success, message = client.verify_connection()

        if success:
            print(f"\n  [成功] {message}")
            return True
        else:
            print(f"\n  [失败] {message}")
            return False
    except ValueError as e:
        print(f"\n  [配置错误] {e}")
        return False
    except Exception as e:
        print(f"\n  [异常] {type(e).__name__}: {e}")
        return False


def main():
    print("=" * 60)
    print("  WebShell LLM Detector - API 连通性验证")
    print("  T1.1 · 阶段一环境验证")
    print("=" * 60)

    # 步骤 1：检查环境变量
    print("\n[步骤 1] 检查 API 密钥环境变量")
    print("-" * 60)

    env_vars = {
        "deepseek": "DEEPSEEK_API_KEY",
        "qwen": "DASHSCOPE_API_KEY",
    }

    all_env_ok = True
    for provider, var_name in env_vars.items():
        print(f"\n  {provider.upper()}:")
        if not check_env_var(var_name):
            all_env_ok = False

    if not all_env_ok:
        print("\n" + "=" * 60)
        print("  [中断] 部分环境变量未设置，请先配置后再运行验证。")
        print("=" * 60)
        sys.exit(1)

    # 步骤 2：加载配置
    print(f"\n[步骤 2] 加载 config.yaml 配置")
    print("-" * 60)
    try:
        config = load_config()
        providers = list(config["providers"].keys())
        print(f"  配置加载成功，已配置提供商: {providers}")
    except Exception as e:
        print(f"  [失败] 配置加载失败: {type(e).__name__}: {e}")
        sys.exit(1)

    # 步骤 3：逐一验证 API 连通性
    print(f"\n[步骤 3] 验证 API 连通性")
    print("-" * 60)

    results = {}
    for provider in providers:
        results[provider] = verify_provider(provider, config)

    # 汇总结果
    print(f"\n{'='*60}")
    print("  验证结果汇总")
    print(f"{'='*60}")

    all_passed = True
    for provider, success in results.items():
        status = "通过" if success else "失败"
        icon = "[OK]" if success else "[X]"
        print(f"  {icon} {provider.upper():12s} : {status}")
        if not success:
            all_passed = False

    print(f"\n  总结: {'全部通过' if all_passed else '部分失败，请检查上述错误信息'}")

    if all_passed:
        print("\n  环境验证完成，可以进入下一步（样本收集）。")
        sys.exit(0)
    else:
        print("\n  请修复上述问题后重新运行验证。")
        sys.exit(1)


if __name__ == "__main__":
    main()
