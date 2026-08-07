"""
T1.6 + T1.7 · 混淆变种生成脚本

对原始 WebShell 样本应用 4 种混淆技术，生成混淆变种。
所有操作仅做静态文本处理，禁止执行任何代码。

混淆技术：
  1. Base64 编码：eval(base64_decode('...'))  包装
  2. 注释绕过：在关键字间插入 /**/ 注释
  3. 字符串分割：将关键字符串拆分并用 . 连接
  4. XOR 编码：对关键字符串进行 XOR 编码后解码执行

使用方式：
    python scripts/generate_obfuscated.py
    python scripts/generate_obfuscated.py --max-per-sample 1  # 每种混淆只生成1个变种
"""

import os
import sys
import base64
import random
import logging
import re
from pathlib import Path

# 将项目根目录加入 sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="  %(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# 输入目录：原始 WebShell 样本
WEBSHELL_DIR = os.path.join(project_root, "data", "samples", "webshell")

# 输出目录：混淆变种
OBFUSCATED_DIR = os.path.join(project_root, "data", "samples", "obfuscated")

# 4 种混淆技术的子目录
TECHNIQUE_DIRS = {
    "base64": os.path.join(OBFUSCATED_DIR, "base64"),
    "comment_bypass": os.path.join(OBFUSCATED_DIR, "comment_bypass"),
    "string_split": os.path.join(OBFUSCATED_DIR, "string_split"),
    "xor": os.path.join(OBFUSCATED_DIR, "xor"),
}

# 固定随机种子保证可复现
random.seed(42)


# ============================================================
# 混淆技术 1：Base64 编码
# ============================================================

def obfuscate_base64_php(code: str) -> str:
    """
    PHP Base64 编码混淆：
    将原始 PHP 代码 base64 编码，用 eval(base64_decode('...')) 包装。

    示例：
      原始: <?php system($_GET['cmd']); ?>
      混淆: <?php eval(base64_decode('PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSkgPz4=')); ?>
    """
    # 去除 PHP 标签，只编码中间内容
    inner = code
    inner = re.sub(r'^\s*<\?php\s*', '', inner)
    inner = re.sub(r'^\s*<\?\s*', '', inner)
    inner = re.sub(r'\?>\s*$', '', inner)
    inner = inner.strip()

    if not inner:
        return code

    encoded = base64.b64encode(inner.encode("utf-8")).decode("ascii")
    return f"<?php eval(base64_decode('{encoded}')); ?>"


def obfuscate_base64_python(code: str) -> str:
    """
    Python Base64 编码混淆：
    将原始代码 base64 编码，用 exec(base64.b64decode(...)) 包装。
    """
    encoded = base64.b64encode(code.encode("utf-8")).decode("ascii")
    return f"import base64;exec(base64.b64decode('{encoded}'))"


# ============================================================
# 混淆技术 2：注释绕过
# ============================================================

# 需要插入注释绕过的 PHP 关键函数和关键字
PHP_COMMENT_TARGETS = [
    "eval", "system", "exec", "passthru", "shell_exec",
    "base64_decode", "str_rot13", "gzinflate", "gzuncompress",
    "assert", "preg_replace", "create_function",
    "file_get_contents", "file_put_contents", "fopen", "fwrite",
    "move_uploaded_file", "copy", "rename",
    "proc_open", "popen", "pcntl_exec",
]

# 需要插入注释绕过的 Python 关键函数
PYTHON_COMMENT_TARGETS = [
    "exec", "eval", "compile", "os.system", "subprocess",
    "os.popen", "getattr", "__import__",
]


def obfuscate_comment_bypass_php(code: str) -> str:
    """
    PHP 注释绕过混淆：
    在关键函数名中间插入 /**/ 注释，使关键字匹配失效。

    示例：
      原始: system('whoami')
      混淆: sys/**/tem('whoami')
    """
    result = code
    for func in PHP_COMMENT_TARGETS:
        if len(func) <= 3:
            continue
        # 在函数名中间位置插入注释
        mid = len(func) // 2
        pattern = re.compile(r'\b' + re.escape(func) + r'\b')
        replacement = func[:mid] + '/**/' + func[mid:]
        result = pattern.sub(replacement, result)
    return result


def obfuscate_comment_bypass_python(code: str) -> str:
    """
    Python 注释绕过混淆：
    在关键函数名中间插入空字符串拼接，打断特征匹配。

    示例：
      原始: os.system('whoami')
      混淆: os.sys# comment\ntem('whoami')  (使用行连接)
    """
    result = code
    for func in PYTHON_COMMENT_TARGETS:
        if '.' in func:
            parts = func.split('.')
            if len(parts) == 2 and len(parts[1]) > 3:
                mid = len(parts[1]) // 2
                pattern = re.compile(re.escape(func))
                replacement = parts[0] + '.' + parts[1][:mid] + '""+' + '""' + parts[1][mid:]
                result = pattern.sub(replacement, result, count=1)
        elif len(func) > 3:
            mid = len(func) // 2
            pattern = re.compile(r'\b' + re.escape(func) + r'\b')
            replacement = func[:mid] + '""+' + '""' + func[mid:]
            result = pattern.sub(replacement, result, count=1)
    return result


# ============================================================
# 混淆技术 3：字符串分割
# ============================================================

def obfuscate_string_split_php(code: str) -> str:
    """
    PHP 字符串分割混淆：
    将关键字符串拆分为多个部分，用 . 连接。

    示例：
      原始: eval('phpinfo()')
      混淆: ev.'al'('phpinfo()')  →  ('ev'.'al')('phpinfo()')
    """
    result = code
    for func in PHP_COMMENT_TARGETS:
        if len(func) <= 3:
            continue
        # 将函数名拆分为两半并用字符串连接
        mid = len(func) // 2
        pattern = re.compile(r'\b' + re.escape(func) + r'\b')
        replacement = "'" + func[:mid] + "'.'" + func[mid:] + "'"
        result = pattern.sub(replacement, result)
    return result


def obfuscate_string_split_python(code: str) -> str:
    """
    Python 字符串分割混淆：
    将关键字符串拆分为多个部分，用 + 连接。
    """
    result = code
    for func in PYTHON_COMMENT_TARGETS:
        if '.' in func:
            parts = func.split('.')
            if len(parts) == 2 and len(parts[1]) > 3:
                mid = len(parts[1]) // 2
                pattern = re.compile(re.escape(func))
                replacement = parts[0] + '.' + '"' + parts[1][:mid] + '"+"' + parts[1][mid:] + '"'
                result = pattern.sub(replacement, result, count=1)
        elif len(func) > 3:
            mid = len(func) // 2
            pattern = re.compile(r'\b' + re.escape(func) + r'\b')
            replacement = '"' + func[:mid] + '"+' + '"' + func[mid:] + '"'
            result = pattern.sub(replacement, result, count=1)
    return result


# ============================================================
# 混淆技术 4：XOR 编码
# ============================================================

def xor_encode(data: bytes, key: bytes) -> bytes:
    """对数据进行 XOR 编码"""
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)


def bytes_to_php_hex(data: bytes) -> str:
    """将字节数据转换为 PHP 十六进制字符串表示"""
    return ''.join(f'\\x{b:02x}' for b in data)


def obfuscate_xor_php(code: str) -> str:
    """
    PHP XOR 编码混淆：
    将原始代码 XOR 编码后，用 eval 解码执行。

    示例：
      原始: <?php system('whoami'); ?>
      混淆: <?php $k='key';$c="\x01\x02...";eval($c^str_repeat($k,strlen($c))); ?>
    """
    # 去除 PHP 标签
    inner = code
    inner = re.sub(r'^\s*<\?php\s*', '', inner)
    inner = re.sub(r'^\s*<\?\s*', '', inner)
    inner = re.sub(r'\?>\s*$', '', inner)
    inner = inner.strip()

    if not inner:
        return code

    # XOR 编码
    key = b"k3y"
    encoded = xor_encode(inner.encode("utf-8"), key)
    hex_encoded = bytes_to_php_hex(encoded)

    return (
        f"<?php $k='{key.decode()}';"
        f"$c=\"{hex_encoded}\";"
        f"eval($c^str_repeat($k,strlen($c))); ?>"
    )


def obfuscate_xor_python(code: str) -> str:
    """
    Python XOR 编码混淆：
    将原始代码 XOR 编码后，用 exec 解码执行。
    """
    key = b"k3y"
    encoded = xor_encode(code.encode("utf-8"), key)
    hex_encoded = ''.join(f'\\x{b:02x}' for b in encoded)

    return (
        f"k=b'{key.decode()}';"
        f"c=b'{hex_encoded}';"
        f"exec(bytes(c[i]^k[i%len(k)]for i in range(len(c))))"
    )


# ============================================================
# 主逻辑
# ============================================================

def detect_language(filename: str) -> str:
    """根据文件扩展名检测语言"""
    ext = os.path.splitext(filename)[1].lower()
    if ext == ".php":
        return "php"
    elif ext == ".py":
        return "python"
    elif ext in (".jsp", ".asp", ".aspx"):
        return "other"
    return "text"


def obfuscate_sample(code: str, language: str, technique: str) -> str | None:
    """
    对样本应用指定的混淆技术。

    Args:
        code: 原始代码内容
        language: 语言（php / python / other）
        technique: 混淆技术（base64 / comment_bypass / string_split / xor）

    Returns:
        混淆后的代码，如果不适用则返回 None
    """
    if language == "php":
        if technique == "base64":
            return obfuscate_base64_php(code)
        elif technique == "comment_bypass":
            return obfuscate_comment_bypass_php(code)
        elif technique == "string_split":
            return obfuscate_string_split_php(code)
        elif technique == "xor":
            return obfuscate_xor_php(code)
    elif language == "python":
        if technique == "base64":
            return obfuscate_base64_python(code)
        elif technique == "comment_bypass":
            return obfuscate_comment_bypass_python(code)
        elif technique == "string_split":
            return obfuscate_string_split_python(code)
        elif technique == "xor":
            return obfuscate_xor_python(code)

    # 其他语言暂不处理
    return None


def main():
    import argparse

    parser = argparse.ArgumentParser(description="T1.6+T1.7 · 混淆变种生成")
    parser.add_argument(
        "--max-per-sample", type=int, default=1,
        help="每种混淆技术对每个样本生成的变种数（默认1）"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  T1.6+T1.7 · 混淆变种生成")
    print("  [安全提示] 仅做静态文本处理，禁止执行任何代码")
    print("=" * 60)

    # 创建输出目录
    for tech, dir_path in TECHNIQUE_DIRS.items():
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

    # 4 种混淆技术
    techniques = ["base64", "comment_bypass", "string_split", "xor"]
    technique_labels = {
        "base64": "Base64 编码",
        "comment_bypass": "注释绕过",
        "string_split": "字符串分割",
        "xor": "XOR 编码",
    }

    total_generated = 0
    stats = {tech: 0 for tech in techniques}

    for sample_path in samples:
        fname = os.path.basename(sample_path)
        language = detect_language(fname)

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

        # 对每种混淆技术生成变种
        for tech in techniques:
            obfuscated = obfuscate_sample(code, language, tech)
            if obfuscated is None:
                continue

            if obfuscated == code:
                logger.warning(f"混淆无变化: {fname} + {tech}")
                continue

            # 生成输出文件名
            output_fname = f"{base_name}_{tech}{ext}"
            output_path = os.path.join(TECHNIQUE_DIRS[tech], output_fname)

            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(obfuscated)
                stats[tech] += 1
                total_generated += 1
            except Exception as e:
                logger.warning(f"写入失败 {output_fname}: {e}")

    # 汇总
    print(f"\n{'='*60}")
    print("  混淆变种生成完成")
    print(f"{'='*60}")
    for tech in techniques:
        label = technique_labels[tech]
        count = stats[tech]
        print(f"  {label:15s} ({tech:15s}): {count:4d} 个")
    print(f"  {'─'*45}")
    print(f"  {'总计':15s}{'':15s}: {total_generated:4d} 个")
    print(f"\n  输出目录: {OBFUSCATED_DIR}")

    # 打印各子目录
    for tech, dir_path in TECHNIQUE_DIRS.items():
        print(f"    {tech:15s}: {dir_path}")


if __name__ == "__main__":
    main()
