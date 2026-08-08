"""
传统规则型 WebShell 扫描器

基于正则模式匹配和特征工程的检测方法，作为 LLM 检测的对照基线。
不依赖任何机器学习或大语言模型，纯粹基于预定义的恶意代码特征规则。

检测维度：
1. 危险函数调用（eval, system, exec, passthru, shell_exec, proc_open 等）
2. 用户输入到危险函数的数据流（$_POST/$_GET/$_REQUEST → eval/system）
3. 混淆技术识别（base64_decode, 字符串拼接, 异或, 注释绕过）
4. SQL 注入特征（UNION SELECT, SLEEP, BENCHMARK, 堆叠注入）
5. 后门连接特征（fsockopen, socket_connect, reverse shell）
6. 文件管理功能（upload, download, 列目录）

使用方式：
    from src.traditional_scanner import TraditionalScanner
    scanner = TraditionalScanner()
    result = scanner.scan(code_text, language="php")
"""

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """扫描结果数据结构。"""
    label: str = "benign"           # benign | malicious
    malware_type: str = "none"      # webshell | backdoor | sqli | none
    subtype: str = ""               # 具体子类型
    obfuscation: str = "none"       # none | base64 | string_split | xor | comment_bypass
    confidence: float = 0.0         # 0.0 - 1.0
    risk_level: str = "none"        # high | medium | low | none
    reason: str = ""               # 判定理由
    indicators: list = field(default_factory=list)  # 触发的规则
    rules_triggered: list = field(default_factory=list)  # 触发的规则名称


class TraditionalScanner:
    """
    基于规则匹配的 WebShell 检测器。

    模拟传统安全扫描器的工作方式：
    - 预定义恶意代码特征规则库
    - 对输入代码进行正则匹配
    - 根据匹配到的规则数量和严重程度判定
    """

    # ================================================================
    # 危险函数规则（高危）
    # ================================================================
    DANGEROUS_FUNCTIONS = {
        # 代码执行类
        "eval": r"\beval\s*\(",
        "assert": r"\bassert\s*\(",
        "preg_replace_eval": r"preg_replace\s*\(.*/e",  # /e 修饰符
        "create_function": r"\bcreate_function\s*\(",
        "call_user_func": r"\bcall_user_func\s*\(",
        "call_user_func_array": r"\bcall_user_func_array\s*\(",

        # 命令执行类
        "system": r"\bsystem\s*\(",
        "exec": r"\bexec\s*\(",
        "shell_exec": r"\bshell_exec\s*\(",
        "passthru": r"\bpassthru\s*\(",
        "proc_open": r"\bproc_open\s*\(",
        "popen": r"\bpopen\s*\(",
        "pcntl_exec": r"\bpcntl_exec\s*\(",
        "backticks": r"`[^`]+`",  # 反引号执行

        # Python 危险函数
        "python_exec": r"\bexec\s*\(",
        "python_eval": r"\beval\s*\(",
        "python_os_system": r"\bos\.system\s*\(",
        "python_subprocess": r"\bsubprocess\.(call|Popen|run)\s*\(",
        "python_importlib": r"\bimportlib\.(import_module|__import__)\s*\(",
    }

    # ================================================================
    # 用户输入源规则
    # ================================================================
    USER_INPUT_PATTERNS = {
        "php_post": r"\$_POST\s*\[",
        "php_get": r"\$_GET\s*\[",
        "php_request": r"\$_REQUEST\s*\[",
        "php_cookie": r"\$_COOKIE\s*\[",
        "php_server": r"\$_SERVER\s*\[",
        "php_argv": r"\$argv\b",
        "php_stdin": r"php://input",
        "php_files": r"\$_FILES\s*\[",
        "python_input": r"\binput\s*\(",
        "python_sys_argv": r"\bsys\.argv\b",
        "python_stdin": r"\bsys\.stdin\b",
    }

    # ================================================================
    # 混淆技术规则
    # ================================================================
    OBFUSCATION_RULES = {
        "base64": [
            r"base64_decode\s*\(",
            r"base64\.b64decode\s*\(",
            r"\bbase64\.b64encode\s*\(",
        ],
        "string_split": [
            r'\$\w+\s*=\s*["\']\w+["\']\s*;?\s*\$\w+\s*=\s*["\']\w+["\']',  # $a="ev";$b="al";
            r'\$\w+\s*\.\s*\$\w+\s*\(',  # $a.$b(
            r"str_replace\s*\(.+\(.*\)",  # str_replace 组装
            r"implode\s*\(.+\(.*\)",
        ],
        "xor": [
            r"\b\w+\s*\^\s*\w+",  # XOR 运算
            r"\bord\s*\(\s*\w+\s*\)\s*\^\s*ord\s*\(\s*\w+\s*\)",
        ],
        "comment_bypass": [
            r"/\*\*/",  # 注释穿插 ev/**/al
            r"//.*\n.*//",  # 多行注释分隔
        ],
        "hex_encode": [
            r"\\x[0-9a-fA-F]{2}",  # 十六进制编码
            r"chr\s*\(\s*\d+\s*\)",  # chr() 编码
            r"pack\s*\(\s*['\"]H\*",  # pack hex
        ],
        "rot13": [
            r"str_rot13\s*\(",
        ],
        "gzip": [
            r"gzinflate\s*\(",
            r"gzuncompress\s*\(",
            r"gzdecode\s*\(",
        ],
    }

    # ================================================================
    # SQL 注入特征规则
    # ================================================================
    SQL_INJECTION_RULES = {
        "union_select": r"(?i)\bunion\b\s+(?i)\bselect\b",
        "boolean_blind": r"(?i)\b(and|or)\b\s+\d+\s*=\s*\d+",
        "time_blind": r"(?i)\b(sleep|benchmark|pg_sleep)\s*\(",
        "stacked": r";\s*(?i)(drop|insert|update|delete)\b",
        "error_based": r"(?i)(extractvalue|updatexml|floor)\s*\(",
        "comment_injection": r"(--|#|/\*).*$",
        "information_schema": r"(?i)information_schema",
        "load_file": r"(?i)\bload_file\s*\(",
        "into_outfile": r"(?i)\binto\s+(?i)outfile\b",
        "hex_injection": r"(?i)0x[0-9a-f]+",
        "concat": r"(?i)\bconcat\s*\(",
        "group_concat": r"(?i)\bgroup_concat\s*\(",
    }

    # ================================================================
    # 后门/反弹 Shell 规则
    # ================================================================
    BACKDOOR_RULES = {
        "fsockopen": r"\bfsockopen\s*\(",
        "socket_create": r"\bsocket_create\s*\(",
        "socket_connect": r"\bsocket_connect\s*\(",
        "stream_socket": r"\bstream_socket_client\s*\(",
        "reverse_shell": r"(?i)(bash|sh|zsh)\s+-i",
        "python_socket": r"\bsocket\.socket\s*\(",
        "python_os_popen": r"\bos\.popen\s*\(",
        "eval_payload": r"(?i)(python|perl|ruby)\s+-c\s+['\"]",
    }

    # ================================================================
    # 文件管理功能规则（WebShell 常见功能）
    # ================================================================
    FILE_MANAGEMENT_RULES = {
        "file_upload": r"(?i)move_uploaded_file\s*\(",
        "file_put_contents": r"\bfile_put_contents\s*\(",
        "file_get_contents": r"\bfile_get_contents\s*\(",
        "fopen_write": r"\bfopen\s*\(.+['\"]w",
        "copy": r"\bcopy\s*\(",
        "rename": r"\brename\s*\(",
        "unlink": r"\bunlink\s*\(",
        "mkdir": r"\bmkdir\s*\(",
        "scandir": r"\bscandir\s*\(",
        "glob": r"\bglob\s*\(",
        "readdir": r"\breaddir\s*\(",
    }

    # 规则权重（不同规则的严重程度）
    RULE_WEIGHTS = {
        # 代码执行 + 用户输入 = 高危
        "eval_with_input": 1.0,
        "system_with_input": 1.0,
        "exec_with_input": 1.0,
        "passthru_with_input": 1.0,
        "shell_exec_with_input": 1.0,
        "proc_open_with_input": 1.0,
        # 代码执行无输入
        "eval_no_input": 0.6,
        "system_no_input": 0.5,
        "exec_no_input": 0.5,
        # 混淆
        "base64_decode_eval": 1.0,
        "base64_decode_only": 0.4,
        "string_split_func": 0.7,
        "xor_decode": 0.6,
        "comment_bypass": 0.5,
        "hex_encode": 0.4,
        # SQL 注入
        "sqli_union": 0.9,
        "sqli_time": 0.9,
        "sqli_boolean": 0.7,
        "sqli_stacked": 0.8,
        # 后门
        "reverse_shell": 1.0,
        "fsockopen": 0.6,
        "socket_connect": 0.6,
        # 文件管理
        "file_upload": 0.5,
        "file_management": 0.3,
    }

    def scan(self, code_text: str, language: str = "unknown") -> ScanResult:
        """
        扫描代码文本，返回检测结果。

        Args:
            code_text: 代码文本
            language: 代码语言（php/python/sql/unknown）

        Returns:
            ScanResult 检测结果
        """
        if not code_text or not code_text.strip():
            return ScanResult(
                label="benign",
                reason="代码内容为空",
                confidence=0.0,
            )

        code_lower = code_text.lower()
        indicators = []
        rules_triggered = []
        total_score = 0.0

        # ---- 1. 检测危险函数 + 用户输入组合 ----
        dangerous_found = set()
        user_input_found = set()

        for name, pattern in self.DANGEROUS_FUNCTIONS.items():
            if re.search(pattern, code_text, re.IGNORECASE):
                dangerous_found.add(name)

        for name, pattern in self.USER_INPUT_PATTERNS.items():
            if re.search(pattern, code_text, re.IGNORECASE):
                user_input_found.add(name)

        # 危险函数 + 用户输入 = 高危
        high_risk_functions = {"eval", "assert", "system", "exec", "shell_exec",
                               "passthru", "proc_open", "popen", "pcntl_exec"}
        for func in dangerous_found:
            func_base = func.replace("python_", "").replace("preg_replace_eval", "eval")
            if func_base in high_risk_functions or func in high_risk_functions:
                if user_input_found:
                    score = self.RULE_WEIGHTS.get(f"{func_base}_with_input", 0.8)
                    total_score += score
                    indicators.append(f"{func_base}() + 用户输入")
                    rules_triggered.append(f"dangerous_func_with_input:{func_base}")
                else:
                    score = self.RULE_WEIGHTS.get(f"{func_base}_no_input", 0.4)
                    total_score += score
                    indicators.append(f"{func_base}()")
                    rules_triggered.append(f"dangerous_func:{func_base}")

        # ---- 2. 检测混淆技术 ----
        obfuscation_detected = "none"

        # base64 + eval 组合
        has_base64 = bool(re.search(r"base64_decode\s*\(", code_text, re.IGNORECASE) or
                         re.search(r"base64\.b64decode\s*\(", code_text, re.IGNORECASE))
        has_eval = bool(re.search(r"\beval\s*\(", code_text, re.IGNORECASE))

        if has_base64 and has_eval:
            total_score += self.RULE_WEIGHTS["base64_decode_eval"]
            indicators.append("base64_decode + eval 组合")
            rules_triggered.append("obfuscation:base64_eval")
            obfuscation_detected = "base64"
        elif has_base64:
            total_score += self.RULE_WEIGHTS["base64_decode_only"]
            indicators.append("base64_decode")
            rules_triggered.append("obfuscation:base64")
            obfuscation_detected = "base64"

        # 字符串拆分
        for pattern in self.OBFUSCATION_RULES["string_split"]:
            if re.search(pattern, code_text):
                total_score += self.RULE_WEIGHTS["string_split_func"]
                indicators.append("字符串拼接还原函数名")
                rules_triggered.append("obfuscation:string_split")
                obfuscation_detected = "string_split"
                break

        # XOR
        for pattern in self.OBFUSCATION_RULES["xor"]:
            if re.search(pattern, code_text):
                total_score += self.RULE_WEIGHTS["xor_decode"]
                indicators.append("XOR 异或运算")
                rules_triggered.append("obfuscation:xor")
                obfuscation_detected = "xor"
                break

        # 注释绕过
        if re.search(r"/\*\*/", code_text):
            # 检查是否用于绕过关键词检测
            if re.search(r"\w+/\*\*/\w+", code_text):
                total_score += self.RULE_WEIGHTS["comment_bypass"]
                indicators.append("注释穿插绕过 ev/**/al")
                rules_triggered.append("obfuscation:comment_bypass")
                obfuscation_detected = "comment_bypass"

        # ---- 3. 检测 SQL 注入 ----
        sqli_indicators = []
        for name, pattern in self.SQL_INJECTION_RULES.items():
            if re.search(pattern, code_text):
                sqli_indicators.append(name)
                rules_triggered.append(f"sqli:{name}")

        if sqli_indicators:
            for ind in sqli_indicators:
                weight_key = f"sqli_{ind}" if f"sqli_{ind}" in self.RULE_WEIGHTS else "sqli_union"
                total_score += self.RULE_WEIGHTS.get(weight_key, 0.7)
            indicators.append(f"SQL注入: {', '.join(sqli_indicators)}")

        # ---- 4. 检测后门/反弹 Shell ----
        for name, pattern in self.BACKDOOR_RULES.items():
            if re.search(pattern, code_text, re.IGNORECASE):
                weight = self.RULE_WEIGHTS.get("reverse_shell" if "reverse" in name else name, 0.6)
                total_score += weight
                indicators.append(f"后门: {name}")
                rules_triggered.append(f"backdoor:{name}")

        # ---- 5. 检测文件管理功能 ----
        file_mgmt_count = 0
        for name, pattern in self.FILE_MANAGEMENT_RULES.items():
            if re.search(pattern, code_text, re.IGNORECASE):
                file_mgmt_count += 1
                rules_triggered.append(f"file_mgmt:{name}")

        if file_mgmt_count >= 2:
            total_score += self.RULE_WEIGHTS["file_management"]
            indicators.append(f"文件管理功能 ({file_mgmt_count} 个)")
        elif file_mgmt_count >= 1:
            total_score += 0.1
            indicators.append("文件操作函数")

        # ---- 6. 综合判定 ----
        # 归一化分数（上限 1.0）
        confidence = min(total_score, 1.0)

        # 判定阈值
        if confidence >= 0.5:
            label = "malicious"
            if sqli_indicators and not dangerous_found and not obfuscation_detected != "none":
                malware_type = "sqli"
            elif any("backdoor" in r for r in rules_triggered):
                malware_type = "backdoor"
            else:
                malware_type = "webshell"

            if confidence >= 0.8:
                risk_level = "high"
            elif confidence >= 0.5:
                risk_level = "medium"
            else:
                risk_level = "low"

            reason = f"规则匹配触发 {len(rules_triggered)} 条规则, " + \
                     ", ".join(indicators[:5])
        else:
            label = "benign"
            malware_type = "none"
            risk_level = "none"
            if indicators:
                reason = f"检测到低风险特征 ({len(indicators)} 个), 未达到恶意判定阈值"
            else:
                reason = "未匹配到任何恶意特征规则"

        return ScanResult(
            label=label,
            malware_type=malware_type,
            subtype="",
            obfuscation=obfuscation_detected if label == "malicious" else "none",
            confidence=round(confidence, 2),
            risk_level=risk_level,
            reason=reason,
            indicators=indicators,
            rules_triggered=rules_triggered,
        )
