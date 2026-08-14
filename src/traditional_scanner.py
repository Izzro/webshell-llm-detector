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
            r"['\"]\w+['\"]\s*\.\s*['\"]\w+['\"]\s*\(",  # 'ev'.'al'(  — 字符串字面量拼接
            r"\(['\"]\w+['\"]\s*\.\s*['\"]\w+['\"]\)\s*\(",  # ('ev'.'al')(  — 拼接后调用
            r"str_replace\s*\(.+\(.*\)",  # str_replace 组装
            r"implode\s*\(.+\(.*\)",
        ],
        "xor": [
            r"\b\w+\s*\^\s*\w+",  # XOR 运算
            r"\bord\s*\(\s*\w+\s*\)\s*\^\s*ord\s*\(\s*\w+\s*\)",
            r"\w+\[[^\]]+\]\s*\^\s*\w+\[",  # c[i]^k[i...] Python XOR
            r"exec\s*\(\s*bytes\s*\([^)]*\^",  # exec(bytes(...^...))
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
        "union_select": r"(?i)\bunion\b\s+\bselect\b",
        "boolean_blind": r"(?i)\b(and|or)\b\s+\d+\s*=\s*\d+",
        "time_blind": r"(?i)\b(sleep|benchmark|pg_sleep)\s*\(",
        "stacked": r"(?i);\s*(drop|insert|update|delete)\b",
        "error_based": r"(?i)(extractvalue|updatexml|floor)\s*\(",
        "comment_injection": r"(--|#|/\*).*$",
        "information_schema": r"(?i)information_schema",
        "load_file": r"(?i)\bload_file\s*\(",
        "into_outfile": r"(?i)\binto\s+outfile\b",
        "hex_injection": r"(?i)0x[0-9a-f]{8,}",
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
        "comment_bypass": 0.7,
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

    # ================================================================
    # 安全模式规则（用于降低误报）
    # ================================================================
    SAFE_PATTERNS = {
        "escapeshellarg": r"\bescapeshellarg\s*\(",
        "escapeshellcmd": r"\bescapeshellcmd\s*\(",
        "prepared_stmt": r"(?i)(prepare\s*\(|PDO::|mysqli_prepare|stmt_bind_param)",
        "htmlspecialchars": r"\bhtmlspecialchars\s*\(",
        "filter_var": r"\bfilter_var\s*\(",
        "whitelist_check": r"\bin_array\s*\(.+,\s*\$",  # in_array($input, $whitelist)
        "type_check": r"\b(is_string|is_numeric|is_int|is_array|ctype_alnum)\s*\(",
        "realpath_check": r"\brealpath\s*\(",
        "token_verify": r"(?i)(hash_equals|password_verify|token_verify)",
    }

    def _detect_safe_patterns(self, code_text: str) -> list[str]:
        """
        检测代码中的安全防护模式。

        当代码使用了危险函数但同时存在安全防护措施时，
        降低风险评分以减少误报。

        Args:
            code_text: 代码文本

        Returns:
            检测到的安全模式名称列表
        """
        found = []
        for name, pattern in self.SAFE_PATTERNS.items():
            if re.search(pattern, code_text, re.IGNORECASE):
                found.append(name)
        return found

    # 命令执行类函数（受 escapeshellarg/cmd 保护后风险大幅降低）
    CMD_EXEC_FUNCS = {"system", "exec", "shell_exec", "passthru", "proc_open", "popen", "pcntl_exec"}

    def _has_shell_escaping(self, code_text: str) -> bool:
        """检测是否使用了 escapeshellarg/escapeshellcmd 命令注入防护"""
        return bool(re.search(r"\bescapeshell(arg|cmd)\s*\(", code_text, re.IGNORECASE))

    def _is_python_eval_sandboxed(self, code_text: str) -> bool:
        """
        检测 Python eval 是否在沙箱环境中使用。
        判据：__builtins__ 被禁用或限制了命名空间。
        """
        return bool(re.search(r'__builtins__["\']*\s*:\s*\{?\s*\}?', code_text) or
                     re.search(r'__builtins__\s*=\s*(?:None|\{\})', code_text))

    def _eval_input_from_file(self, code_text: str) -> bool:
        """
        检测 eval 的输入是否来自文件读取而非用户直接输入。
        当 eval 的参数是变量，且该变量最近被 file_get_contents 赋值时，
        认为是配置/文件驱动的 eval，风险低于用户输入驱动。
        """
        # 查找 eval($var) 模式
        eval_matches = re.finditer(r'\beval\s*\(\s*\$(\w+)\s*\)', code_text)
        for m in eval_matches:
            var_name = m.group(1)
            # 在 eval 之前查找该变量的赋值
            before_eval = code_text[:m.start()]
            pattern = rf'\${re.escape(var_name)}\s*=\s*(?:file_get_contents|file_get_contents\s*\()'
            if re.search(pattern, before_eval):
                return True
        return False

    def _assert_with_type_check(self, code_text: str) -> bool:
        """
        检测 assert 是否用于类型校验而非代码执行。
        判据：assert(is_xxx(...)) 模式，传入的是布尔表达式而非字符串。
        """
        # assert(is_string(...)), assert(is_numeric(...)), assert(is_array(...)) 等
        return bool(re.search(r'\bassert\s*\(\s*is_(?:string|numeric|int|integer|array|bool|float|long)\s*\(',
                              code_text))

    def _is_safe_string_concat(self, code_text: str) -> bool:
        """
        判断字符串拼接是否为安全模式（非函数名重构）。
        当拼接的变量不是危险函数名时，不视为混淆。
        """
        # 查找 $a.$b( 模式，检查拼接结果是否可能是危险函数名
        concat_matches = re.finditer(r'\$(\w+)\s*\.\s*\$(\w+)\s*\(', code_text)
        dangerous_names = {"eval", "system", "exec", "assert", "passthru", "shell_exec",
                          "base64_decode", "proc_open", "popen", "create_function"}
        for m in concat_matches:
            # 获取变量值（查找赋值）
            var1, var2 = m.group(1), m.group(2)
            before = code_text[:m.start()]
            val1 = re.search(rf'\${re.escape(var1)}\s*=\s*["\'](\w+)["\']', before)
            val2 = re.search(rf'\${re.escape(var2)}\s*=\s*["\'](\w+)["\']', before)
            if val1 and val2:
                combined = val1.group(1) + val2.group(1)
                if combined.lower() in dangerous_names:
                    return False  # 是危险函数名重构
            # 如果无法确定变量值，也不视为混淆（保守策略：减少误报）
        return True

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

        # 上下文安全检测
        has_shell_escape = self._has_shell_escaping(code_text)
        py_eval_sandboxed = self._is_python_eval_sandboxed(code_text) if language == "python" else False
        eval_from_file = self._eval_input_from_file(code_text)
        assert_type_check = self._assert_with_type_check(code_text)

        # 危险函数 + 用户输入 = 高危（但需结合上下文调整）
        high_risk_functions = {"eval", "assert", "system", "exec", "shell_exec",
                               "passthru", "proc_open", "popen", "pcntl_exec"}
        scored_funcs = set()  # 防止同一函数被多个模式重复计分
        for func in dangerous_found:
            func_base = func.replace("python_", "").replace("preg_replace_eval", "eval")
            if func_base in scored_funcs:
                continue  # 已计分，跳过
            scored_funcs.add(func_base)
            if func_base in high_risk_functions or func in high_risk_functions:
                # 上下文安全减免
                is_cmd_exec = func_base in self.CMD_EXEC_FUNCS
                is_assert_check = func_base == "assert" and assert_type_check
                is_eval_sandboxed = func_base == "eval" and py_eval_sandboxed
                is_eval_file = func_base == "eval" and eval_from_file

                if is_assert_check:
                    # assert 用于类型校验，风险极低
                    total_score += 0.1
                    indicators.append(f"{func_base}() [类型校验模式]")
                    rules_triggered.append(f"safe_assert:{func_base}")
                elif is_cmd_exec and has_shell_escape:
                    # 命令执行 + escapeshellarg 保护，风险大幅降低
                    score = self.RULE_WEIGHTS.get(f"{func_base}_no_input", 0.4) * 0.2
                    total_score += score
                    indicators.append(f"{func_base}() + escapeshellarg 保护")
                    rules_triggered.append(f"mitigated_cmd:{func_base}")
                elif is_eval_sandboxed:
                    # Python eval 在沙箱中，风险降低
                    total_score += 0.2
                    indicators.append(f"{func_base}() [沙箱环境]")
                    rules_triggered.append(f"sandboxed_eval:{func_base}")
                elif is_eval_file:
                    # eval 输入来自文件/配置，非用户直接输入
                    score = self.RULE_WEIGHTS.get(f"{func_base}_no_input", 0.4)
                    total_score += score
                    indicators.append(f"{func_base}() [文件驱动]")
                    rules_triggered.append(f"file_driven_eval:{func_base}")
                elif user_input_found:
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

        # base64 + 代码执行函数 组合
        has_base64 = bool(re.search(r"base64_decode\s*\(", code_text, re.IGNORECASE) or
                         re.search(r"base64\.b64decode\s*\(", code_text, re.IGNORECASE))
        has_eval = bool(re.search(r"\beval\s*\(", code_text, re.IGNORECASE))
        has_exec = bool(re.search(r"\bexec\s*\(", code_text, re.IGNORECASE))

        if has_base64 and (has_eval or has_exec):
            total_score += self.RULE_WEIGHTS["base64_decode_eval"]
            indicators.append("base64_decode + eval/exec 组合")
            rules_triggered.append("obfuscation:base64_eval")
            obfuscation_detected = "base64"
        elif has_base64:
            total_score += self.RULE_WEIGHTS["base64_decode_only"]
            indicators.append("base64_decode")
            rules_triggered.append("obfuscation:base64")
            obfuscation_detected = "base64"

        # 字符串拆分检测
        # 模式0-1：变量拼接（需安全检查避免误报）
        # 模式2-3：字符串字面量拼接（几乎总是混淆）
        # 模式4-5：str_replace/implode 重构（仅当存在危险函数时检测）
        string_split_patterns = self.OBFUSCATION_RULES["string_split"]
        
        # 先检查字符串字面量拼接模式（高置信度，不需要安全检查）
        for pattern in string_split_patterns[2:4]:
            if re.search(pattern, code_text):
                total_score += self.RULE_WEIGHTS["string_split_func"]
                indicators.append("字符串拼接还原函数名")
                rules_triggered.append("obfuscation:string_split")
                obfuscation_detected = "string_split"
                break
        
        # 再检查变量拼接模式（需安全检查）
        if obfuscation_detected == "none" and not self._is_safe_string_concat(code_text):
            for pattern in string_split_patterns[:2]:
                if re.search(pattern, code_text):
                    total_score += self.RULE_WEIGHTS["string_split_func"]
                    indicators.append("字符串拼接还原函数名")
                    rules_triggered.append("obfuscation:string_split")
                    obfuscation_detected = "string_split"
                    break
        
        # 最后检查 str_replace/implode 模式（仅当存在危险函数时）
        if obfuscation_detected == "none" and dangerous_found:
            for pattern in string_split_patterns[4:]:
                if re.search(pattern, code_text):
                    total_score += self.RULE_WEIGHTS["string_split_func"]
                    indicators.append("str_replace/implode 函数名重构")
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
            # 仅当同时存在危险函数时才计分，避免框架文件操作误报
            if dangerous_found:
                total_score += self.RULE_WEIGHTS["file_management"]
                indicators.append(f"文件管理功能 ({file_mgmt_count} 个)")
            else:
                total_score += 0.05
        elif file_mgmt_count >= 1:
            if dangerous_found:
                total_score += 0.1
                indicators.append("文件操作函数")

        # ---- 5.5 安全模式检测（降低误报）----
        # 检测代码中是否存在安全防护措施，存在则降低风险评分
        safe_patterns = self._detect_safe_patterns(code_text)
        if safe_patterns:
            # 当检测到混淆技术时，输出编码类安全模式（htmlspecialchars/filter_var）
            # 不减免分数，因为输出编码不能缓解代码执行漏洞
            if obfuscation_detected != "none":
                input_validation_patterns = {
                    "escapeshellarg", "escapeshellcmd", "prepared_stmt",
                    "whitelist_check", "type_check", "realpath_check", "token_verify"
                }
                effective_safe = [p for p in safe_patterns if p in input_validation_patterns]
            else:
                effective_safe = safe_patterns
            
            if effective_safe:
                reduction = min(0.15 * len(effective_safe), 0.4)
                total_score -= reduction
                indicators.append(f"安全模式 ({', '.join(effective_safe)})")

        # 如果危险函数存在但无用户输入，降低评分（框架代码常见模式）
        # 但检测到混淆技术时不降低（混淆本身是恶意特征）
        if dangerous_found and not user_input_found and obfuscation_detected == "none":
            total_score *= 0.5  # 无用户输入的危险函数风险减半

        # ---- 6. 综合判定 ----
        # 归一化分数（上限 1.0，下限 0.0）
        confidence = max(0.0, min(total_score, 1.0))

        # 判定阈值（从0.5提高到0.6，降低误报率）
        if confidence >= 0.6:
            label = "malicious"
            if sqli_indicators and not dangerous_found and obfuscation_detected == "none":
                malware_type = "sqli"
            elif any("backdoor" in r for r in rules_triggered):
                malware_type = "backdoor"
            else:
                malware_type = "webshell"

            if confidence >= 0.8:
                risk_level = "high"
            elif confidence >= 0.6:
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
