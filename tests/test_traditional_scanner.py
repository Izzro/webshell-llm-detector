"""
TraditionalScanner 单元测试

测试要点：
- 恶意样本检测（PHP一句话木马、Python后门、SQL注入）
- 良性样本不误报
- 混淆样本检测（base64、string_split、xor、comment_bypass）
- 空输入处理
- 安全模式减免（escapeshellarg、assert类型校验、eval沙箱）

注意：所有测试用例使用最小化的模式片段，仅触发扫描器的正则匹配，
不包含可执行的完整恶意代码。
"""

import pytest
from src.traditional_scanner import TraditionalScanner, ScanResult


@pytest.fixture
def scanner():
    """创建扫描器实例。"""
    return TraditionalScanner()


# ================================================================
# 恶意样本检测
# ================================================================

class TestMaliciousDetection:
    """测试恶意样本的检测能力。"""

    def test_php_webshell_oneliner(self, scanner):
        """测试 PHP 一句话木马模式检测。"""
        # 最小化模式片段：eval + $_POST 组合触发高危规则
        code = "<?php eval($_POST['x']); ?>"
        result = scanner.scan(code, language="php")

        assert result.label == "malicious"
        assert result.malware_type == "webshell"
        assert result.confidence >= 0.6
        assert result.risk_level in ("high", "medium")
        # 应触发危险函数 + 用户输入规则
        assert any("eval" in r for r in result.rules_triggered)

    def test_php_webshell_with_error_suppression(self, scanner):
        """测试带 @ 错误抑制的 PHP 一句话木马。"""
        code = "<?php @eval($_POST['cmd']); ?>"
        result = scanner.scan(code, language="php")

        assert result.label == "malicious"
        assert result.malware_type == "webshell"
        assert result.confidence >= 0.8

    def test_python_backdoor_os_system(self, scanner):
        """测试 Python 后门：os.system + input 组合。"""
        code = "import os\nresult = os.system(input('cmd: '))"
        result = scanner.scan(code, language="python")

        assert result.label == "malicious"
        assert result.confidence >= 0.6
        # system 模式应被触发（\bsystem\s*\( 匹配 os.system(）
        assert any("system" in r for r in result.rules_triggered)

    def test_python_backdoor_exec_argv(self, scanner):
        """测试 Python 后门：exec + sys.argv 组合。"""
        code = (
            "import sys\n"
            "exec(sys.argv[1])"
        )
        result = scanner.scan(code, language="python")

        assert result.label == "malicious"
        assert result.confidence >= 0.6
        # exec + 用户输入应触发高危规则
        assert any("exec" in r for r in result.rules_triggered)

    def test_sqli_union_select(self, scanner):
        """测试 SQL 注入：UNION SELECT 载荷。"""
        code = "1 UNION SELECT username FROM users"
        result = scanner.scan(code, language="sql")

        assert result.label == "malicious"
        assert result.malware_type == "sqli"
        assert result.confidence >= 0.6
        assert any("sqli" in r for r in result.rules_triggered)

    def test_sqli_time_based(self, scanner):
        """测试 SQL 注入：时间盲注。"""
        code = "1 AND SLEEP(5)"
        result = scanner.scan(code, language="sql")

        assert result.label == "malicious"
        assert result.malware_type == "sqli"

    def test_sqli_boolean_blind(self, scanner):
        """测试 SQL 注入：布尔盲注。"""
        code = "1 AND 1=1"
        result = scanner.scan(code, language="sql")

        assert result.label == "malicious"
        assert result.malware_type == "sqli"

    def test_backdoor_fsockopen(self, scanner):
        """测试后门：fsockopen 反向连接。"""
        code = "$fp = fsockopen('127.0.0.1', 4444);"
        result = scanner.scan(code, language="php")

        assert result.label == "malicious"
        assert result.malware_type == "backdoor"


# ================================================================
# 良性样本不误报
# ================================================================

class TestBenignNoFalsePositive:
    """测试良性样本不产生误报。"""

    def test_benign_php_calculate(self, scanner):
        """测试良性 PHP 计算函数。"""
        code = (
            "<?php\n"
            "function calculateTotal($items) {\n"
            "    $total = 0;\n"
            "    foreach ($items as $item) {\n"
            "        $total += $item['price'];\n"
            "    }\n"
            "    return $total;\n"
            "}\n"
            "?>"
        )
        result = scanner.scan(code, language="php")

        assert result.label == "benign"
        assert result.confidence < 0.6
        assert result.malware_type == "none"

    def test_benign_python_greet(self, scanner):
        """测试良性 Python 函数。"""
        code = (
            "def greet(name):\n"
            '    message = "Hello, " + name\n'
            "    return message\n"
        )
        result = scanner.scan(code, language="python")

        assert result.label == "benign"
        assert result.confidence < 0.6

    def test_benign_php_html_output(self, scanner):
        """测试良性 PHP HTML 输出（含 htmlspecialchars 安全模式）。"""
        code = (
            "<?php\n"
            "$name = $_GET['name'];\n"
            "echo htmlspecialchars($name);\n"
            "?>"
        )
        result = scanner.scan(code, language="php")

        assert result.label == "benign"
        # htmlspecialchars 应触发安全模式减免
        assert any("安全模式" in ind for ind in result.indicators) or result.confidence < 0.6

    def test_benign_php_pdo_prepared(self, scanner):
        """测试良性 PHP PDO 预处理语句。"""
        code = (
            "<?php\n"
            "$pdo = new PDO('mysql:host=localhost', 'user', 'pass');\n"
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
            "$stmt->bindParam(':id', $id);\n"
            "$stmt->execute();\n"
            "?>"
        )
        result = scanner.scan(code, language="php")

        # PDO 预处理语句不应被判为恶意
        assert result.label == "benign"

    def test_benign_empty_namespace(self, scanner):
        """测试良性 PHP 命名空间声明。"""
        code = (
            "<?php\n"
            "namespace App\\Controllers;\n"
            "use App\\Models\\User;\n"
            "class UserController {\n"
            "    public function index() {\n"
            "        return User::all();\n"
            "    }\n"
            "}\n"
            "?>"
        )
        result = scanner.scan(code, language="php")

        assert result.label == "benign"


# ================================================================
# 混淆样本检测
# ================================================================

class TestObfuscationDetection:
    """测试各种混淆技术的检测。"""

    def test_base64_obfuscation(self, scanner):
        """测试 base64 混淆检测。"""
        # 模式片段：base64_decode + eval 组合
        code = '<?php $x="dGVzdA==";eval(base64_decode($x)); ?>'
        result = scanner.scan(code, language="php")

        assert result.label == "malicious"
        assert result.obfuscation == "base64"
        assert result.confidence >= 0.6

    def test_base64_python_obfuscation(self, scanner):
        """测试 Python base64 混淆检测。"""
        code = (
            "import base64\n"
            "payload = base64.b64decode('aGVsbG8=')\n"
            "exec(payload)"
        )
        result = scanner.scan(code, language="python")

        assert result.label == "malicious"
        assert result.obfuscation == "base64"

    def test_string_split_obfuscation(self, scanner):
        """测试字符串拆分混淆检测。"""
        # 模式片段：变量拼接还原函数名
        code = '$a="ev";$b="al";$a.$b($_POST["x"]);'
        result = scanner.scan(code, language="php")

        assert result.label == "malicious"
        assert result.obfuscation == "string_split"
        assert result.confidence >= 0.6

    def test_string_split_literal_concat(self, scanner):
        """测试字符串字面量拼接混淆检测。"""
        # 字符串字面量拼接（高置信度模式）
        code = "('ev'.'al')($_POST['x']);"
        result = scanner.scan(code, language="php")

        assert result.label == "malicious"
        assert result.obfuscation == "string_split"

    def test_xor_obfuscation(self, scanner):
        """测试 XOR 异或混淆检测。"""
        # 模式片段：常量间 XOR 运算（PHP 变量 $ 前缀不匹配 \b\w+，
        # 使用常量名确保正则 \b\w+\s*\^\s*\w+ 能匹配）
        code = '$payload = PAYLOAD ^ SECRET_KEY;'
        result = scanner.scan(code, language="php")

        assert result.label == "malicious"
        assert result.obfuscation == "xor"
        assert result.confidence >= 0.6

    def test_xor_python_obfuscation(self, scanner):
        """测试 Python XOR 混淆检测。"""
        code = "c = [a[i] ^ b[i] for i in range(len(a))]"
        result = scanner.scan(code, language="python")

        assert result.label == "malicious"
        assert result.obfuscation == "xor"

    def test_comment_bypass_obfuscation(self, scanner):
        """测试注释绕过混淆检测。"""
        # 模式片段：注释穿插打断关键词
        code = 'ev/**/al($_POST["x"]);'
        result = scanner.scan(code, language="php")

        assert result.label == "malicious"
        assert result.obfuscation == "comment_bypass"
        assert result.confidence >= 0.6


# ================================================================
# 空输入处理
# ================================================================

class TestEmptyInput:
    """测试空输入和异常输入的处理。"""

    def test_empty_string(self, scanner):
        """测试空字符串输入。"""
        result = scanner.scan("", language="php")

        assert result.label == "benign"
        assert result.confidence == 0.0
        assert "空" in result.reason

    def test_whitespace_only(self, scanner):
        """测试纯空白输入。"""
        result = scanner.scan("   \n\t  \n", language="php")

        assert result.label == "benign"
        assert result.confidence == 0.0

    def test_none_input(self, scanner):
        """测试 None 输入（应安全处理）。"""
        result = scanner.scan(None, language="php")

        assert result.label == "benign"
        assert result.confidence == 0.0

    def test_empty_input_has_no_indicators(self, scanner):
        """测试空输入不触发任何规则。"""
        result = scanner.scan("", language="php")

        assert result.indicators == []
        assert result.rules_triggered == []


# ================================================================
# 安全模式减免
# ================================================================

class TestSafeModeMitigation:
    """测试安全模式对误报的减免效果。"""

    def test_system_with_escapeshellarg(self, scanner):
        """测试 system + escapeshellarg 保护：风险应大幅降低。"""
        code = (
            "<?php\n"
            "$dir = '/var/log';\n"
            "system('ls ' . escapeshellarg($dir));\n"
            "?>"
        )
        result = scanner.scan(code, language="php")

        # escapeshellarg 保护 + 无用户输入 → 应判定为良性
        assert result.label == "benign"
        assert result.confidence < 0.6

    def test_assert_type_check(self, scanner):
        """测试 assert 用于类型校验：风险极低。"""
        code = (
            "<?php\n"
            "function validate($input) {\n"
            "    assert(is_string($input));\n"
            "    assert(is_numeric($input));\n"
            "    return true;\n"
            "}\n"
            "?>"
        )
        result = scanner.scan(code, language="php")

        # assert(is_xxx()) 模式 → 类型校验，低风险
        assert result.label == "benign"
        assert result.confidence < 0.6

    def test_eval_in_sandbox(self, scanner):
        """测试 Python eval 在沙箱中使用：风险降低。"""
        code = (
            "result = eval('1 + 2', "
            "{'__builtins__': {}}, {})"
        )
        result = scanner.scan(code, language="python")

        # __builtins__ 被禁用 → 沙箱环境，风险降低
        assert result.label == "benign"
        assert result.confidence < 0.6

    def test_eval_from_file(self, scanner):
        """测试 eval 输入来自文件读取：风险低于用户输入。"""
        code = (
            "<?php\n"
            "$config = file_get_contents('config.php');\n"
            "eval($config);\n"
            "?>"
        )
        result = scanner.scan(code, language="php")

        # eval 输入来自 file_get_contents → 文件驱动，降低评分
        # 但仍有风险，不应为高危
        assert result.confidence < 0.8

    def test_safe_string_concat_not_flagged(self, scanner):
        """测试安全字符串拼接不误报为混淆。"""
        # 非危险函数名的拼接不应触发 string_split
        code = (
            '<?php\n'
            '$prefix = "get";\n'
            '$suffix = "Name";\n'
            '$method = $prefix . $suffix;\n'
            '$name = $method();\n'
            '?>'
        )
        result = scanner.scan(code, language="php")

        # 拼接结果 "getName" 不是危险函数名 → 不应标记为 string_split 混淆
        assert result.obfuscation != "string_split"

    def test_prepared_statement_reduces_risk(self, scanner):
        """测试预处理语句减免 SQL 注入误报。"""
        code = (
            "<?php\n"
            "$pdo = new PDO('mysql:host=localhost', 'root', '');\n"
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n"
            "$stmt->execute([$_GET['id']]);\n"
            "?>"
        )
        result = scanner.scan(code, language="php")

        # PDO prepare 应触发安全模式减免
        assert result.label == "benign"


# ================================================================
# ScanResult 结构验证
# ================================================================

class TestScanResultStructure:
    """测试 ScanResult 数据结构的完整性。"""

    def test_result_has_all_fields(self, scanner):
        """测试返回结果包含所有必需字段。"""
        result = scanner.scan("eval($_POST['x']);", language="php")

        assert hasattr(result, "label")
        assert hasattr(result, "malware_type")
        assert hasattr(result, "subtype")
        assert hasattr(result, "obfuscation")
        assert hasattr(result, "confidence")
        assert hasattr(result, "risk_level")
        assert hasattr(result, "reason")
        assert hasattr(result, "indicators")
        assert hasattr(result, "rules_triggered")

    def test_confidence_in_range(self, scanner):
        """测试置信度在 [0.0, 1.0] 范围内。"""
        test_cases = [
            ("eval($_POST['x']);", "php"),
            ("def hello(): pass", "python"),
            ("", "php"),
            ("1 UNION SELECT x FROM y", "sql"),
        ]
        for code, lang in test_cases:
            result = scanner.scan(code, language=lang)
            assert 0.0 <= result.confidence <= 1.0, (
                f"confidence={result.confidence} 超出范围 (code={code[:30]})"
            )

    def test_obfuscation_only_when_malicious(self, scanner):
        """测试良性结果的 obfuscation 字段为 none。"""
        result = scanner.scan("def add(a, b): return a + b", language="python")
        assert result.obfuscation == "none"

    def test_default_language_unknown(self, scanner):
        """测试默认语言参数为 unknown。"""
        # 不传 language 参数，应使用默认值 "unknown"
        result = scanner.scan("eval($_POST['x']);")
        assert result.label == "malicious"
