"""
MetricsCalculator 单元测试

测试要点：
- 准确率 Accuracy 计算
- 精确率 Precision 计算
- 召回率 Recall 计算
- F1 分数计算
- 未分类（unknown）样本统计
- 混淆识别率（obfuscation_recall）
- 分类一致性（type_consistency）
- 延迟和 Token 统计
- 空输入和长度不一致处理
"""

import pytest
from src.metrics import MetricsCalculator


@pytest.fixture
def calc():
    """创建指标计算器实例。"""
    return MetricsCalculator()


# ================================================================
# 准确率
# ================================================================

class TestAccuracy:
    """测试准确率计算。"""

    def test_perfect_accuracy(self, calc):
        """测试全部预测正确时准确率为 1.0。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["accuracy"] == 1.0
        assert result["tp"] == 1
        assert result["tn"] == 1
        assert result["fp"] == 0
        assert result["fn"] == 0

    def test_zero_accuracy(self, calc):
        """测试全部预测错误时准确率为 0.0。"""
        predictions = [
            {"label": "benign"},
            {"label": "malicious"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["accuracy"] == 0.0
        assert result["tp"] == 0
        assert result["tn"] == 0
        assert result["fp"] == 1
        assert result["fn"] == 1

    def test_half_accuracy(self, calc):
        """测试一半正确时准确率为 0.5。"""
        predictions = [
            {"label": "malicious"},
            {"label": "malicious"},
            {"label": "benign"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["accuracy"] == 0.5
        assert result["tp"] == 1
        assert result["tn"] == 1
        assert result["fp"] == 1
        assert result["fn"] == 1

    def test_empty_predictions_accuracy(self, calc):
        """测试空输入时准确率为 0.0（不报错）。"""
        result = calc.calculate([], [])

        assert result["accuracy"] == 0.0
        assert result["total_samples"] == 0


# ================================================================
# 精确率
# ================================================================

class TestPrecision:
    """测试精确率计算。"""

    def test_perfect_precision(self, calc):
        """测试无误报时精确率为 1.0。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["precision"] == 1.0

    def test_zero_precision(self, calc):
        """测试全部误报时精确率为 0.0。"""
        predictions = [
            {"label": "malicious"},
            {"label": "malicious"},
        ]
        true_labels = [
            {"label": "benign"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["precision"] == 0.0
        assert result["fp"] == 2
        assert result["tp"] == 0

    def test_half_precision(self, calc):
        """测试一半误报时精确率为 0.5。"""
        predictions = [
            {"label": "malicious"},
            {"label": "malicious"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["precision"] == 0.5

    def test_no_positive_predictions(self, calc):
        """测试无正预测时精确率为 0.0（避免除零）。"""
        predictions = [
            {"label": "benign"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["precision"] == 0.0


# ================================================================
# 召回率
# ================================================================

class TestRecall:
    """测试召回率计算。"""

    def test_perfect_recall(self, calc):
        """测试无漏报时召回率为 1.0。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["recall"] == 1.0

    def test_zero_recall(self, calc):
        """测试全部漏报时召回率为 0.0。"""
        predictions = [
            {"label": "benign"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "malicious"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["recall"] == 0.0
        assert result["fn"] == 2
        assert result["tp"] == 0

    def test_half_recall(self, calc):
        """测试一半漏报时召回率为 0.5。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "malicious"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["recall"] == 0.5

    def test_no_true_positives_recall(self, calc):
        """测试无真实恶意样本时召回率为 0.0（避免除零）。"""
        predictions = [
            {"label": "benign"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "benign"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["recall"] == 0.0


# ================================================================
# F1 分数
# ================================================================

class TestF1:
    """测试 F1 分数计算。"""

    def test_perfect_f1(self, calc):
        """测试完美预测时 F1 为 1.0。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["f1"] == 1.0

    def test_zero_f1(self, calc):
        """测试全部错误时 F1 为 0.0。"""
        predictions = [
            {"label": "benign"},
            {"label": "malicious"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["f1"] == 0.0

    def test_balanced_f1(self, calc):
        """测试 P=R=0.5 时 F1=0.5。"""
        predictions = [
            {"label": "malicious"},
            {"label": "malicious"},
            {"label": "benign"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["f1"] == 0.5

    def test_f1_zero_when_precision_and_recall_zero(self, calc):
        """测试 P=0 且 R=0 时 F1=0.0（避免除零）。"""
        predictions = [
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["f1"] == 0.0


# ================================================================
# 未分类样本统计
# ================================================================

class TestUnclassified:
    """测试 unknown 预测的统计。"""

    def test_unknown_count(self, calc):
        """测试 unknown 预测被计入 unclassified。"""
        predictions = [
            {"label": "unknown"},
            {"label": "unknown"},
            {"label": "malicious"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
            {"label": "malicious"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["unclassified"] == 2

    def test_unknown_malicious_counts_as_fn(self, calc):
        """测试 unknown + 真实恶意 → 计入 FN（漏报）。"""
        predictions = [{"label": "unknown"}]
        true_labels = [{"label": "malicious"}]
        result = calc.calculate(predictions, true_labels)

        assert result["fn"] == 1
        assert result["unclassified"] == 1

    def test_unknown_benign_counts_as_tn(self, calc):
        """测试 unknown + 真实良性 → 计入 TN（未误报）。"""
        predictions = [{"label": "unknown"}]
        true_labels = [{"label": "benign"}]
        result = calc.calculate(predictions, true_labels)

        assert result["tn"] == 1
        assert result["unclassified"] == 1

    def test_no_unknown_when_all_classified(self, calc):
        """测试全部已分类时 unclassified=0。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["unclassified"] == 0


# ================================================================
# 混淆识别率
# ================================================================

class TestObfuscationRecall:
    """测试混淆样本识别率。"""

    def test_all_obfuscated_detected(self, calc):
        """测试所有混淆样本都被检出时 recall=1.0。"""
        predictions = [
            {"label": "malicious"},
            {"label": "malicious"},
        ]
        true_labels = [
            {"label": "malicious", "obfuscation": "base64"},
            {"label": "malicious", "obfuscation": "xor"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["obfuscation_recall"] == 1.0
        assert result["obf_total"] == 2
        assert result["obf_correct"] == 2

    def test_half_obfuscated_detected(self, calc):
        """测试一半混淆样本被检出时 recall=0.5。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious", "obfuscation": "base64"},
            {"label": "malicious", "obfuscation": "xor"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["obfuscation_recall"] == 0.5
        assert result["obf_total"] == 2
        assert result["obf_correct"] == 1

    def test_obf_by_type(self, calc):
        """测试按混淆类型分组的识别率。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
            {"label": "malicious"},
        ]
        true_labels = [
            {"label": "malicious", "obfuscation": "base64"},
            {"label": "malicious", "obfuscation": "xor"},
            {"label": "malicious", "obfuscation": "base64"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["obf_by_type"]["base64"] == 1.0
        assert result["obf_by_type"]["xor"] == 0.0

    def test_no_obfuscated_samples(self, calc):
        """测试无混淆样本时 recall=0.0。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious", "obfuscation": "none"},
            {"label": "benign", "obfuscation": "none"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["obfuscation_recall"] == 0.0
        assert result["obf_total"] == 0


# ================================================================
# 分类一致性
# ================================================================

class TestTypeConsistency:
    """测试恶意类型标注准确性。"""

    def test_perfect_type_consistency(self, calc):
        """测试所有恶意样本类型预测正确时一致性为 1.0。"""
        predictions = [
            {"label": "malicious", "malware_type": "webshell"},
            {"label": "malicious", "malware_type": "sqli"},
        ]
        true_labels = [
            {"label": "malicious", "malware_type": "webshell"},
            {"label": "malicious", "malware_type": "sqli"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["type_consistency"] == 1.0

    def test_half_type_consistency(self, calc):
        """测试一半类型预测正确时一致性为 0.5。"""
        predictions = [
            {"label": "malicious", "malware_type": "webshell"},
            {"label": "malicious", "malware_type": "sqli"},
        ]
        true_labels = [
            {"label": "malicious", "malware_type": "webshell"},
            {"label": "malicious", "malware_type": "webshell"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["type_consistency"] == 0.5

    def test_type_consistency_with_fn(self, calc):
        """测试有漏报时 type_consistency 分母包含 FN。"""
        predictions = [
            {"label": "malicious", "malware_type": "webshell"},
            {"label": "benign", "malware_type": "none"},
        ]
        true_labels = [
            {"label": "malicious", "malware_type": "webshell"},
            {"label": "malicious", "malware_type": "webshell"},
        ]
        result = calc.calculate(predictions, true_labels)

        # malicious_total = TP + FN = 1 + 1 = 2
        # type_correct = 1 (first sample matches)
        assert result["type_consistency"] == 0.5

    def test_no_malicious_samples(self, calc):
        """测试无恶意样本时 type_consistency=0.0。"""
        predictions = [
            {"label": "benign"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "benign"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["type_consistency"] == 0.0


# ================================================================
# 延迟和 Token 统计
# ================================================================

class TestLatencyAndTokens:
    """测试延迟和 Token 消耗统计。"""

    def test_avg_latency(self, calc):
        """测试平均延迟计算。"""
        predictions = [
            {"label": "malicious", "latency_ms": 100},
            {"label": "benign", "latency_ms": 200},
            {"label": "malicious", "latency_ms": 300},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
            {"label": "malicious"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["avg_latency_ms"] == 200.0
        assert result["max_latency_ms"] == 300
        assert result["min_latency_ms"] == 100

    def test_total_tokens(self, calc):
        """测试 Token 总量计算。"""
        predictions = [
            {"label": "malicious", "total_tokens": 500},
            {"label": "benign", "total_tokens": 300},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["total_tokens"] == 800
        assert result["avg_tokens"] == 400.0

    def test_no_latency_data(self, calc):
        """测试无延迟数据时不报错。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["avg_latency_ms"] == 0.0
        assert result["max_latency_ms"] == 0
        assert result["min_latency_ms"] == 0
        assert result["total_tokens"] == 0
        assert result["avg_tokens"] == 0.0


# ================================================================
# 边界情况
# ================================================================

class TestEdgeCases:
    """测试边界情况。"""

    def test_empty_lists(self, calc):
        """测试空列表输入。"""
        result = calc.calculate([], [])

        assert result["total_samples"] == 0
        assert result["accuracy"] == 0.0
        assert result["precision"] == 0.0
        assert result["recall"] == 0.0
        assert result["f1"] == 0.0
        assert result["tp"] == 0
        assert result["tn"] == 0
        assert result["fp"] == 0
        assert result["fn"] == 0
        assert result["unclassified"] == 0

    def test_mismatched_lengths(self, calc):
        """测试预测和标签长度不一致（按较短长度计算）。"""
        predictions = [
            {"label": "malicious"},
            {"label": "benign"},
            {"label": "malicious"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        # 应按较短长度（2）计算，全部正确
        assert result["accuracy"] == 1.0
        # total_samples 使用 predictions 的长度
        assert result["total_samples"] == 3

    def test_single_sample_correct(self, calc):
        """测试单条样本预测正确。"""
        predictions = [{"label": "malicious", "malware_type": "webshell"}]
        true_labels = [{"label": "malicious", "malware_type": "webshell"}]
        result = calc.calculate(predictions, true_labels)

        assert result["accuracy"] == 1.0
        assert result["tp"] == 1
        assert result["type_consistency"] == 1.0

    def test_single_sample_wrong(self, calc):
        """测试单条样本预测错误。"""
        predictions = [{"label": "benign"}]
        true_labels = [{"label": "malicious"}]
        result = calc.calculate(predictions, true_labels)

        assert result["accuracy"] == 0.0
        assert result["fn"] == 1

    def test_all_malicious_correct(self, calc):
        """测试全部恶意样本被正确检出。"""
        predictions = [
            {"label": "malicious", "malware_type": "webshell"},
            {"label": "malicious", "malware_type": "backdoor"},
            {"label": "malicious", "malware_type": "sqli"},
        ]
        true_labels = [
            {"label": "malicious", "malware_type": "webshell"},
            {"label": "malicious", "malware_type": "backdoor"},
            {"label": "malicious", "malware_type": "sqli"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["accuracy"] == 1.0
        assert result["recall"] == 1.0
        assert result["tp"] == 3
        assert result["type_consistency"] == 1.0

    def test_all_benign_correct(self, calc):
        """测试全部良性样本被正确判定。"""
        predictions = [
            {"label": "benign"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "benign"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        assert result["accuracy"] == 1.0
        assert result["tn"] == 2
        assert result["fp"] == 0


# ================================================================
# 返回值结构验证
# ================================================================

class TestResultStructure:
    """测试返回值包含所有必需字段。"""

    def test_result_has_all_keys(self, calc):
        """测试返回字典包含所有必需的键。"""
        result = calc.calculate(
            [{"label": "malicious"}],
            [{"label": "malicious"}],
        )

        expected_keys = {
            "total_samples", "accuracy", "precision", "recall", "f1",
            "tp", "tn", "fp", "fn", "unclassified",
            "obfuscation_recall", "obf_total", "obf_correct", "obf_by_type",
            "type_consistency", "avg_latency_ms", "max_latency_ms",
            "min_latency_ms", "total_tokens", "avg_tokens",
        }
        assert expected_keys.issubset(result.keys())

    def test_metrics_are_rounded(self, calc):
        """测试指标值被四舍五入到4位小数。"""
        predictions = [
            {"label": "malicious"},
            {"label": "malicious"},
            {"label": "benign"},
        ]
        true_labels = [
            {"label": "malicious"},
            {"label": "benign"},
            {"label": "benign"},
        ]
        result = calc.calculate(predictions, true_labels)

        # precision = 1/2 = 0.5, 应为4位小数
        assert result["precision"] == 0.5
        # accuracy = 2/3 = 0.6667 (rounded to 4 decimal places)
        assert result["accuracy"] == round(2 / 3, 4)
