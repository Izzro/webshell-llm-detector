"""
SampleLoader 单元测试

测试要点：
- 样本加载（从 CSV 加载标签索引）
- 标签匹配（0→benign, 1→malicious）
- 分类过滤（category / obfuscation）
- 语言映射（PHP→php, Python→python, Text→sql）
- 文件内容读取
- 缺失文件处理
- labels.csv 不存在时的错误处理

使用 tmp_path fixture 创建临时 CSV 和样本文件，不依赖项目实际数据。
"""

import os
import csv
import pytest
from src.sample_loader import SampleLoader, Sample


# ================================================================
# 测试辅助函数
# ================================================================

def create_labels_csv(base_dir, rows):
    """在 base_dir 下创建 labels.csv 文件。

    Args:
        base_dir: 基础目录路径
        rows: CSV 行数据列表，每行为 dict

    Returns:
        labels.csv 的完整路径
    """
    csv_path = os.path.join(base_dir, "labels.csv")
    fieldnames = ["file_path", "filename", "category", "subcategory",
                  "label", "language", "file_size"]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return csv_path


def create_sample_file(base_dir, relative_path, content="sample code"):
    """在 base_dir 下创建样本文件。

    Args:
        base_dir: 基础目录路径
        relative_path: 相对于 base_dir 的文件路径
        content: 文件内容

    Returns:
        样本文件的完整路径
    """
    full_path = os.path.join(base_dir, relative_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content)
    return full_path


@pytest.fixture
def sample_data(tmp_path):
    """创建测试用的样本数据和 CSV 文件。

    在 tmp_path 下创建：
    - labels.csv（4 条样本记录）
    - 4 个样本文件（benign/webshell/obfuscated/sqli 各一个）
    """
    rows = [
        {
            "file_path": "samples/benign/test_benign.py",
            "filename": "test_benign.py",
            "category": "benign",
            "subcategory": "flask",
            "label": "0",
            "language": "Python",
            "file_size": "50",
        },
        {
            "file_path": "samples/webshell/test_shell.php",
            "filename": "test_shell.php",
            "category": "webshell",
            "subcategory": "php",
            "label": "1",
            "language": "PHP",
            "file_size": "100",
        },
        {
            "file_path": "samples/obfuscated/base64/test_obf.php",
            "filename": "test_obf.php",
            "category": "obfuscated",
            "subcategory": "base64",
            "label": "1",
            "language": "PHP",
            "file_size": "200",
        },
        {
            "file_path": "samples/sqli/test_sqli.txt",
            "filename": "test_sqli.txt",
            "category": "sqli",
            "subcategory": "sqli",
            "label": "1",
            "language": "Text",
            "file_size": "30",
        },
    ]
    csv_path = create_labels_csv(str(tmp_path), rows)

    # 创建样本文件
    create_sample_file(str(tmp_path), "samples/benign/test_benign.py",
                       "def hello():\n    return 'world'\n")
    create_sample_file(str(tmp_path), "samples/webshell/test_shell.php",
                       "<?php echo 'test'; ?>\n")
    create_sample_file(str(tmp_path), "samples/obfuscated/base64/test_obf.php",
                       "<?php $x='dGVzdA=='; ?>\n")
    create_sample_file(str(tmp_path), "samples/sqli/test_sqli.txt",
                       "1 UNION SELECT x FROM y\n")

    return {
        "base_dir": str(tmp_path),
        "csv_path": csv_path,
        "rows": rows,
    }


# ================================================================
# 标签加载
# ================================================================

class TestLoadLabels:
    """测试从 CSV 加载标签索引。"""

    def test_load_labels_returns_list(self, sample_data):
        """测试 load_labels 返回样本列表。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()

        assert isinstance(samples, list)
        assert len(samples) == 4

    def test_load_labels_caches(self, sample_data):
        """测试 load_labels 缓存：第二次调用返回缓存。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        first = loader.load_labels()
        second = loader.load_labels()

        assert first is second  # 同一对象引用

    def test_label_mapping_0_to_benign(self, sample_data):
        """测试 label=0 映射为 benign。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()

        benign_sample = next(s for s in samples if s.category == "benign")
        assert benign_sample.label == "benign"

    def test_label_mapping_1_to_malicious(self, sample_data):
        """测试 label=1 映射为 malicious。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()

        for s in samples:
            if s.category != "benign":
                assert s.label == "malicious"

    def test_malware_type_mapping(self, sample_data):
        """测试 malware_type 映射。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()

        by_cat = {s.category: s for s in samples}
        assert by_cat["benign"].malware_type == "none"
        assert by_cat["webshell"].malware_type == "webshell"
        assert by_cat["sqli"].malware_type == "sqli"
        assert by_cat["obfuscated"].malware_type == "webshell"

    def test_obfuscation_mapping(self, sample_data):
        """测试 obfuscation 映射。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()

        by_cat = {s.category: s for s in samples}
        # 非混淆样本 obfuscation 为 none
        assert by_cat["benign"].obfuscation == "none"
        assert by_cat["webshell"].obfuscation == "none"
        assert by_cat["sqli"].obfuscation == "none"
        # 混淆样本 obfuscation 为 subcategory
        assert by_cat["obfuscated"].obfuscation == "base64"

    def test_language_mapping(self, sample_data):
        """测试语言映射。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()

        by_cat = {s.category: s for s in samples}
        assert by_cat["benign"].language == "python"
        assert by_cat["webshell"].language == "php"
        assert by_cat["obfuscated"].language == "php"
        # Text → sql（.txt 文件均为 SQLi 载荷）
        assert by_cat["sqli"].language == "sql"

    def test_file_size_parsed(self, sample_data):
        """测试 file_size 被正确解析为整数。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()

        benign = next(s for s in samples if s.category == "benign")
        assert benign.file_size == 50
        assert isinstance(benign.file_size, int)

    def test_file_path_stored(self, sample_data):
        """测试 file_path 被正确存储。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()

        benign = next(s for s in samples if s.category == "benign")
        assert "test_benign.py" in benign.file_path

    def test_csv_not_found_raises(self, tmp_path):
        """测试 labels.csv 不存在时抛出 FileNotFoundError。"""
        loader = SampleLoader(
            labels_file="nonexistent.csv",
            base_dir=str(tmp_path),
        )
        with pytest.raises(FileNotFoundError):
            loader.load_labels()


# ================================================================
# 样本内容加载
# ================================================================

class TestLoadSamples:
    """测试样本文件内容的加载。"""

    def test_load_samples_returns_filtered(self, sample_data):
        """测试 load_samples 返回筛选后的样本。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples(category="benign")

        assert len(samples) == 1
        assert samples[0].category == "benign"

    def test_load_samples_reads_code_text(self, sample_data):
        """测试 load_samples 读取文件内容到 code_text。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples(category="benign")

        assert samples[0].code_text != ""
        assert "hello" in samples[0].code_text

    def test_load_all_samples(self, sample_data):
        """测试加载全部样本（无筛选）。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples()

        assert len(samples) == 4
        for s in samples:
            assert s.code_text != ""

    def test_load_samples_by_obfuscation(self, sample_data):
        """测试按混淆方式筛选样本。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples(obfuscation="base64")

        assert len(samples) == 1
        assert samples[0].obfuscation == "base64"
        assert samples[0].code_text != ""

    def test_load_samples_category_and_obfuscation(self, sample_data):
        """测试同时按 category 和 obfuscation 筛选。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples(
            category="obfuscated", obfuscation="base64"
        )

        assert len(samples) == 1
        assert samples[0].category == "obfuscated"
        assert samples[0].obfuscation == "base64"

    def test_load_samples_no_match(self, sample_data):
        """测试筛选条件无匹配时返回空列表。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples(category="nonexistent")

        assert samples == []

    def test_load_samples_missing_file(self, tmp_path):
        """测试样本文件不存在时 code_text 为空字符串。"""
        rows = [
            {
                "file_path": "missing/file.php",
                "filename": "file.php",
                "category": "webshell",
                "subcategory": "php",
                "label": "1",
                "language": "PHP",
                "file_size": "100",
            },
        ]
        csv_path = create_labels_csv(str(tmp_path), rows)
        # 不创建对应的样本文件

        loader = SampleLoader(
            labels_file=csv_path,
            base_dir=str(tmp_path),
        )
        samples = loader.load_samples()

        assert len(samples) == 1
        assert samples[0].code_text == ""


# ================================================================
# 分类过滤
# ================================================================

class TestCategoryFiltering:
    """测试分类过滤功能。"""

    def test_filter_benign(self, sample_data):
        """测试过滤 benign 类别。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        loader.load_labels()
        samples = loader.load_samples(category="benign")

        assert all(s.category == "benign" for s in samples)
        assert len(samples) == 1

    def test_filter_webshell(self, sample_data):
        """测试过滤 webshell 类别。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples(category="webshell")

        assert all(s.category == "webshell" for s in samples)
        assert len(samples) == 1

    def test_filter_obfuscated(self, sample_data):
        """测试过滤 obfuscated 类别。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples(category="obfuscated")

        assert all(s.category == "obfuscated" for s in samples)
        assert len(samples) == 1

    def test_filter_sqli(self, sample_data):
        """测试过滤 sqli 类别。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples(category="sqli")

        assert all(s.category == "sqli" for s in samples)
        assert len(samples) == 1


# ================================================================
# Sample 数据结构验证
# ================================================================

class TestSampleStructure:
    """测试 Sample 数据结构的完整性。"""

    def test_sample_has_all_fields(self, sample_data):
        """测试 Sample 对象包含所有必需字段。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()
        s = samples[0]

        assert hasattr(s, "file_path")
        assert hasattr(s, "category")
        assert hasattr(s, "label")
        assert hasattr(s, "malware_type")
        assert hasattr(s, "subtype")
        assert hasattr(s, "obfuscation")
        assert hasattr(s, "source")
        assert hasattr(s, "code_text")
        assert hasattr(s, "language")
        assert hasattr(s, "file_size")

    def test_code_text_empty_before_load(self, sample_data):
        """测试 load_labels 后 code_text 为空（未调用 load_samples）。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_labels()

        for s in samples:
            assert s.code_text == ""

    def test_code_text_filled_after_load(self, sample_data):
        """测试 load_samples 后 code_text 被填充。"""
        loader = SampleLoader(
            labels_file=sample_data["csv_path"],
            base_dir=sample_data["base_dir"],
        )
        samples = loader.load_samples()

        for s in samples:
            assert s.code_text != ""
            assert len(s.code_text) > 0
