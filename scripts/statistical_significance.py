"""
统计显著性检验脚本（McNemar 检验）

对实验结果进行统计显著性检验，判断不同提示词策略（或不同模型/方法）之间
的性能差异是否具有统计学意义。

McNemar 检验适用于「配对二分类」场景：两组分类器在同一组样本上做出预测，
我们关心的是两者预测「不一致」的样本中，是否存在系统性偏向。

配对二分类表（不一致对）：
    b = 策略 A 正确但策略 B 错误的样本数
    c = 策略 A 错误但策略 B 正确的样本数

检验统计量（带连续性校正，Edwards 修正）：
    chi2 = (|b - c| - 1)^2 / (b + c)        当 b + c > 0
    chi2 = 0                                 当 b + c = 0（无不一致对）

p 值通过自由度 df=1 的卡方分布上侧概率计算：
    - 优先使用 scipy.stats.chi2.sf（精确）
    - scipy 不可用时降级为纯 Python 实现（math.erfc 精确计算 df=1，通用 df
      使用正则化不完全 Gamma 函数的级数/连分式数值解）

判定标准：p < α（默认 α=0.05）则认为两组策略性能差异显著。

功能：
    1. 读取两组实验的 raw_results.json 文件
    2. 按样本配对，提取真实标签与预测标签判定正确性
    3. 构建 b/c 列联表并执行 McNemar 检验
    4. 支持 results/ 目录下所有实验的两两批量对比
    5. 输出格式化的对比表格，可选导出 JSON

用法：
    # 自动对比 results/ 下所有实验（两两组合）
    python scripts/statistical_significance.py

    # 指定结果目录
    python scripts/statistical_significance.py --dir results

    # 仅对比指定的两组实验
    python scripts/statistical_significance.py --a results/E1_xxx --b results/E2_xxx

    # 导出检验结果到 JSON
    python scripts/statistical_significance.py --output results/significance.json

兼容性：Python 3.10+
"""

from __future__ import annotations

import os
import sys
import json
import math
import argparse
import itertools
from typing import Any

# ----------------------------------------------------------------------------
# 路径初始化：将项目根目录加入 sys.path，使脚本可从项目根目录直接运行
# ----------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# 结果根目录（默认）
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")

# 默认显著性水平
DEFAULT_ALPHA = 0.05

# 小样本阈值：b+c 低于此值时卡方近似可能不可靠，建议参考精确二项检验
SMALL_SAMPLE_THRESHOLD = 25

# 尝试导入 scipy（可选依赖）
try:
    from scipy import stats as scipy_stats  # type: ignore

    _HAS_SCIPY = True
except ImportError:  # pragma: no cover - 取决于运行环境
    _HAS_SCIPY = False


# ============================================================================
# 纯 Python 卡方分布 p 值计算（scipy 不可用时的降级方案）
# ============================================================================
def _gser(a: float, x: float) -> float:
    """级数展开计算正则化下不完全 Gamma 函数 P(a, x)。

    适用于 x < a + 1 的情形。迭代至收敛（相对误差 < 1e-15）或达到上限。

    参考：Numerical Recipes 第 6.2 节 gammp 的 series 分支。
    """
    gln = math.lgamma(a)
    ap = a
    summ = 1.0 / a
    delta = summ
    for _ in range(1000):
        ap += 1.0
        delta *= x / ap
        summ += delta
        if abs(delta) < abs(summ) * 1e-15:
            break
    return summ * math.exp(-x + a * math.log(x) - gln)


def _gcf(a: float, x: float) -> float:
    """连分式（Lentz 算法）计算正则化上不完全 Gamma 函数 Q(a, x)。

    适用于 x >= a + 1 的情形。迭代至收敛或达到上限。

    参考：Numerical Recipes 第 6.2 节 gammq 的 continued-fraction 分支。
    """
    gln = math.lgamma(a)
    tiny = 1e-30
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def _gammp(a: float, x: float) -> float:
    """正则化下不完全 Gamma 函数 P(a, x) = γ(a, x) / Γ(a)。"""
    if x < 0 or a <= 0:
        raise ValueError(f"参数非法：a={a}（需 > 0），x={x}（需 >= 0）")
    if x == 0:
        return 0.0
    if x < a + 1.0:
        return _gser(a, x)
    return 1.0 - _gcf(a, x)


def _gammq(a: float, x: float) -> float:
    """正则化上不完全 Gamma 函数 Q(a, x) = 1 - P(a, x)。"""
    if x < 0 or a <= 0:
        raise ValueError(f"参数非法：a={a}（需 > 0），x={x}（需 >= 0）")
    if x == 0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gser(a, x)
    return _gcf(a, x)


def _chi2_sf_pure(chi2: float, df: int = 1) -> float:
    """纯 Python 计算卡方分布的上侧概率（survival function）。

    sf(x; df) = Q(df/2, x/2) = 1 - F(x; df)

    对于 df=1（McNemar 检验的固定自由度），可由标准库 math.erfc 精确计算：
        F(x; 1) = erf(sqrt(x/2))
        sf(x; 1) = erfc(sqrt(x/2))
    其余自由度使用正则化不完全 Gamma 函数的数值解（近似）。
    """
    if chi2 <= 0:
        return 1.0
    if df == 1:
        # df=1 的精确闭式解（标准库 erfc）
        return math.erfc(math.sqrt(chi2 / 2.0))
    return _gammq(df / 2.0, chi2 / 2.0)


def chi2_sf(chi2: float, df: int = 1) -> float:
    """卡方分布上侧概率。

    优先使用 scipy.stats.chi2.sf（精确）；scipy 不可用时降级为纯 Python 实现。

    Args:
        chi2: 卡方统计量
        df: 自由度（McNemar 检验恒为 1）

    Returns:
        上侧概率 p 值，范围 [0, 1]
    """
    if _HAS_SCIPY:
        return float(scipy_stats.chi2.sf(chi2, df))
    return _chi2_sf_pure(chi2, df)


def _binom_two_sided_p(b: int, c: int) -> float:
    """McNemar 精确检验的双侧 p 值（二项分布）。

    在 H0 下，不一致对中 A 正确的次数服从 Binom(n=b+c, p=0.5)。
    双侧 p = 2 * P(X <= min(b, c))，截断至 1.0。

    适用于 b+c 较小（卡方近似不可靠）时的参考。
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # P(X <= k) = sum_{i=0}^{k} C(n,i) * 0.5^n
    cum = sum(math.comb(n, i) for i in range(k + 1))
    p = cum * (0.5 ** n)
    return min(1.0, 2.0 * p)


# ============================================================================
# 终端显示宽度工具（处理中英文混排对齐）
# ============================================================================
# CJK / 全角字符的 Unicode 区间（这些字符在等宽终端中占 2 列）
_CJK_RANGES = (
    (0x1100, 0x115F), (0x2E80, 0x303E), (0x3041, 0x33FF),
    (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xA000, 0xA4CF),
    (0xAC00, 0xD7A3), (0xF900, 0xFAFF), (0xFE30, 0xFE4F),
    (0xFF00, 0xFF60), (0xFFE0, 0xFFE6),
)


def _display_width(s: str) -> int:
    """估算字符串在等宽终端中的显示宽度（CJK 计 2，其余计 1）。"""
    width = 0
    for ch in s:
        cp = ord(ch)
        if any(lo <= cp <= hi for lo, hi in _CJK_RANGES):
            width += 2
        else:
            width += 1
    return width


def _pad_right(s: str, width: int) -> str:
    """右侧填充空格使显示宽度达到 width。"""
    return s + " " * max(0, width - _display_width(s))


def _truncate(s: str, max_width: int) -> str:
    """按显示宽度截断字符串，超出部分以 « 结尾。"""
    if _display_width(s) <= max_width:
        return s
    out = ""
    cur = 0
    for ch in s:
        cw = 2 if any(lo <= ord(ch) <= hi for lo, hi in _CJK_RANGES) else 1
        if cur + cw > max_width - 1:  # 留 1 列给 «
            break
        out += ch
        cur += cw
    return out + "\u00ab"  # «


# ============================================================================
# McNemar 检验核心
# ============================================================================
class McNemarTest:
    """McNemar 检验封装。

    封装从结果加载、配对列联表构建到统计检验的完整流程。

    典型用法：
        tester = McNemarTest()
        ra = tester.load_results("results/E1_xxx")
        rb = tester.load_results("results/E2_xxx")
        result = tester.test(ra, rb)
        print(result["significant"], result["p_value"])
    """

    def __init__(self, alpha: float = DEFAULT_ALPHA) -> None:
        """
        Args:
            alpha: 显著性水平阈值，p < alpha 时判定为显著（默认 0.05）
        """
        self.alpha = alpha

    # ------------------------------------------------------------------
    # 结果加载
    # ------------------------------------------------------------------
    def load_results(self, run_dir: str) -> list[dict]:
        """从结果目录加载 raw_results.json。

        支持两种输入：
            - 实验结果目录（包含 raw_results.json）
            - 直接指向 raw_results.json 的文件路径

        Args:
            run_dir: 实验结果目录或 raw_results.json 文件路径

        Returns:
            逐条结果列表（每条含 true_label / pred_label / correct 等字段）

        Raises:
            FileNotFoundError: 找不到 raw_results.json
            ValueError: JSON 结构不符合预期
        """
        if os.path.isdir(run_dir):
            path = os.path.join(run_dir, "raw_results.json")
        elif os.path.isfile(run_dir) and os.path.basename(run_dir) == "raw_results.json":
            path = run_dir
        else:
            raise FileNotFoundError(
                f"未找到有效结果目录或 raw_results.json: {run_dir}"
            )

        if not os.path.isfile(path):
            raise FileNotFoundError(f"结果文件不存在: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict) or "results" not in data:
            raise ValueError(
                f"JSON 结构不符合预期（缺少 'results' 字段）: {path}"
            )

        results = data["results"]
        if not isinstance(results, list):
            raise ValueError(f"'results' 字段应为列表: {path}")

        return results

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    @staticmethod
    def _sample_key(item: dict) -> str:
        """提取样本唯一标识（规范化文件路径）。

        将路径分隔符统一为 '/'，以便跨平台/跨实验匹配同一样本。
        """
        fp = item.get("file_path") or item.get("filename") or ""
        return fp.replace("\\", "/").strip()

    @staticmethod
    def _is_correct(item: dict) -> bool | None:
        """判断单条预测是否正确。

        判定优先级：
            1. 优先使用 'correct' 字段（1=正确，0=错误，""/=无法判断）
            2. 降级比较 true_label 与 pred_label（忽略大小写/空白）

        Returns:
            True  — 预测正确
            False — 预测错误
            None  — 无法判断（如解析失败），配对时将跳过
        """
        # 1. 优先使用 correct 字段
        correct = item.get("correct")
        if correct is not None and correct != "":
            try:
                return int(correct) == 1
            except (ValueError, TypeError):
                pass  # 字段存在但无法解析，降级到标签比较

        # 2. 降级：比较 true_label 与 pred_label
        true_label = str(item.get("true_label", "")).strip().lower()
        pred_label = str(item.get("pred_label", "")).strip().lower()
        if not true_label or not pred_label:
            return None
        return true_label == pred_label

    # ------------------------------------------------------------------
    # 列联表构建
    # ------------------------------------------------------------------
    def build_contingency(
        self,
        results_a: list[dict],
        results_b: list[dict],
    ) -> dict[str, Any]:
        """构建配对二分类列联表。

        按样本唯一标识（规范化 file_path）将两组结果配对，仅保留两组均能
        判定正确性的样本，统计不一致对：
            b = A 正确但 B 错误
            c = A 错误但 B 正确

        Args:
            results_a: 策略 A 的逐条结果
            results_b: 策略 B 的逐条结果

        Returns:
            dict 包含:
                b, c           — 不一致对计数
                n_both_correct — 两者均正确的样本数
                n_both_wrong   — 两者均错误的样本数
                n_matched      — 成功配对且可判定的样本数
                n_a, n_b       — 各组原始样本数
                n_skipped      — 因无法判定正确性而跳过的配对数
                note           — 提示信息（如样本数不一致）
        """
        # 分别构建 key -> correctness（None 表示无法判定）
        map_a: dict[str, bool | None] = {}
        for item in results_a:
            key = self._sample_key(item)
            if key:
                map_a[key] = self._is_correct(item)

        map_b: dict[str, bool | None] = {}
        for item in results_b:
            key = self._sample_key(item)
            if key:
                map_b[key] = self._is_correct(item)

        # 取两组 key 的交集进行配对
        common_keys = map_a.keys() & map_b.keys()

        b = c = 0
        n_both_correct = n_both_wrong = 0
        n_skipped = 0

        for key in common_keys:
            ca = map_a[key]
            cb = map_b[key]
            # 任一组无法判定则跳过该样本
            if ca is None or cb is None:
                n_skipped += 1
                continue
            if ca and not cb:
                b += 1
            elif not ca and cb:
                c += 1
            elif ca and cb:
                n_both_correct += 1
            else:
                n_both_wrong += 1

        n_matched = b + c + n_both_correct + n_both_wrong

        note_parts: list[str] = []
        if len(results_a) != len(results_b):
            note_parts.append(
                f"两组样本数不同（A={len(results_a)}, B={len(results_b)}），"
                f"仅使用交集 {len(common_keys)} 个配对"
            )
        if n_skipped > 0:
            note_parts.append(
                f"{n_skipped} 个配对因无法判定正确性被跳过"
            )
        if len(common_keys) == 0:
            note_parts.append("两组结果无相同样本，无法配对")

        return {
            "b": b,
            "c": c,
            "n_both_correct": n_both_correct,
            "n_both_wrong": n_both_wrong,
            "n_matched": n_matched,
            "n_a": len(results_a),
            "n_b": len(results_b),
            "n_common": len(common_keys),
            "n_skipped": n_skipped,
            "note": "；".join(note_parts) if note_parts else "",
        }

    # ------------------------------------------------------------------
    # 执行检验
    # ------------------------------------------------------------------
    def test(
        self,
        results_a: list[dict],
        results_b: list[dict],
    ) -> dict[str, Any]:
        """执行 McNemar 检验。

        流程：
            1. 构建配对列联表（b, c）
            2. 计算带连续性校正的卡方统计量
            3. 计算上侧 p 值（scipy 或纯 Python）
            4. 判定显著性（p < alpha）

        Args:
            results_a: 策略 A 的逐条结果
            results_b: 策略 B 的逐条结果

        Returns:
            dict 包含:
                chi2          — 卡方统计量（带连续性校正）
                p_value       — 上侧 p 值
                b, c          — 不一致对计数
                significant   — 是否显著（p < alpha）
                n_matched     — 配对样本数
                n_discordant  — 不一致对总数 (b + c)
                p_value_exact — 精确二项检验双侧 p 值（参考）
                engine        — p 值计算引擎（"scipy" / "pure-python"）
                note          — 提示信息
        """
        cont = self.build_contingency(results_a, results_b)
        b = cont["b"]
        c = cont["c"]
        n_discordant = b + c

        engine = "scipy" if _HAS_SCIPY else "pure-python"
        notes: list[str] = []
        if cont["note"]:
            notes.append(cont["note"])

        # 边界情形：无不一致对
        if n_discordant == 0:
            notes.append("无不一致对（b+c=0），两组在所有配对样本上判定一致")
            return {
                "chi2": 0.0,
                "p_value": 1.0,
                "b": b,
                "c": c,
                "significant": False,
                "n_matched": cont["n_matched"],
                "n_discordant": 0,
                "p_value_exact": 1.0,
                "engine": engine,
                "note": "；".join(notes),
            }

        # McNemar 统计量（带连续性校正）
        chi2 = (abs(b - c) - 1) ** 2 / n_discordant

        # p 值（df = 1）
        p_value = chi2_sf(chi2, df=1)

        # 精确二项检验 p 值（小样本参考）
        p_exact = _binom_two_sided_p(b, c)

        # 小样本提示
        if n_discordant < SMALL_SAMPLE_THRESHOLD:
            notes.append(
                f"不一致对数较小（b+c={n_discordant}<{SMALL_SAMPLE_THRESHOLD}），"
                f"卡方近似可能不可靠，建议参考精确二项 p 值"
            )

        return {
            "chi2": round(chi2, 6),
            "p_value": p_value,
            "b": b,
            "c": c,
            "significant": bool(p_value < self.alpha),
            "n_matched": cont["n_matched"],
            "n_discordant": n_discordant,
            "p_value_exact": p_exact,
            "engine": engine,
            "note": "；".join(notes),
        }


# ============================================================================
# 实验发现与批量对比
# ============================================================================
def discover_experiments(results_dir: str) -> list[tuple[str, str]]:
    """扫描结果目录，发现所有包含 raw_results.json 的实验。

    Args:
        results_dir: 结果根目录（如 results/）

    Returns:
        [(实验名, 目录路径), ...] 按实验名排序
    """
    experiments: list[tuple[str, str]] = []
    if not os.path.isdir(results_dir):
        return experiments
    for name in sorted(os.listdir(results_dir)):
        dir_path = os.path.join(results_dir, name)
        if os.path.isdir(dir_path) and os.path.isfile(
            os.path.join(dir_path, "raw_results.json")
        ):
            experiments.append((name, dir_path))
    return experiments


def format_pairwise_table(
    comparisons: list[dict[str, Any]],
    alpha: float,
) -> str:
    """格式化两两对比结果为表格字符串。

    Args:
        comparisons: 每组对比的结果字典列表
        alpha: 显著性水平

    Returns:
        格式化的多行表格字符串
    """
    sep = "=" * 92
    lines: list[str] = []
    lines.append(sep)
    lines.append("  McNemar 检验 · 实验两两对比")
    lines.append(sep)
    lines.append(f"  显著性水平 α = {alpha}")
    lines.append(
        f"  p 值引擎: {'scipy.stats.chi2.sf' if _HAS_SCIPY else '纯 Python (math.erfc / incomplete gamma)'}"
    )
    lines.append(f"  共 {len(comparisons)} 组对比")
    lines.append("")

    if not comparisons:
        lines.append("  （无可用对比）")
        lines.append(sep)
        return "\n".join(lines)

    # 列定义：(表头, 宽度)
    header = (
        "实验 A", "实验 B", "b", "c", "χ²", "p 值", "精确 p", "显著?"
    )
    widths = (28, 28, 5, 5, 9, 11, 11, 7)

    # 表头行
    header_line = "  " + "  ".join(
        _pad_right(h, w) for h, w in zip(header, widths)
    )
    lines.append(header_line)
    lines.append("  " + "─" * (_display_width(header_line) - 2))

    # 数据行
    for cmp in comparisons:
        name_a = _truncate(cmp["name_a"], widths[0])
        name_b = _truncate(cmp["name_b"], widths[1])
        sig = "是 *" if cmp["significant"] else "否"
        row = [
            _pad_right(name_a, widths[0]),
            _pad_right(name_b, widths[1]),
            _pad_right(str(cmp["b"]), widths[2]),
            _pad_right(str(cmp["c"]), widths[3]),
            _pad_right(f"{cmp['chi2']:.3f}", widths[4]),
            _pad_right(f"{cmp['p_value']:.6f}", widths[5]),
            _pad_right(f"{cmp['p_value_exact']:.6f}", widths[6]),
            _pad_right(sig, widths[7]),
        ]
        lines.append("  " + "  ".join(row))

    lines.append("")

    # 汇总显著对比
    sig_cmps = [c for c in comparisons if c["significant"]]
    if sig_cmps:
        lines.append(f"  显著差异（p < {alpha}）：{len(sig_cmps)} 组")
        for c in sig_cmps:
            direction = "A 优于 B" if c["b"] < c["c"] else "B 优于 A" if c["b"] > c["c"] else "—"
            lines.append(
                f"    · {c['name_a']}  vs  {c['name_b']}"
                f"  (b={c['b']}, c={c['c']}, p={c['p_value']:.6f}, {direction})"
            )
    else:
        lines.append(f"  无显著差异的对比组（p >= {alpha}）")

    # 备注行
    notes_lines = [c for c in comparisons if c.get("note")]
    if notes_lines:
        lines.append("")
        lines.append("  备注：")
        for c in notes_lines:
            lines.append(f"    · [{c['name_a']} vs {c['name_b']}] {c['note']}")

    lines.append(sep)
    return "\n".join(lines)


# ============================================================================
# 命令行入口
# ============================================================================
def main() -> None:
    """命令行入口。

    支持两种模式：
        1. 批量模式（默认）：--dir 指定结果目录，自动发现所有实验并两两对比
        2. 单次模式：--a / --b 指定两组实验目录进行单次对比
    """
    parser = argparse.ArgumentParser(
        description="McNemar 检验：对实验结果进行统计显著性检验",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  python scripts/statistical_significance.py\n"
            "  python scripts/statistical_significance.py --dir results\n"
            "  python scripts/statistical_significance.py --a results/E1_xxx --b results/E2_xxx\n"
            "  python scripts/statistical_significance.py --output results/significance.json\n"
        ),
    )
    parser.add_argument(
        "--dir", type=str, default=RESULTS_DIR,
        help=f"结果根目录，自动发现其下所有实验并两两对比（默认: {RESULTS_DIR}）",
    )
    parser.add_argument(
        "--a", type=str, default=None,
        help="策略 A 的结果目录或 raw_results.json 路径（单次对比模式）",
    )
    parser.add_argument(
        "--b", type=str, default=None,
        help="策略 B 的结果目录或 raw_results.json 路径（单次对比模式）",
    )
    parser.add_argument(
        "--alpha", type=float, default=DEFAULT_ALPHA,
        help=f"显著性水平阈值（默认: {DEFAULT_ALPHA}）",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="将检验结果导出为 JSON 文件（可选）",
    )
    args = parser.parse_args()

    tester = McNemarTest(alpha=args.alpha)

    print("=" * 92)
    print("  McNemar 统计显著性检验")
    print("=" * 92)
    print(f"  显著性水平 α = {args.alpha}")
    print(f"  p 值引擎: {'scipy.stats.chi2.sf' if _HAS_SCIPY else '纯 Python (math.erfc / incomplete gamma)'}")
    if not _HAS_SCIPY:
        print("  [提示] 未安装 scipy，已降级为纯 Python 实现（df=1 时使用 math.erfc 精确计算）")
    print("")

    # ------------------------------------------------------------------
    # 单次对比模式
    # ------------------------------------------------------------------
    if args.a and args.b:
        try:
            results_a = tester.load_results(args.a)
            results_b = tester.load_results(args.b)
        except (FileNotFoundError, ValueError) as e:
            print(f"  [错误] 加载结果失败: {e}")
            sys.exit(1)

        name_a = os.path.basename(os.path.normpath(args.a))
        name_b = os.path.basename(os.path.normpath(args.b))
        # 若直接传入 raw_results.json，取上级目录名
        if name_a == "raw_results.json":
            name_a = os.path.basename(os.path.dirname(os.path.normpath(args.a)))
        if name_b == "raw_results.json":
            name_b = os.path.basename(os.path.dirname(os.path.normpath(args.b)))

        print(f"  策略 A: {name_a}（{len(results_a)} 条）")
        print(f"  策略 B: {name_b}（{len(results_b)} 条）")
        print("")

        result = tester.test(results_a, results_b)
        result["name_a"] = name_a
        result["name_b"] = name_b

        print("-" * 60)
        print("  检验结果")
        print("-" * 60)
        print(f"  b (A正确, B错误) = {result['b']}")
        print(f"  c (A错误, B正确) = {result['c']}")
        print(f"  不一致对总数 b+c = {result['n_discordant']}")
        print(f"  配对样本数       = {result['n_matched']}")
        print(f"  χ² 统计量        = {result['chi2']}")
        print(f"  p 值             = {result['p_value']:.6f}")
        print(f"  精确二项 p 值    = {result['p_value_exact']:.6f}")
        print(f"  显著 (p<{args.alpha})    = {'是' if result['significant'] else '否'}")
        if result["note"]:
            print(f"  备注: {result['note']}")
        print("-" * 60)

        if args.output:
            _export_json([result], args.output, args.alpha)
        return

    # ------------------------------------------------------------------
    # 批量对比模式
    # ------------------------------------------------------------------
    results_dir = args.dir
    experiments = discover_experiments(results_dir)

    if not experiments:
        print(f"  [错误] 在 {results_dir} 下未发现任何实验（含 raw_results.json 的子目录）")
        sys.exit(1)

    print(f"  结果目录: {results_dir}")
    print(f"  发现 {len(experiments)} 个实验：")
    for name, _ in experiments:
        print(f"    · {name}")
    print("")

    # 预加载所有结果（避免重复 IO）
    loaded: dict[str, list[dict]] = {}
    failed: list[str] = []
    for name, dir_path in experiments:
        try:
            loaded[name] = tester.load_results(dir_path)
        except (FileNotFoundError, ValueError) as e:
            failed.append(f"{name}: {e}")

    if failed:
        print("  [警告] 以下实验加载失败，已跳过：")
        for msg in failed:
            print(f"    · {msg}")
        print("")

    usable = [name for name, _ in experiments if name in loaded]
    if len(usable) < 2:
        print("  [错误] 可用实验不足 2 个，无法进行两两对比")
        sys.exit(1)

    # 两两组合
    comparisons: list[dict[str, Any]] = []
    for name_a, name_b in itertools.combinations(usable, 2):
        result = tester.test(loaded[name_a], loaded[name_b])
        result["name_a"] = name_a
        result["name_b"] = name_b
        comparisons.append(result)

    # 输出格式化表格
    print(format_pairwise_table(comparisons, args.alpha))

    # 导出 JSON
    if args.output:
        _export_json(comparisons, args.output, args.alpha)


def _export_json(comparisons: list[dict[str, Any]], output_path: str, alpha: float) -> None:
    """将对比结果导出为 JSON 文件。"""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    export_data = {
        "test": "McNemar",
        "engine": "scipy.stats.chi2.sf" if _HAS_SCIPY else "pure-python",
        "alpha": alpha,
        "n_comparisons": len(comparisons),
        "comparisons": comparisons,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, ensure_ascii=False, indent=2)
    print(f"\n  检验结果已导出: {output_path}")


if __name__ == "__main__":
    main()
