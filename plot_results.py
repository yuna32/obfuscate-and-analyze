#!/usr/bin/env python3
"""
plot_results.py
results.csv에서 두 가지 그래프를 생성한다.
  - results_vuln_detection.png  : LLM 취약점 탐지율 vs 난독화 레벨
  - results_cfg_complexity.png  : CFG Cyclomatic Complexity 평균 vs 난독화 레벨
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless 환경 대응
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import pandas as pd

# 한글 폰트 설정 (환경에 따라 없을 수 있으므로 안전하게 처리)
try:
    import matplotlib.font_manager as fm
    _korean_fonts = [f.name for f in fm.fontManager.ttflist
                     if any(k in f.name for k in ("Gothic", "Gulim", "Malgun", "NanumGothic", "AppleGothic"))]
    if _korean_fonts:
        plt.rcParams["font.family"] = _korean_fonts[0]
    else:
        plt.rcParams["font.family"] = "DejaVu Sans"
except Exception:
    plt.rcParams["font.family"] = "DejaVu Sans"

plt.rcParams["axes.unicode_minus"] = False

LEVEL_ORDER = ["none", "L1", "L1L2", "L1L2L3", "L1L2L3L4"]
LEVEL_LABELS = {
    "none":     "none\n(원본)",
    "L1":       "L1",
    "L1L2":     "L1L2",
    "L1L2L3":   "L1L2L3",
    "L1L2L3L4": "L1L2L3L4",
}

CATEGORY_STYLE = {
    "easy": {"color": "steelblue",  "marker": "o", "label": "Easy"},
    "hard": {"color": "crimson",    "marker": "s", "label": "Hard"},
}


def _load(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    required = {"vuln_category", "binary_level", "llm_vuln_found", "cyclomatic_complexity"}
    missing = required - set(df.columns)
    if missing:
        print(f"[오류] CSV에 필요한 컬럼이 없습니다: {missing}", file=sys.stderr)
        sys.exit(1)
    return df


def _ordered_levels(df: pd.DataFrame, category: str) -> tuple[list[str], list[float]]:
    """Return (x_labels, y_values) in LEVEL_ORDER for the given category."""
    sub = df[df["vuln_category"] == category]
    xs, ys = [], []
    for lvl in LEVEL_ORDER:
        rows = sub[sub["binary_level"] == lvl]
        if rows.empty:
            continue
        xs.append(LEVEL_LABELS.get(lvl, lvl))
        ys.append(rows)  # type: ignore[arg-type]  — placeholder, replaced below
    return xs, ys  # caller decides aggregation


def plot_vuln_detection(df: pd.DataFrame, out_path: str) -> None:
    df = df.copy()
    df["llm_vuln_found"] = df["llm_vuln_found"].astype(str).str.lower().map(
        {"true": True, "false": False}
    ).fillna(False)

    fig, ax = plt.subplots(figsize=(9, 5))
    plotted = False

    for cat, style in CATEGORY_STYLE.items():
        sub = df[df["vuln_category"] == cat]
        if sub.empty:
            continue
        xs, ys = [], []
        for lvl in LEVEL_ORDER:
            rows = sub[sub["binary_level"] == lvl]
            if rows.empty:
                continue
            rate = rows["llm_vuln_found"].mean() * 100
            xs.append(LEVEL_LABELS.get(lvl, lvl))
            ys.append(rate)
        if xs:
            ax.plot(xs, ys, marker=style["marker"], color=style["color"],
                    label=style["label"], linewidth=2, markersize=8)
            plotted = True

    if not plotted:
        ax.text(0.5, 0.5, "데이터 없음\n(vuln_category 컬럼을 확인하세요)",
                ha="center", va="center", transform=ax.transAxes, fontsize=12, color="gray")

    ax.set_xlabel("난독화 레벨", fontsize=12)
    ax.set_ylabel("취약점 탐지율 (%)", fontsize=12)
    ax.set_title("LLM 취약점 탐지율 vs 난독화 레벨", fontsize=14, fontweight="bold")
    ax.set_ylim(-5, 105)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=100))
    ax.legend(fontsize=11)
    ax.grid(True, linestyle="--", alpha=0.4)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"저장: {out_path}")


def plot_cfg_complexity(df: pd.DataFrame, out_path: str) -> None:
    df = df.copy()
    df["cyclomatic_complexity"] = pd.to_numeric(df["cyclomatic_complexity"], errors="coerce")

    fig, ax = plt.subplots(figsize=(9, 5))
    plotted = False

    for cat, style in CATEGORY_STYLE.items():
        # 특정 함수가 아닌 전체 함수 평균으로 집계
        sub = df[df["vuln_category"] == cat]
        if sub.empty:
            continue
        xs, ys, errs = [], [], []
        for lvl in LEVEL_ORDER:
            rows = sub[sub["binary_level"] == lvl]
            if rows.empty:
                continue
            vals = rows["cyclomatic_complexity"].dropna()
            if vals.empty:
                continue
            xs.append(LEVEL_LABELS.get(lvl, lvl))
            ys.append(vals.mean())
            errs.append(vals.std() if len(vals) > 1 else 0)
        if xs:
            ax.errorbar(xs, ys, yerr=errs,
                        marker=style["marker"], color=style["color"],
                        label=style["label"], linewidth=2, markersize=8,
                        capsize=4, alpha=0.9)
            plotted = True

    if not plotted:
        ax.text(0.5, 0.5, "데이터 없음\n(vuln_category 컬럼을 확인하세요)",
                ha="center", va="center", transform=ax.transAxes, fontsize=12, color="gray")

    ax.set_xlabel("난독화 레벨", fontsize=12)
    ax.set_ylabel("Cyclomatic Complexity (평균 ± 표준편차)", fontsize=12)
    ax.set_title("CFG 복잡도 변화 vs 난독화 레벨\n(분석 대상 함수 전체 평균)", fontsize=14, fontweight="bold")
    ax.legend(fontsize=11)
    ax.grid(True, linestyle="--", alpha=0.4)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"저장: {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot analysis results from results.csv")
    parser.add_argument("--input", required=True, help="results.csv 경로")
    args = parser.parse_args()

    csv_path = Path(args.input)
    if not csv_path.exists():
        print(f"[오류] 파일을 찾을 수 없습니다: {csv_path}", file=sys.stderr)
        sys.exit(1)

    df = _load(str(csv_path))
    out_dir = csv_path.parent

    plot_vuln_detection(df, str(out_dir / "results_vuln_detection.png"))
    plot_cfg_complexity(df, str(out_dir / "results_cfg_complexity.png"))

    print("\n그래프 생성 완료.")


if __name__ == "__main__":
    main()
