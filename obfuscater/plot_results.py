#!/usr/bin/env python3
"""
plot_results.py — Visualise obfuscation experiment results.

Graphs produced
───────────────
1. results_detection.png  — detection rate  per level  (from results.csv)
2. results_cfg.png        — CFG complexity  per level  (from results.csv)
3. results_injected.png   — injected_count  per level  (from stats.csv), 2 lines
4. results_ptload.png     — pt_load_filesz  per level  (from stats.csv), 2 lines

Usage
─────
  python plot_results.py --stats experiment/stats.csv
  python plot_results.py --results results.csv --stats experiment/stats.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

LEVEL_ORDER = ["none", "L1", "L1L2", "L1L2L3", "L1L2L3L4"]


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

def _read_csv(path: str) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _pivot(rows: list[dict], key_col: str, level_col: str, val_col: str
           ) -> dict[str, dict[str, float]]:
    """Return {key_value: {level: numeric_value}} mapping."""
    out: dict[str, dict[str, float]] = {}
    for row in rows:
        k = row[key_col]
        lv = row[level_col]
        try:
            v = float(row[val_col])
        except (KeyError, ValueError):
            continue
        out.setdefault(k, {})[lv] = v
    return out


# ---------------------------------------------------------------------------
# Plotting helpers
# ---------------------------------------------------------------------------

def _import_matplotlib():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        print("ERROR: matplotlib is not installed.  pip install matplotlib", file=sys.stderr)
        sys.exit(1)


def _ordered_xy(series: dict[str, float]) -> tuple[list[str], list[float]]:
    xs = [lv for lv in LEVEL_ORDER if lv in series]
    ys = [series[lv] for lv in xs]
    return xs, ys


def _single_line_graph(
    plt,
    pivot: dict[str, dict[str, float]],
    ylabel: str,
    title: str,
    out_path: str,
) -> None:
    """One line per key in pivot."""
    fig, ax = plt.subplots(figsize=(7, 4))
    for key, series in sorted(pivot.items()):
        xs, ys = _ordered_xy(series)
        ax.plot(xs, ys, marker="o", label=key)
    ax.set_xlabel("Level")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Saved: {out_path}")


def _bar_graph(
    plt,
    pivot: dict[str, dict[str, float]],
    ylabel: str,
    title: str,
    out_path: str,
) -> None:
    """Bar chart (single series assumed — first key in pivot used as label)."""
    fig, ax = plt.subplots(figsize=(7, 4))
    for key, series in sorted(pivot.items()):
        xs, ys = _ordered_xy(series)
        ax.bar(xs, ys, label=key, alpha=0.7)
    ax.set_xlabel("Level")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Saved: {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Plot obfuscation experiment results")
    p.add_argument("--results", metavar="CSV", default=None,
                   help="results.csv with columns: target,level,detection_rate,cfg_complexity")
    p.add_argument("--stats", metavar="CSV", default=None,
                   help="experiment/stats.csv with columns: target,level,file_size_bytes,pt_load_filesz,injected_count")
    p.add_argument("--out-dir", metavar="DIR", default=".",
                   help="Directory to write PNG files (default: current directory)")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if not args.results and not args.stats:
        print("ERROR: Provide at least one of --results or --stats", file=sys.stderr)
        return 1

    plt = _import_matplotlib()
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)

    # ── Graphs 1 & 2: from results.csv ──────────────────────────────────────
    if args.results:
        if not os.path.isfile(args.results):
            print(f"WARNING: --results file not found: {args.results}", file=sys.stderr)
        else:
            rows = _read_csv(args.results)

            # Graph 1: detection rate
            pivot_det = _pivot(rows, "target", "level", "detection_rate")
            _single_line_graph(
                plt, pivot_det,
                ylabel="Detection Rate",
                title="Detection Rate per Obfuscation Level",
                out_path=os.path.join(out_dir, "results_detection.png"),
            )

            # Graph 2: CFG complexity
            pivot_cfg = _pivot(rows, "target", "level", "cfg_complexity")
            _single_line_graph(
                plt, pivot_cfg,
                ylabel="CFG Complexity",
                title="CFG Complexity per Obfuscation Level",
                out_path=os.path.join(out_dir, "results_cfg.png"),
            )

    # ── Graphs 3 & 4: from stats.csv ────────────────────────────────────────
    if args.stats:
        if not os.path.isfile(args.stats):
            print(f"WARNING: --stats file not found: {args.stats}", file=sys.stderr)
        else:
            rows = _read_csv(args.stats)

            # Graph 3: injected_count
            pivot_inj = _pivot(rows, "target", "level", "injected_count")
            _single_line_graph(
                plt, pivot_inj,
                ylabel="Injected Count",
                title="Injected Items per Obfuscation Level",
                out_path=os.path.join(out_dir, "results_injected.png"),
            )

            # Graph 4: pt_load_filesz
            pivot_pt = _pivot(rows, "target", "level", "pt_load_filesz")
            _single_line_graph(
                plt, pivot_pt,
                ylabel="PT_LOAD p_filesz (bytes)",
                title="Executable Segment Size per Obfuscation Level",
                out_path=os.path.join(out_dir, "results_ptload.png"),
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
