#!/usr/bin/env python3
"""ELF Binary Reverse Engineering TUI — main entry point."""
from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

# Ensure package root is on sys.path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.core.cfg import build_cfg, compute_stats, CFGStats
from analyzer.core.disasm import disassemble, extract_basic_blocks, format_disassembly
from analyzer.core.elf_loader import ELFLoader, FunctionInfo
from analyzer.core import llm as llm_mod
from analyzer.ui import layout as ui
from analyzer.ui.keys import read_key, UP_KEYS, DOWN_KEYS

RESULTS_CSV = Path(__file__).parent.parent / "results.csv"
console = Console()

# ──────────────────────────────────────────────
# CSV helpers
# ──────────────────────────────────────────────

CSV_HEADER = [
    "binary", "function", "blocks", "edges", "cyclomatic_complexity",
    "llm_vuln_found", "llm_obfuscation_detected", "llm_techniques",
    "vuln_category", "binary_level", "timestamp",
]


def _ensure_csv() -> None:
    if not RESULTS_CSV.exists():
        with RESULTS_CSV.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(CSV_HEADER)
        return

    # Migrate if existing CSV is missing new columns
    with RESULTS_CSV.open("r", newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))

    existing_header = rows[0] if rows else []
    new_cols = [c for c in CSV_HEADER if c not in existing_header]
    if not new_cols:
        return

    # Insert new columns before "timestamp"
    try:
        ts_idx = existing_header.index("timestamp")
        new_header = existing_header[:ts_idx] + new_cols + existing_header[ts_idx:]
        migrated = [new_header] + [
            r[:ts_idx] + ["unknown"] * len(new_cols) + r[ts_idx:]
            for r in rows[1:]
        ]
    except ValueError:
        new_header = existing_header + new_cols
        migrated = [new_header] + [r + ["unknown"] * len(new_cols) for r in rows[1:]]

    with RESULTS_CSV.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(migrated)


def _append_result(
    binary: str,
    func: FunctionInfo,
    stats: Optional[CFGStats],
    parsed: Optional[dict],
    vuln_category: str = "unknown",
    binary_level: str = "unknown",
) -> None:
    _ensure_csv()
    blocks = stats.num_blocks if stats else 0
    edges = stats.num_edges if stats else 0
    cc = stats.cyclomatic_complexity if stats else 0

    vuln_found = ""
    obf_detected = ""
    techniques = ""
    if parsed:
        vuln_found = str(parsed.get("vulnerability", {}).get("found", "")).lower()
        obf_detected = str(parsed.get("obfuscation", {}).get("detected", "")).lower()
        techniques = ";".join(parsed.get("obfuscation", {}).get("techniques", []))

    with RESULTS_CSV.open("a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            binary, func.name, blocks, edges, cc,
            vuln_found, obf_detected, techniques,
            vuln_category, binary_level,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ])


# ──────────────────────────────────────────────
# Analysis helpers
# ──────────────────────────────────────────────

def auto_select_function(functions: list[FunctionInfo]) -> int:
    """Prefer vuln() / process_input(); otherwise pick the highest block-count function."""
    preferred = {"vuln", "process_input"}
    for i, fn in enumerate(functions):
        if fn.name in preferred:
            return i

    best_idx, best_blocks = 0, 0
    for i, fn in enumerate(functions):
        if not fn.data:
            continue
        insns = disassemble(fn.data, fn.address)
        blk_count = len(extract_basic_blocks(insns))
        if blk_count > best_blocks:
            best_blocks, best_idx = blk_count, i
    return best_idx


def analyze_function(func: FunctionInfo):
    """Returns (disasm_text, cfg_stats)."""
    if not func.data:
        return "[ 데이터 없음 ]", None
    instructions = disassemble(func.data, func.address)
    if not instructions:
        return "[ 디스어셈블 실패 ]", None
    disasm_text = format_disassembly(instructions)
    blocks = extract_basic_blocks(instructions)
    g = build_cfg(blocks)
    stats = compute_stats(g, blocks)
    return disasm_text, stats


# ──────────────────────────────────────────────
# LLM streaming with Live panel
# ──────────────────────────────────────────────

def run_llm_analysis(
    binary_name: str,
    func: FunctionInfo,
    disasm_text: str,
    stats: Optional[CFGStats],
    no_llm: bool,
    vuln_category: str = "unknown",
    binary_level: str = "unknown",
) -> str:
    if no_llm:
        return "[dim]--no-llm 모드: LLM 분석 비활성화[/dim]"

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "[red]ANTHROPIC_API_KEY 환경변수가 설정되지 않았습니다.[/red]"

    raw_buf: list[str] = []

    try:
        for chunk in llm_mod.stream_analysis(disasm_text):
            raw_buf.append(chunk)
    except KeyboardInterrupt:
        pass

    raw = "".join(raw_buf)
    parsed = llm_mod.parse_response(raw)
    _append_result(binary_name, func, stats, parsed, vuln_category, binary_level)

    if parsed is not None:
        return llm_mod.format_parsed(parsed)

    # 파싱 실패 시 코드펜스만 제거해서 출력
    clean = raw.strip()
    if clean.startswith("```"):
        lines = clean.splitlines()
        clean = "\n".join(
            l for l in lines
            if not l.strip().startswith("```")
        ).strip()
    return f"[dim](JSON 파싱 실패)[/dim]\n{clean}"


# ──────────────────────────────────────────────
# Main TUI loop
# ──────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ELF Binary Reverse Engineering TUI")
    parser.add_argument("--binary", required=True, help="분석할 ELF 바이너리 경로")
    parser.add_argument("--no-llm", action="store_true", help="LLM 없이 디스어셈블+CFG만 동작")
    parser.add_argument("--category", default="unknown",
                        choices=["easy", "hard", "unknown"],
                        help="취약점 난이도 카테고리 (easy/hard)")
    parser.add_argument("--level", default="unknown",
                        choices=["none", "L1", "L1L2", "L1L2L3", "L1L2L3L4", "unknown"],
                        help="난독화 레벨 (none/L1/L1L2/L1L2L3/L1L2L3L4)")
    parser.add_argument("--auto-select", action="store_true",
                        help="함수 자동 선택 후 LLM 분석 → CSV 저장 후 종료 (비대화형)")
    args = parser.parse_args()

    try:
        loader = ELFLoader(args.binary)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    functions = loader.functions
    if not functions:
        console.print("[red]함수를 찾을 수 없습니다.[/red]")
        sys.exit(1)

    # ── 비대화형 자동 선택 모드 ──────────────────────
    if args.auto_select:
        selected = auto_select_function(functions)
        func = functions[selected]
        console.print(
            f"[cyan]자동 선택 함수:[/cyan] {func.name}  "
            f"(category={args.category}, level={args.level})"
        )
        disasm_text, cfg_stats = analyze_function(func)
        result = run_llm_analysis(
            binary_name=loader.binary_name,
            func=func,
            disasm_text=disasm_text,
            stats=cfg_stats,
            no_llm=args.no_llm,
            vuln_category=args.category,
            binary_level=args.level,
        )
        console.print(result)
        return

    # ── 대화형 TUI 모드 ──────────────────────────────
    selected = 0
    disasm_text, cfg_stats = analyze_function(functions[selected])
    llm_content = ""

    ui.render_full(functions, selected, disasm_text, cfg_stats, llm_content)

    while True:
        try:
            key = read_key()
        except KeyboardInterrupt:
            break

        if key == "q":
            break

        elif key in UP_KEYS:
            if selected > 0:
                selected -= 1
                disasm_text, cfg_stats = analyze_function(functions[selected])
                llm_content = ""
                ui.render_full(functions, selected, disasm_text, cfg_stats, llm_content)

        elif key in DOWN_KEYS:
            if selected < len(functions) - 1:
                selected += 1
                disasm_text, cfg_stats = analyze_function(functions[selected])
                llm_content = ""
                ui.render_full(functions, selected, disasm_text, cfg_stats, llm_content)

        elif key == "r":
            disasm_text, cfg_stats = analyze_function(functions[selected])
            ui.render_full(functions, selected, disasm_text, cfg_stats, llm_content)

        elif key == "a":
            llm_content = run_llm_analysis(
                binary_name=loader.binary_name,
                func=functions[selected],
                disasm_text=disasm_text,
                stats=cfg_stats,
                no_llm=args.no_llm,
                vuln_category=args.category,
                binary_level=args.level,
            )
            ui.render_full(functions, selected, disasm_text, cfg_stats, llm_content)

    console.clear()
    console.print("[bold green]종료합니다.[/bold green]")


if __name__ == "__main__":
    main()
