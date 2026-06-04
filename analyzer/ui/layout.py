from __future__ import annotations
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich import box

from ..core.cfg import CFGStats
from ..core.elf_loader import FunctionInfo


console = Console()


def _make_function_list(
    functions: list[FunctionInfo],
    selected: int,
    panel_height: int = 20,
) -> Panel:
    text = Text()
    visible_start = max(0, selected - panel_height // 2)
    visible_end = min(len(functions), visible_start + panel_height)

    for i in range(visible_start, visible_end):
        fn = functions[i]
        line = f" {fn.name[:22]:<22} 0x{fn.address:08x}\n"
        if i == selected:
            text.append(line, style="bold reverse cyan")
        else:
            text.append(line)

    return Panel(
        text,
        title="[bold]함수 목록[/bold]",
        border_style="blue",
        padding=(0, 0),
    )


def _make_disasm_panel(disasm_text: str, func_name: str) -> Panel:
    try:
        syntax = Syntax(disasm_text, "asm", theme="monokai", line_numbers=False)
    except Exception:
        syntax = Syntax(disasm_text, "text", theme="monokai", line_numbers=False)

    return Panel(
        syntax,
        title=f"[bold]디스어셈블: {func_name}[/bold]",
        border_style="green",
        padding=(0, 1),
    )


def _make_cfg_panel(stats: Optional[CFGStats]) -> Panel:
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
    table.add_column("항목", style="cyan", no_wrap=True)
    table.add_column("값", justify="right", style="yellow")

    if stats:
        table.add_row("기본 블록 수", str(stats.num_blocks))
        table.add_row("엣지 수", str(stats.num_edges))
        table.add_row("Cyclomatic Complexity", str(stats.cyclomatic_complexity))
        table.add_row("최장 경로 길이", str(stats.longest_path))
    else:
        table.add_row("—", "—")

    return Panel(
        table,
        title="[bold]CFG 통계[/bold]",
        border_style="magenta",
    )


def _make_llm_panel(content: str) -> Panel:
    return Panel(
        Text.from_markup(content) if content else Text("[ a ] 를 눌러 LLM 분석 실행", style="dim"),
        title="[bold]LLM 분석 결과[/bold]",
        border_style="yellow",
        padding=(0, 1),
    )


def _status_bar() -> str:
    return (
        "[bold cyan][q][/bold cyan] 종료  "
        "[bold cyan][a][/bold cyan] LLM 분석  "
        "[bold cyan][↑↓/jk][/bold cyan] 함수 이동  "
        "[bold cyan][r][/bold cyan] 새로고침"
    )


def render_full(
    functions: list[FunctionInfo],
    selected: int,
    disasm_text: str,
    cfg_stats: Optional[CFGStats],
    llm_content: str,
) -> None:
    console.clear()

    func_name = functions[selected].name if functions else "—"

    layout = Layout()
    layout.split_column(
        Layout(name="main", ratio=1),
        Layout(name="statusbar", size=1),
    )
    layout["main"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=2),
    )
    layout["left"].split_column(
        Layout(name="funclist", ratio=3),
        Layout(name="cfg", ratio=2),
    )
    layout["right"].split_column(
        Layout(name="disasm", ratio=1),
        Layout(name="llm", ratio=1),
    )

    layout["funclist"].update(_make_function_list(functions, selected))
    layout["cfg"].update(_make_cfg_panel(cfg_stats))
    layout["disasm"].update(_make_disasm_panel(disasm_text, func_name))
    layout["llm"].update(_make_llm_panel(llm_content))
    layout["statusbar"].update(Text.from_markup(_status_bar()))

    console.print(layout)
