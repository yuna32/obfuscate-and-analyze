from __future__ import annotations
from dataclasses import dataclass

import networkx as nx

from .disasm import BasicBlock


@dataclass
class CFGStats:
    num_blocks: int
    num_edges: int
    cyclomatic_complexity: int
    longest_path: int


def build_cfg(blocks: list[BasicBlock]) -> nx.DiGraph:
    g: nx.DiGraph = nx.DiGraph()
    block_starts = {b.start for b in blocks}

    for block in blocks:
        g.add_node(block.start)
        for succ in block.successors:
            if succ in block_starts:
                g.add_edge(block.start, succ)

    return g


def compute_stats(g: nx.DiGraph, blocks: list[BasicBlock]) -> CFGStats:
    n = g.number_of_nodes()
    e = g.number_of_edges()

    # Cyclomatic complexity: M = E - N + 2
    cc = max(e - n + 2, 1) if n > 0 else 1

    # Longest path (only for DAGs; fall back to number of nodes for cyclic)
    try:
        lp = nx.dag_longest_path_length(g) if nx.is_directed_acyclic_graph(g) else n
    except Exception:
        lp = n

    return CFGStats(
        num_blocks=len(blocks),
        num_edges=e,
        cyclomatic_complexity=cc,
        longest_path=lp,
    )
