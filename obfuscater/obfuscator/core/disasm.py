"""Disassembly helpers using Capstone."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

import capstone


@dataclass
class Instruction:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes

    @property
    def is_branch(self) -> bool:
        return self.mnemonic in {
            "jmp", "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
            "jb", "jbe", "ja", "jae", "js", "jns", "jo", "jno", "jp", "jnp",
            "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
        }

    @property
    def is_call(self) -> bool:
        return self.mnemonic == "call"

    @property
    def is_ret(self) -> bool:
        return self.mnemonic in {"ret", "retn", "retf"}

    @property
    def is_block_end(self) -> bool:
        return self.is_branch or self.is_ret or self.is_call


@dataclass
class BasicBlock:
    start_addr: int
    instructions: List[Instruction] = field(default_factory=list)

    @property
    def end_addr(self) -> int:
        if not self.instructions:
            return self.start_addr
        last = self.instructions[-1]
        return last.address + last.size

    @property
    def size(self) -> int:
        return sum(i.size for i in self.instructions)


def disassemble(data: bytes, base_addr: int = 0) -> List[Instruction]:
    """Disassemble raw bytes into a list of Instruction objects."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    result = []
    for insn in md.disasm(data, base_addr):
        result.append(Instruction(
            address=insn.address,
            size=insn.size,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            bytes=bytes(insn.bytes),
        ))
    return result


def find_basic_blocks(instructions: List[Instruction]) -> List[BasicBlock]:
    """
    Split instruction list into basic blocks.
    A block ends at any branch/call/ret and a new block starts after it.
    Also starts a new block whenever the address is a known branch target.
    """
    if not instructions:
        return []

    # Collect all explicit branch targets
    targets: set[int] = set()
    for insn in instructions:
        if insn.is_branch and insn.op_str.startswith("0x"):
            try:
                targets.add(int(insn.op_str, 16))
            except ValueError:
                pass

    blocks: List[BasicBlock] = []
    current = BasicBlock(start_addr=instructions[0].address)

    for insn in instructions:
        # Start a new block if this address is a branch target
        if insn.address in targets and current.instructions:
            blocks.append(current)
            current = BasicBlock(start_addr=insn.address)

        current.instructions.append(insn)

        if insn.is_block_end:
            blocks.append(current)
            next_addr = insn.address + insn.size
            current = BasicBlock(start_addr=next_addr)

    if current.instructions:
        blocks.append(current)

    return blocks
