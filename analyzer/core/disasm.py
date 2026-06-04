from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

import capstone

ARCH = capstone.CS_ARCH_X86
MODE = capstone.CS_MODE_64

# Branch/terminator mnemonics
BRANCH_GROUPS = {capstone.x86.X86_GRP_JUMP, capstone.x86.X86_GRP_RET, capstone.x86.X86_GRP_CALL}
BRANCH_MNEMONICS = {
    "jmp", "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp",
    "jcxz", "jecxz", "jrcxz", "ret", "retq", "retn", "retf", "call",
    "loop", "loope", "loopne",
}


@dataclass
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    bytes: bytes
    is_branch: bool = False
    is_ret: bool = False
    is_call: bool = False

    @property
    def display(self) -> str:
        hex_bytes = " ".join(f"{b:02x}" for b in self.bytes)
        return f"0x{self.address:08x}  {hex_bytes:<20}  {self.mnemonic:<8} {self.op_str}"


@dataclass
class BasicBlock:
    start: int
    end: int
    instructions: list[Instruction] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)


def disassemble(data: bytes, base_address: int) -> list[Instruction]:
    md = capstone.Cs(ARCH, MODE)
    md.detail = True
    instructions: list[Instruction] = []
    for insn in md.disasm(data, base_address):
        mnem = insn.mnemonic.lower()
        is_branch = mnem in BRANCH_MNEMONICS or bool(
            set(insn.groups) & BRANCH_GROUPS
        )
        is_ret = mnem.startswith("ret")
        is_call = mnem == "call"
        instructions.append(
            Instruction(
                address=insn.address,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes=bytes(insn.bytes),
                is_branch=is_branch,
                is_ret=is_ret,
                is_call=is_call,
            )
        )
    return instructions


def extract_basic_blocks(instructions: list[Instruction]) -> list[BasicBlock]:
    if not instructions:
        return []

    # Collect leader addresses
    leaders: set[int] = {instructions[0].address}
    for i, insn in enumerate(instructions):
        if insn.is_branch:
            # Next instruction is a leader
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].address)
            # Try to parse branch target
            try:
                target = int(insn.op_str.strip(), 16)
                leaders.add(target)
            except (ValueError, OverflowError):
                pass

    addr_to_idx = {insn.address: idx for idx, insn in enumerate(instructions)}
    leader_list = sorted(leaders)

    blocks: list[BasicBlock] = []
    for li, leader in enumerate(leader_list):
        if leader not in addr_to_idx:
            continue
        start_idx = addr_to_idx[leader]
        # End at next leader or end of instructions
        if li + 1 < len(leader_list):
            next_leader = leader_list[li + 1]
            end_idx = addr_to_idx.get(next_leader, len(instructions))
        else:
            end_idx = len(instructions)

        block_insns = instructions[start_idx:end_idx]
        if not block_insns:
            continue

        last = block_insns[-1]
        successors: list[int] = []
        if last.is_branch and not last.is_ret:
            # Try to parse explicit target
            try:
                target = int(last.op_str.strip(), 16)
                successors.append(target)
            except (ValueError, OverflowError):
                pass
            # Conditional branches also fall through
            if last.mnemonic.lower() not in ("jmp",) and li + 1 < len(leader_list):
                ft = leader_list[li + 1]
                if ft not in successors:
                    successors.append(ft)
        elif not last.is_ret:
            # Fall-through
            if li + 1 < len(leader_list):
                successors.append(leader_list[li + 1])

        blocks.append(
            BasicBlock(
                start=leader,
                end=block_insns[-1].address,
                instructions=block_insns,
                successors=successors,
            )
        )
    return blocks


def format_disassembly(instructions: list[Instruction]) -> str:
    return "\n".join(insn.display for insn in instructions)
