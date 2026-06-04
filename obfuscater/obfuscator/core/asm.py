"""Assembly helpers using Keystone."""

from __future__ import annotations

import keystone


_ks: keystone.Ks | None = None


def _get_ks() -> keystone.Ks:
    global _ks
    if _ks is None:
        _ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    return _ks


def assemble(asm_text: str, base_addr: int = 0) -> bytes:
    """Assemble a string of x86-64 instructions, return raw bytes."""
    ks = _get_ks()
    encoding, _ = ks.asm(asm_text, addr=base_addr)
    return bytes(encoding)


def assemble_insn(mnemonic: str, op_str: str = "", base_addr: int = 0) -> bytes:
    src = mnemonic if not op_str else f"{mnemonic} {op_str}"
    return assemble(src, base_addr)
