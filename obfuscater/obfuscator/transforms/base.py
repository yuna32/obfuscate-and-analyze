"""Abstract base class for all obfuscation transforms."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from core.elf_parser import ELFInfo

logger = logging.getLogger(__name__)


class Transform(ABC):
    name: str = "base"

    def apply(self, raw: bytearray, info: ELFInfo) -> tuple[bytearray, int]:
        """
        Apply this transform to the raw ELF bytes.

        Returns:
            (modified_bytearray, count)
            count: number of items injected/transformed by this layer.
        """
        sec = info.section(".text")
        before = sec.size if sec else 0

        raw, count = self._apply(raw, info)

        sec_after = info.section(".text")
        after = sec_after.size if sec_after else 0
        delta = after - before
        sign = "+" if delta >= 0 else ""
        logger.info("[%s] .text size: %d → %d (%s%d bytes)",
                    self.name, before, after, sign, delta)
        return raw, count

    @abstractmethod
    def _apply(self, raw: bytearray, info: ELFInfo) -> tuple[bytearray, int]:
        """Subclasses return (modified_raw, count)."""
        ...
