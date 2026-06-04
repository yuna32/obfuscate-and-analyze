from __future__ import annotations

import readchar

UP_KEYS = {readchar.key.UP, "k"}
DOWN_KEYS = {readchar.key.DOWN, "j"}


def read_key() -> str:
    return readchar.readkey()
