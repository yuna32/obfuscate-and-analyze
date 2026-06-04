"""Obfuscation transform registry."""

from .l1_junk import L1JunkTransform
from .l2_opaque import L2OpaqueTransform
from .l3_flatten import L3FlattenTransform
from .l4_strings import L4StringTransform

REGISTRY = {
    "L1": L1JunkTransform,
    "L2": L2OpaqueTransform,
    "L3": L3FlattenTransform,
    "L4": L4StringTransform,
}
