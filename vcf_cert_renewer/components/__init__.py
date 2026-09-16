"""Component adapter registry and normalized inventory."""

from .base import Capability, InventoryTarget
from .registry import adapter_for, discover_inventory, plan_inventory

__all__ = ["Capability", "InventoryTarget", "adapter_for",
           "discover_inventory", "plan_inventory"]
