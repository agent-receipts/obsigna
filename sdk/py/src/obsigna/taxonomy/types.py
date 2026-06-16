"""Core taxonomy types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from obsigna.receipt.types import RiskLevel


@dataclass(frozen=True)
class ActionTypeEntry:
    """A single action type with its risk level."""

    type: str
    description: str
    risk_level: RiskLevel


@dataclass(frozen=True)
class TaxonomyMapping:
    """Maps a tool name to an action type string."""

    tool_name: str
    action_type: str
