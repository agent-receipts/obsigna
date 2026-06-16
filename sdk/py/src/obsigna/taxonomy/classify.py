"""Classify tool calls into action types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from obsigna.taxonomy.actions import UNKNOWN_ACTION, resolve_action_type

if TYPE_CHECKING:
    from obsigna.receipt.types import RiskLevel
    from obsigna.taxonomy.types import TaxonomyMapping


@dataclass(frozen=True)
class ClassificationResult:
    """Result of classifying a tool call."""

    action_type: str
    risk_level: RiskLevel


def classify_tool_call(
    tool_name: str,
    mappings: list[TaxonomyMapping] | None = None,
) -> ClassificationResult:
    """Classify a tool call using optional taxonomy mappings."""
    effective_mappings = mappings or []
    mapping = next(
        (m for m in effective_mappings if m.tool_name == tool_name),
        None,
    )
    action_type = mapping.action_type if mapping else UNKNOWN_ACTION.type
    entry = resolve_action_type(action_type)
    return ClassificationResult(action_type=entry.type, risk_level=entry.risk_level)
