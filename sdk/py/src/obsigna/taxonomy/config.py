"""Load taxonomy configuration from JSON files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from obsigna.taxonomy.actions import get_action_type
from obsigna.taxonomy.types import TaxonomyMapping


def load_taxonomy_config(file_path: str) -> list[TaxonomyMapping]:
    """Load taxonomy mappings from a JSON configuration file."""
    raw = Path(file_path).read_text(encoding="utf-8")
    parsed: object = json.loads(raw)

    if not isinstance(parsed, dict):
        msg = 'Invalid taxonomy config: expected { "mappings": [...] }'
        raise ValueError(msg)
    parsed_dict = cast("dict[str, Any]", parsed)
    raw_mappings = parsed_dict.get("mappings")
    if not isinstance(raw_mappings, list):
        msg = 'Invalid taxonomy config: expected { "mappings": [...] }'
        raise ValueError(msg)

    mappings_list = cast("list[Any]", raw_mappings)
    seen: set[str] = set()
    result: list[TaxonomyMapping] = []

    for entry in mappings_list:
        if not isinstance(entry, dict):
            msg = (
                "Invalid taxonomy mapping: each entry must have "
                'non-empty "tool_name" and "action_type" strings'
            )
            raise ValueError(msg)
        entry_dict = cast("dict[str, Any]", entry)
        tool_name: object = entry_dict.get("tool_name")
        action_type: object = entry_dict.get("action_type")
        if (
            not isinstance(tool_name, str)
            or not isinstance(action_type, str)
            or not tool_name
            or not action_type
        ):
            msg = (
                "Invalid taxonomy mapping: each entry must have "
                'non-empty "tool_name" and "action_type" strings'
            )
            raise ValueError(msg)
        if get_action_type(action_type) is None:
            msg = f'Unknown action type "{action_type}" for tool_name "{tool_name}"'
            raise ValueError(msg)
        if tool_name in seen:
            msg = f'Duplicate taxonomy mapping for tool_name "{tool_name}"'
            raise ValueError(msg)
        seen.add(tool_name)
        result.append(TaxonomyMapping(tool_name=tool_name, action_type=action_type))

    return result
