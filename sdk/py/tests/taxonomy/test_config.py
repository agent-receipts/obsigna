"""Tests for taxonomy configuration loading."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from obsigna.taxonomy.config import load_taxonomy_config


class TestLoadTaxonomyConfig:
    def test_load_valid_config(self, tmp_path: Path) -> None:
        config = {
            "mappings": [
                {"tool_name": "write_file", "action_type": "filesystem.file.create"},
                {"tool_name": "read_file", "action_type": "filesystem.file.read"},
            ],
        }
        config_file = tmp_path / "taxonomy.json"
        config_file.write_text(json.dumps(config))

        result = load_taxonomy_config(str(config_file))
        assert len(result) == 2
        assert result[0].tool_name == "write_file"
        assert result[0].action_type == "filesystem.file.create"
        assert result[1].tool_name == "read_file"
        assert result[1].action_type == "filesystem.file.read"

    def test_load_invalid_structure(self, tmp_path: Path) -> None:
        config_file = tmp_path / "taxonomy.json"
        config_file.write_text(json.dumps(["not", "a", "dict"]))

        with pytest.raises(ValueError, match="Invalid taxonomy config"):
            load_taxonomy_config(str(config_file))

    def test_load_invalid_mapping_entry(self, tmp_path: Path) -> None:
        config = {"mappings": [{"tool_name": "write_file"}]}
        config_file = tmp_path / "taxonomy.json"
        config_file.write_text(json.dumps(config))

        with pytest.raises(ValueError, match="Invalid taxonomy mapping"):
            load_taxonomy_config(str(config_file))

    def test_load_duplicate_tool_name(self, tmp_path: Path) -> None:
        config = {
            "mappings": [
                {"tool_name": "write_file", "action_type": "filesystem.file.create"},
                {"tool_name": "write_file", "action_type": "filesystem.file.modify"},
            ],
        }
        config_file = tmp_path / "taxonomy.json"
        config_file.write_text(json.dumps(config))

        with pytest.raises(ValueError, match="Duplicate taxonomy mapping"):
            load_taxonomy_config(str(config_file))

    def test_load_unknown_action_type(self, tmp_path: Path) -> None:
        config = {
            "mappings": [
                {"tool_name": "my_tool", "action_type": "bogus.action"},
            ],
        }
        config_file = tmp_path / "taxonomy.json"
        config_file.write_text(json.dumps(config))

        with pytest.raises(ValueError, match="Unknown action type"):
            load_taxonomy_config(str(config_file))

    def test_load_empty_mappings(self, tmp_path: Path) -> None:
        config = {"mappings": []}
        config_file = tmp_path / "taxonomy.json"
        config_file.write_text(json.dumps(config))

        result = load_taxonomy_config(str(config_file))
        assert result == []
