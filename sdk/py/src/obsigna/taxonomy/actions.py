"""Built-in action type definitions."""

from __future__ import annotations

from obsigna.taxonomy.types import ActionTypeEntry

FILESYSTEM_ACTIONS: list[ActionTypeEntry] = [
    ActionTypeEntry(
        type="filesystem.file.create",
        description="Create a file",
        risk_level="low",
    ),
    ActionTypeEntry(
        type="filesystem.file.read",
        description="Read a file",
        risk_level="low",
    ),
    ActionTypeEntry(
        type="filesystem.file.modify",
        description="Modify a file",
        risk_level="medium",
    ),
    ActionTypeEntry(
        type="filesystem.file.delete",
        description="Delete a file",
        risk_level="high",
    ),
    ActionTypeEntry(
        type="filesystem.file.move",
        description="Move or rename a file",
        risk_level="medium",
    ),
    ActionTypeEntry(
        type="filesystem.directory.create",
        description="Create a directory",
        risk_level="low",
    ),
    ActionTypeEntry(
        type="filesystem.directory.delete",
        description="Delete a directory",
        risk_level="high",
    ),
]

SYSTEM_ACTIONS: list[ActionTypeEntry] = [
    ActionTypeEntry(
        type="system.application.launch",
        description="Launch an application",
        risk_level="low",
    ),
    ActionTypeEntry(
        type="system.application.control",
        description="Control an application via UI automation",
        risk_level="medium",
    ),
    ActionTypeEntry(
        type="system.settings.modify",
        description="Modify system or app settings",
        risk_level="high",
    ),
    ActionTypeEntry(
        type="system.command.execute",
        description="Execute a shell command",
        risk_level="high",
    ),
    ActionTypeEntry(
        type="system.browser.navigate",
        description="Navigate to a URL",
        risk_level="low",
    ),
    ActionTypeEntry(
        type="system.browser.form_submit",
        description="Submit a web form",
        risk_level="medium",
    ),
    ActionTypeEntry(
        type="system.browser.authenticate",
        description="Log into a service",
        risk_level="high",
    ),
]

DATA_ACTIONS: list[ActionTypeEntry] = [
    ActionTypeEntry(
        type="data.api.read",
        description="Read data from an external API",
        risk_level="low",
    ),
    ActionTypeEntry(
        type="data.api.write",
        description="Write data to an external API",
        risk_level="medium",
    ),
    ActionTypeEntry(
        type="data.api.delete",
        description="Delete data via an external API",
        risk_level="high",
    ),
]

UNKNOWN_ACTION: ActionTypeEntry = ActionTypeEntry(
    type="unknown",
    description="Tool call that does not map to any known action type",
    risk_level="medium",
)

ALL_ACTIONS: list[ActionTypeEntry] = [
    *FILESYSTEM_ACTIONS,
    *SYSTEM_ACTIONS,
    *DATA_ACTIONS,
    UNKNOWN_ACTION,
]

_ACTION_MAP: dict[str, ActionTypeEntry] = {entry.type: entry for entry in ALL_ACTIONS}


def get_action_type(action_type: str) -> ActionTypeEntry | None:
    """Look up an action type by its type string, returning ``None`` if not found."""
    return _ACTION_MAP.get(action_type)


def resolve_action_type(action_type: str) -> ActionTypeEntry:
    """Look up an action type by its type string, falling back to ``UNKNOWN_ACTION``."""
    return _ACTION_MAP.get(action_type, UNKNOWN_ACTION)
