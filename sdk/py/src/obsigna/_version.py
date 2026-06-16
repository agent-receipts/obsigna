"""Package version, derived from installed package metadata.

Reading the version from ``importlib.metadata`` keeps it in lockstep with
``pyproject.toml`` automatically — no second hand-maintained constant to
forget bumping. ``pyproject.toml`` is the single source of truth.

If the package is imported from a checkout that hasn't been installed
(e.g. running ``python -m`` against ``src/`` without ``uv sync`` or
``pip install -e .`` first), ``importlib.metadata.version`` raises
``PackageNotFoundError``. We surface a clearly-fake fallback so a stray
import in such an environment doesn't crash on import — but every test
and supported user path installs the package, so this fallback should
never be observed in practice.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def _resolve_version() -> str:
    try:
        return version("obsigna")
    except PackageNotFoundError:
        return "0.0.0+unknown"


VERSION = _resolve_version()
