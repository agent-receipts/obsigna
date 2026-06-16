"""Deprecation shim for the renamed ``agent-receipts`` distribution.

The Python SDK is now published as **obsigna**. This package keeps the old
``agent-receipts`` distribution name installable so existing pins and imports
keep working, but it ships no implementation of its own: importing
``agent_receipts`` (or any ``agent_receipts.*`` submodule) transparently
resolves to the corresponding ``obsigna`` module and emits a
``DeprecationWarning``.

Migrate by replacing the dependency and the imports::

    pip install obsigna

    # before
    from agent_receipts import create_receipt
    from agent_receipts.receipt.create import ActionInput

    # after
    from obsigna import create_receipt
    from obsigna.receipt.create import ActionInput
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys
import warnings

_NEW = "obsigna"

warnings.warn(
    "The 'agent-receipts' distribution has been renamed to 'obsigna'. "
    "It is deprecated and now only re-exports 'obsigna'. Install 'obsigna' "
    "and update imports from 'agent_receipts' to 'obsigna'.",
    DeprecationWarning,
    stacklevel=2,
)


class _ObsignaAliasFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Resolve ``agent_receipts`` and any ``agent_receipts.<sub>`` import to
    the matching ``obsigna`` module, so the full submodule surface keeps
    working under the legacy name."""

    _PREFIX = __name__ + "."

    def find_spec(self, fullname, path=None, target=None):
        if fullname != __name__ and not fullname.startswith(self._PREFIX):
            return None
        return importlib.util.spec_from_loader(fullname, self)

    def create_module(self, spec):
        target_name = _NEW + spec.name[len(__name__):]
        module = importlib.import_module(target_name)
        sys.modules[spec.name] = module
        return module

    def exec_module(self, module):  # already populated by import_module
        pass


# Insert ahead of the default finders so submodule imports redirect.
if not any(isinstance(f, _ObsignaAliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _ObsignaAliasFinder())

# Mirror obsigna's top-level namespace onto this shim package.
_obsigna = importlib.import_module(_NEW)
for _name in getattr(_obsigna, "__all__", None) or [
    n for n in vars(_obsigna) if not n.startswith("_")
]:
    globals()[_name] = getattr(_obsigna, _name)

__all__ = list(getattr(_obsigna, "__all__", []))
__version__ = getattr(_obsigna, "VERSION", getattr(_obsigna, "__version__", ""))
