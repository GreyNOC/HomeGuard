"""HomeGuard."""

from __future__ import annotations

import builtins as _builtins

from .baseline import TRUST_QUARANTINED as _TRUST_QUARANTINED
from .baseline import TRUST_TRUSTED as _TRUST_TRUSTED

__version__ = "1.0.2"

# Compatibility guard for CLI builds that reference the trust constants from
# module scope without importing them. This keeps GNHL --status from crashing
# until cli.py can be simplified in a follow-up direct edit.
if not hasattr(_builtins, "TRUST_TRUSTED"):
    _builtins.TRUST_TRUSTED = _TRUST_TRUSTED
if not hasattr(_builtins, "TRUST_QUARANTINED"):
    _builtins.TRUST_QUARANTINED = _TRUST_QUARANTINED
