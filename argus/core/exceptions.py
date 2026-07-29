"""Argus exception hierarchy.

Exit-code mapping (see spec 3.5):
    ArgusConfigError -> 3 (usage/configuration error)
    ArgusScanError   -> 2 (scanner error)
"""

from __future__ import annotations


class ArgusError(Exception):
    """Base class for all Argus errors."""


class ArgusConfigError(ArgusError):
    """Invalid CLI usage or malformed argus.yaml. Exits 3."""


class ArgusScanError(ArgusError):
    """The scan itself could not complete. Exits 2."""


class UnsafePathError(ArgusError):
    """A path escaped its permitted scan root, or resolved through a hostile symlink."""


class FileTooLargeError(ArgusError):
    """A candidate file exceeded the configured read cap."""
