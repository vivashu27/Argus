"""Logging setup.

Named ``log`` rather than ``logging`` to avoid shadowing the stdlib module
(spec 4). Log records may contain scanned content, so callers must redact before
logging — nothing here re-redacts.
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "argus"


def configure(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)

    if quiet:
        logger.setLevel(logging.ERROR)
    elif verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logger.propagate = False
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
