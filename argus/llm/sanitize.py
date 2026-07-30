"""Sanitise scanned content before it leaves the machine.

The operator chose "redacted excerpts": secrets redacted, identity stripped, and a
hard byte cap per asset. This module is the single choke point for that — no other
code in :mod:`argus.llm` is permitted to build a payload.

What is removed, and why:

* **Secrets** — a live credential must never reach a third-party API. Reuses the
  same detector the reports use, so anything Argus can find, it redacts here.
* **Home directory, username, hostname** — these identify the operator and their
  machine and add nothing to a security judgement.
* **Bulk** — an oversized asset is truncated, both to bound cost and because a
  hostile file could otherwise pad the request.

What is deliberately *kept*: the shape of sensitive paths. ``~/.ssh/id_rsa`` stays
recognisable after the home prefix is replaced, because that is precisely the signal
the reviewer needs. Stripping it would defeat the feature.
"""

from __future__ import annotations

import getpass
import re
from dataclasses import dataclass
from pathlib import Path

from ..analysis import secrets
from ..analysis.redaction import redact
from ..discovery.platform import hostname

#: Per-asset cap on what is transmitted.
DEFAULT_MAX_BYTES = 8_000

PLACEHOLDER_USER = "<user>"
PLACEHOLDER_HOST = "<host>"


@dataclass(frozen=True)
class SanitisedAsset:
    """An asset excerpt cleared for transmission."""

    asset_id: str
    kind: str
    name: str
    excerpt: str
    truncated: bool = False

    def to_payload(self) -> dict[str, str | bool]:
        return {
            "asset_id": self.asset_id,
            "kind": self.kind,
            "name": self.name,
            "content": self.excerpt,
            "truncated": self.truncated,
        }


def _identity_terms(home: Path | None = None) -> list[tuple[str, str]]:
    """Substitutions that remove operator identity, longest first."""
    terms: list[tuple[str, str]] = []

    home_path = str(home or Path.home()).rstrip("/\\")
    if home_path and home_path not in ("/", ""):
        terms.append((home_path, "~"))

    try:
        user = getpass.getuser()
    except Exception:  # getpass raises on some minimal environments
        user = ""
    if user and len(user) > 2:
        terms.append((user, PLACEHOLDER_USER))

    host = hostname()
    if host and host not in ("unknown", "localhost") and len(host) > 2:
        terms.append((host, PLACEHOLDER_HOST))

    # Longest first so a username that is a substring of the hostname does not
    # partially rewrite it and leave a fragment behind.
    terms.sort(key=lambda pair: len(pair[0]), reverse=True)
    return terms


def scrub(text: str, *, home: Path | None = None) -> str:
    """Redact secrets and strip operator identity from a block of text."""
    if not text:
        return ""

    out = text

    # 1. Secrets first: identity substitution must not split a credential and
    #    accidentally hide it from the detector.
    for pattern in secrets.HIGH_CONFIDENCE:
        def _replace(m: re.Match[str], group: int = pattern.group) -> str:
            value = m.group(group) if group else m.group(0)
            return m.group(0).replace(value, redact(value))

        out = pattern.regex.sub(_replace, out)

    # Generic high-entropy assignments, which have no fixed shape.
    for match in secrets.scan_text(out, max_findings=200):
        if match.pattern_id != "generic-secret":
            continue
        lines = out.splitlines()
        index = match.line - 1
        if 0 <= index < len(lines):
            lines[index] = secrets.GENERIC_ASSIGNMENT.sub(
                lambda m: m.group(0).replace(m.group("value"), redact(m.group("value"))),
                lines[index],
            )
            out = "\n".join(lines)

    # 2. Identity.
    for needle, replacement in _identity_terms(home):
        out = out.replace(needle, replacement)

    return out


def excerpt(
    text: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    home: Path | None = None,
) -> tuple[str, bool]:
    """Scrub then truncate. Returns ``(excerpt, was_truncated)``."""
    scrubbed = scrub(text, home=home)
    encoded = scrubbed.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return scrubbed, False
    clipped = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return clipped + "\n…[truncated by Argus before transmission]", True


def sanitise_asset(
    asset_id: str,
    kind: str,
    name: str,
    text: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    home: Path | None = None,
) -> SanitisedAsset:
    """Build a transmittable excerpt for one asset.

    ``name`` is reduced to a basename: the reviewer needs to know it is a
    ``SKILL.md``, not where on disk it lives.
    """
    body, truncated = excerpt(text, max_bytes=max_bytes, home=home)
    return SanitisedAsset(
        asset_id=asset_id,
        kind=kind,
        name=Path(str(name)).name or str(name),
        excerpt=body,
        truncated=truncated,
    )


def contains_identity(text: str, *, home: Path | None = None) -> list[str]:
    """Any operator-identifying term still present. Used as a test assertion."""
    return [needle for needle, _sub in _identity_terms(home) if needle in text]
