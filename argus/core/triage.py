"""False-positive triage.

A false positive and an accepted risk are different claims, and conflating them
would be dishonest. An accepted risk (``exceptions:`` in ``argus.yaml``) says *this
finding is real and we are living with it* — so it stays fully visible and only
stops gating. A triage entry says *the scanner was wrong* — so it stops counting
altogether.

Neither ever disappears. A suppressed finding is counted, listed, and carries the
reason it was suppressed, because a scanner that can silently drop findings is a
scanner whose clean report means nothing.

Entries are matched on a fingerprint of the finding's own evidence rather than on
its check id alone. Suppressing ``MCP-013`` for a server would otherwise disable
that check for that server permanently, including for a genuine hit later.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .exceptions import ArgusConfigError
from .models import Finding
from .safe_io import read_yaml

#: Bumped only if the file's shape changes incompatibly.
TRIAGE_VERSION = 1

DEFAULT_TRIAGE_FILE = ".argus-triage.yaml"


def fingerprint(finding: Finding) -> str:
    """A stable identity for one finding.

    Built from the check, the asset and the *content* of the evidence — not its line
    number, so moving code does not churn the file, and not its directory, so the
    file stays meaningful on another machine. Changing the matched text changes the
    fingerprint, which is the point: an edited finding is a new finding and must be
    looked at again rather than inheriting an old verdict.
    """
    parts = [finding.check_id, finding.asset]
    if finding.evidence:
        parts.extend(
            sorted(
                "|".join(
                    (
                        Path(item.path).name if item.path else "",
                        item.key or "",
                        item.snippet or "",
                    )
                )
                for item in finding.evidence
            )
        )
    else:
        # Some findings carry no evidence; the detail is then all that identifies them.
        parts.append(finding.detail)
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class TriageEntry:
    """One finding a human has judged to be a false positive."""

    fingerprint: str
    reason: str
    check_id: str = ""
    asset: str = ""
    added: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "fingerprint": self.fingerprint,
            "check_id": self.check_id,
            "asset": self.asset,
            "reason": self.reason,
            "added": self.added,
        }


def load_triage(path: Path) -> list[TriageEntry]:
    """Read a triage file. A missing file is not an error — it is the normal case."""
    if not path.is_file():
        return []
    data = read_yaml(path)
    if data is None:
        raise ArgusConfigError(f"{path}: not valid YAML")
    if not isinstance(data, dict):
        raise ArgusConfigError(f"{path}: expected a mapping at the top level")

    entries = data.get("suppressed") or []
    if not isinstance(entries, list):
        raise ArgusConfigError(f"{path}: 'suppressed' must be a list")

    out: list[TriageEntry] = []
    for index, raw in enumerate(entries, start=1):
        if not isinstance(raw, dict):
            raise ArgusConfigError(f"{path}: entry {index} must be a mapping")
        mark = str(raw.get("fingerprint") or "").strip()
        reason = str(raw.get("reason") or "").strip()
        if not mark:
            raise ArgusConfigError(f"{path}: entry {index} has no fingerprint")
        # A suppression without a stated reason is an unexplained hole in the report.
        if not reason:
            raise ArgusConfigError(
                f"{path}: entry {index} ({mark}) has no reason. Every suppression must "
                "say why the finding is wrong."
            )
        out.append(
            TriageEntry(
                fingerprint=mark,
                reason=reason,
                check_id=str(raw.get("check_id") or ""),
                asset=str(raw.get("asset") or ""),
                added=str(raw.get("added") or ""),
            )
        )
    return out


def save_triage(path: Path, entries: list[TriageEntry]) -> None:
    """Write the triage file, newest entries last."""
    import yaml

    document = {
        "version": TRIAGE_VERSION,
        "suppressed": [e.to_dict() for e in entries],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def apply_triage(findings: list[Finding], entries: list[TriageEntry]) -> list[str]:
    """Mark matching findings as suppressed. Returns entries that matched nothing.

    An entry that no longer matches is reported rather than dropped: either the
    finding was fixed, or it changed and is now being reported afresh under a new
    fingerprint. Both are worth telling the operator about.
    """
    if not entries:
        return []
    by_mark = {e.fingerprint: e for e in entries}
    matched: set[str] = set()

    for finding in findings:
        entry = by_mark.get(fingerprint(finding))
        if entry is None:
            continue
        finding.suppressed = True
        finding.suppression_reason = entry.reason
        matched.add(entry.fingerprint)

    return [
        f"{e.check_id or e.fingerprint}"
        + (f" on {e.asset}" if e.asset else "")
        + " no longer matches any finding — it was fixed, or it changed and is being "
        "reported again"
        for e in entries
        if e.fingerprint not in matched
    ]


def new_entry(finding: Finding, reason: str) -> TriageEntry:
    return TriageEntry(
        fingerprint=fingerprint(finding),
        reason=reason.strip(),
        check_id=finding.check_id,
        asset=finding.asset,
        added=_dt.date.today().isoformat(),
    )
