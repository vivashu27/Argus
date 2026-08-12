"""Orchestration for ``argus review``: prepare payloads, call the model, collect.

Kept out of :mod:`argus.cli` so the code that talks to a third party is never
imported by a plain ``argus scan``. Same separation the runtime probe had, for the
same reason: the default path should not be able to reach the egress path by
accident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .core.models import Asset, Target
from .discovery import discover_all
from .review.payload import Payload, UnsafePayload, build
from .review.reviewer import Review, review
from .rules.providers import Provider


@dataclass
class ReviewRun:
    """Everything one ``argus review`` invocation produced."""

    payloads: list[Payload] = field(default_factory=list)
    reviews: list[Review] = field(default_factory=list)
    #: Assets that could not be prepared, with why. Never silently dropped: a
    #: component missing from a review is not a component that passed.
    refused: list[tuple[str, str]] = field(default_factory=list)

    @property
    def reviewed(self) -> int:
        return sum(1 for r in self.reviews if r.usable)


def prepare(
    project_root: Path,
    *,
    home: Path | None = None,
    user_scope: bool = True,
    targets: set[Target] | None = None,
    only: set[str] | None = None,
    limit: int = 0,
) -> tuple[list[Payload], list[tuple[str, str]]]:
    """Discover reviewable assets and build their payloads.

    Separated from the sending step so the operator can be shown exactly what would
    leave the machine, and how much it will cost, before consenting to it.
    """
    from .checks.review_checks import REVIEWABLE

    wanted = targets or set(REVIEWABLE)
    assets, _ = discover_all(project_root, wanted, home=home, user_scope=user_scope)

    payloads: list[Payload] = []
    refused: list[tuple[str, str]] = []
    for asset in _select(assets, wanted, only):
        try:
            payload = build(asset)
        except UnsafePayload as exc:
            refused.append((asset.asset_id, str(exc)))
            continue
        if not payload.body.strip():
            refused.append((asset.asset_id, "nothing readable to review"))
            continue
        payloads.append(payload)
        if limit and len(payloads) >= limit:
            break
    return payloads, refused


def _select(assets: list[Asset], wanted: set[Target], only: set[str] | None) -> list[Asset]:
    return [
        a
        for a in assets
        if a.target in wanted and (not only or any(n in a.asset_id for n in only))
    ]


def run(payloads: list[Payload], provider: Provider) -> list[Review]:
    """Review each payload in turn."""
    return [review(payload, provider) for payload in payloads]
