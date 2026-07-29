"""Check registry.

Checks self-register with the ``@register`` decorator, so adding a check never
requires editing the engine (spec 4).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, Protocol, TypeVar, cast

from .exceptions import ArgusConfigError
from .models import Category, CheckMeta, Target


class CheckClass(Protocol):
    """Structural type for a registered check.

    Declared as a Protocol rather than the concrete ``Check`` base class because
    ``argus.checks.base`` imports this module — naming it directly would be a
    circular import. Only ``meta`` is declared, since that is all the registry
    itself reads.
    """

    meta: CheckMeta

    def run(self, context: Any) -> list[Any]: ...


C = TypeVar("C", bound=type)

_REGISTRY: dict[str, type[CheckClass]] = {}


def register(cls: C) -> C:
    """Class decorator that adds a check to the global registry."""
    meta = getattr(cls, "meta", None)
    if meta is None:
        raise ArgusConfigError(f"{cls.__name__} has no 'meta' attribute")
    if meta.check_id in _REGISTRY:
        raise ArgusConfigError(f"duplicate check id: {meta.check_id}")
    _REGISTRY[meta.check_id] = cast("type[CheckClass]", cls)
    return cls


def all_checks() -> list[type[CheckClass]]:
    """Every registered check, ordered by category section then numeric id."""
    return sorted(
        _REGISTRY.values(),
        key=lambda c: (c.meta.category.section, int(c.meta.check_id.rsplit("-", 1)[-1])),
    )


def get_check(check_id: str) -> type[CheckClass] | None:
    """Look a check up by check ID ('MCP-003') or AASB number ('2.3')."""
    key = check_id.strip().upper()
    if key in _REGISTRY:
        return _REGISTRY[key]
    for cls in _REGISTRY.values():
        if cls.meta.aasb == check_id.strip():
            return cls
    return None


def select(
    *,
    targets: Iterable[Target] | None = None,
    categories: Iterable[Category] | None = None,
    include_ids: Iterable[str] | None = None,
    exclude_ids: Iterable[str] | None = None,
    level: int | None = None,
) -> list[type[CheckClass]]:
    """Resolve a check selection.

    Composition order is fixed by spec 9: start from target/category/level, intersect
    with ``include_ids`` when given, then subtract ``exclude_ids``. Exclusion always
    wins over inclusion.
    """
    target_set = set(targets) if targets else None
    category_set = set(categories) if categories else None
    include_set = {i.strip().upper() for i in include_ids} if include_ids else None
    exclude_set = {e.strip().upper() for e in exclude_ids} if exclude_ids else set()

    selected: list[type[CheckClass]] = []
    for cls in all_checks():
        meta = cls.meta
        if target_set is not None and not (meta.applies_to & target_set):
            continue
        if category_set is not None and meta.category not in category_set:
            continue
        if level is not None and meta.aasb_level > level:
            continue
        if include_set is not None and meta.check_id not in include_set:
            continue
        if meta.check_id in exclude_set:
            continue
        selected.append(cls)
    return selected


def iter_meta() -> Iterator[CheckMeta]:
    for cls in all_checks():
        yield cls.meta


def clear() -> None:
    """Test-only helper: drop all registrations."""
    _REGISTRY.clear()
