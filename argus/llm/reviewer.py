"""Orchestrates LLM review: select assets, sanitise, call, parse.

Failures are contained. A provider outage, a rate limit, or a model returning prose
instead of JSON must degrade to "no LLM findings" and let the static scan stand —
never abort a security scan because an optional enrichment stage failed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..core.models import Asset, Confidence, Severity, Target
from . import prompts
from .providers import LLMError, Provider, build_provider, consent_line
from .sanitize import DEFAULT_MAX_BYTES, sanitise_asset

#: Review passes, each mapped to the targets it consumes.
PASSES: dict[str, tuple[str, tuple[Target, ...]]] = {
    "injection": (prompts.INJECTION_REVIEW, (Target.INSTRUCTIONS, Target.SKILLS)),
    "mcp": (prompts.MCP_REVIEW, (Target.MCP,)),
    "hooks": (prompts.HOOK_REVIEW, (Target.HOOKS,)),
    "trifecta": (prompts.TRIFECTA_REVIEW, (Target.CLAUDE_CODE, Target.MCP, Target.SKILLS)),
}


@dataclass
class LLMConfig:
    enabled: bool = False
    provider: str = "openai"
    model: str | None = None
    timeout: int = 60
    max_assets: int = 20
    max_bytes_per_asset: int = DEFAULT_MAX_BYTES
    passes: tuple[str, ...] = tuple(PASSES)
    api_key: str | None = None
    transport: object | None = None  # test seam


@dataclass
class LLMFinding:
    """A model-reported concern, before it becomes an Argus Finding."""

    pass_name: str
    asset_id: str
    severity: Severity
    title: str
    rationale: str
    evidence: str
    confidence: Confidence
    provider: str
    model: str


@dataclass
class ReviewResult:
    findings: list[LLMFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    consent: str = ""
    assets_sent: int = 0
    passes_run: list[str] = field(default_factory=list)


def _asset_text(asset: Asset) -> str:
    if asset.target is Target.SKILLS:
        return str(asset.data.get("body") or asset.text or "")
    return str(asset.text or "")


def _asset_kind(asset: Asset) -> str:
    return asset.target.value


def _select(assets: list[Asset], targets: tuple[Target, ...], limit: int) -> list[Asset]:
    """Largest-first within the requested targets, capped.

    Bigger assets carry more surface, so under a budget they are the better spend.
    """
    candidates = [a for a in assets if a.target in targets and _asset_text(a).strip()]
    candidates.sort(key=lambda a: len(_asset_text(a)), reverse=True)
    return candidates[:limit]


_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def _parse_findings(
    text: str, pass_name: str, provider: str, model: str, known_ids: set[str]
) -> tuple[list[LLMFinding], list[str]]:
    """Parse a model response. Anything malformed is dropped, not guessed at."""
    errors: list[str] = []
    if not text or not text.strip():
        return [], []

    match = _JSON_BLOCK.search(text)
    if not match:
        return [], [f"{pass_name}: response contained no JSON object"]

    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        return [], [f"{pass_name}: malformed JSON ({exc.msg})"]

    raw = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return [], [f"{pass_name}: response had no 'findings' list"]

    out: list[LLMFinding] = []
    for entry in raw[:50]:
        if not isinstance(entry, dict):
            continue
        asset_id = str(entry.get("asset_id") or "").strip()
        title = str(entry.get("title") or "").strip()
        if not title:
            continue
        # A model may hallucinate an asset it was never shown; attribute those to the
        # pass rather than to a file that does not exist.
        if asset_id not in known_ids:
            asset_id = f"(unattributed:{pass_name})"
        try:
            severity = Severity.parse(str(entry.get("severity") or "MEDIUM"))
        except ValueError:
            severity = Severity.MEDIUM
        confidence_raw = str(entry.get("confidence") or "LOW").strip().upper()
        confidence = (
            Confidence[confidence_raw] if confidence_raw in Confidence.__members__ else Confidence.LOW
        )
        out.append(
            LLMFinding(
                pass_name=pass_name,
                asset_id=asset_id,
                severity=severity,
                title=title[:120],
                rationale=str(entry.get("rationale") or "")[:600],
                evidence=str(entry.get("evidence") or "")[:300],
                confidence=confidence,
                provider=provider,
                model=model,
            )
        )
    return out, errors


def review(
    assets: list[Asset],
    config: LLMConfig,
    *,
    home: Path | None = None,
    provider: Provider | None = None,
) -> ReviewResult:
    """Run the enabled review passes. Never raises."""
    result = ReviewResult()
    if not config.enabled:
        return result

    try:
        active = provider or build_provider(
            config.provider,
            model=config.model,
            timeout=config.timeout,
            api_key=config.api_key,
            transport=config.transport,
        )
    except LLMError as exc:
        result.errors.append(str(exc))
        return result

    sent_ids: set[str] = set()

    for pass_name in config.passes:
        if pass_name not in PASSES:
            result.errors.append(f"unknown review pass '{pass_name}'")
            continue
        template, targets = PASSES[pass_name]

        selected = _select(assets, targets, config.max_assets)
        if not selected:
            continue

        payload = [
            sanitise_asset(
                a.asset_id,
                _asset_kind(a),
                str(a.path or a.asset_id),
                _asset_text(a),
                max_bytes=config.max_bytes_per_asset,
                home=home,
            ).to_payload()
            for a in selected
        ]
        sent_ids.update(str(p["asset_id"]) for p in payload)

        user_prompt = template.format(assets=prompts.render_assets(payload))
        try:
            response = active.complete(prompts.SYSTEM, user_prompt)
        except LLMError as exc:
            result.errors.append(str(exc))
            continue

        findings, errors = _parse_findings(
            response.text, pass_name, active.name, response.model,
            {str(p["asset_id"]) for p in payload},
        )
        result.findings.extend(findings)
        result.errors.extend(errors)
        result.passes_run.append(pass_name)

    result.assets_sent = len(sent_ids)
    result.consent = consent_line(active, result.assets_sent)
    return result
