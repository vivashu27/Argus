"""Call a model against the rubric and turn its answer into structured verdicts.

Two properties matter more than anything else here.

**A model's answer is untrusted input.** It may be malformed, may invent a check id,
may quote text that never appeared in the payload. The last is the important one: a
fabricated quote is the signature of a hallucinated finding, and since every finding
must cite a verbatim substring, the quote can simply be verified against the payload
and the finding dropped when it does not appear. That single check removes the most
common failure mode of LLM-assisted scanning at almost no cost.

**A failed review is not a clean review.** Every path that cannot produce a verdict
records why, and the checks surface that as MANUAL rather than PASS.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..rules.providers import LLMError, Provider
from .payload import Payload
from .rubric import BY_ID, SYSTEM_PROMPT, user_prompt

#: A quote shorter than this is not evidence — "the", "use" and "run" appear in
#: every document, so matching them proves nothing about grounding.
MIN_QUOTE_CHARS = 12


@dataclass(frozen=True)
class Verdict:
    """One criterion's outcome for one asset."""

    check_id: str
    failed: bool
    confidence: str
    quote: str
    reason: str
    #: Where the quote came from, resolved while the payload is still in hand. The
    #: checks cannot work this out later — by then the mapping from payload text
    #: back to a file has been discarded.
    path: str | None = None
    line: int | None = None


@dataclass
class Review:
    """Everything one asset's review produced."""

    asset_id: str
    verdicts: list[Verdict] = field(default_factory=list)
    model: str = ""
    provider: str = ""
    error: str = ""
    #: Findings the model returned that were dropped, with why. Surfaced in verbose
    #: output: a reviewer that silently discards a third of its own answers is
    #: something the operator should be able to see.
    discarded: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return not self.error and bool(self.verdicts)


def _extract_json(text: str) -> dict | None:
    """Pull the JSON object out of a response that may be wrapped in prose."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _normalise(value: object, allowed: tuple[str, ...], default: str) -> str:
    text = str(value or "").strip().upper()
    return text if text in allowed else default


def parse_response(text: str, payload: Payload) -> tuple[list[Verdict], list[str]]:
    """Turn a model response into verdicts, discarding what cannot be grounded."""
    parsed = _extract_json(text)
    if parsed is None:
        return [], ["response was not JSON"]

    raw = parsed.get("findings")
    if not isinstance(raw, list):
        return [], ["response had no 'findings' list"]

    verdicts: list[Verdict] = []
    discarded: list[str] = []
    seen: set[str] = set()

    for item in raw:
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id") or "").strip().upper()
        if check_id not in BY_ID:
            discarded.append(f"unknown check id {check_id!r}")
            continue
        if check_id in seen:
            discarded.append(f"{check_id}: duplicate entry")
            continue
        seen.add(check_id)

        failed = str(item.get("verdict") or "").strip().lower() == "fail"
        quote = str(item.get("quote") or "").strip()
        reason = str(item.get("reason") or "").strip()

        if failed:
            # The grounding check. A quote that is not in the payload was invented,
            # and a finding resting on invented evidence is worse than no finding —
            # it is unfalsifiable by the person reading the report.
            if len(quote) < MIN_QUOTE_CHARS:
                discarded.append(f"{check_id}: quote too short to verify")
                continue
            # Whitespace-insensitive: hard-wrapped prose is quoted back as one
            # flowing sentence, and rejecting that would drop real findings.
            if payload.find(quote) < 0:
                discarded.append(f"{check_id}: quote does not appear in the component")
                continue
            if not reason:
                discarded.append(f"{check_id}: no reason given")
                continue

        source, line = payload.locate(quote) if quote else (None, None)
        verdicts.append(
            Verdict(
                check_id=check_id,
                failed=failed,
                confidence=_normalise(item.get("confidence"), ("HIGH", "MEDIUM", "LOW"), "LOW"),
                quote=quote,
                reason=reason,
                path=str(source) if source else None,
                line=line,
            )
        )

    # A criterion the model ignored is unanswered, not passed.
    for check_id in BY_ID:
        if check_id not in seen:
            discarded.append(f"{check_id}: not addressed in the response")

    return verdicts, discarded


def review(payload: Payload, provider: Provider) -> Review:
    """Review one prepared payload. Never raises for a provider failure."""
    result = Review(asset_id=payload.asset_id, provider=provider.name)
    try:
        response = provider.complete(
            SYSTEM_PROMPT, user_prompt(payload.kind, payload.asset_id, payload.body)
        )
    except LLMError as exc:
        result.error = str(exc)
        return result

    result.model = response.model
    result.verdicts, result.discarded = parse_response(response.text, payload)
    if not result.verdicts:
        result.error = "model returned no usable verdict"
    return result


def consent_line(provider: Provider, payloads: list[Payload]) -> str:
    """Disclosure printed before anything is sent.

    Deliberately not :func:`argus.rules.providers.consent_line`, which ends with
    "No scanned configuration is transmitted." That is true of rule generation and
    false here — review works by transmitting exactly that. Reusing it would be a
    lie in the one place the user is deciding whether to allow the transfer.
    """
    total = sum(p.approx_tokens for p in payloads)
    redacted = sum(len(p.redactions) for p in payloads)
    lines = [
        f"Sending {len(payloads)} component(s) — roughly {total:,} tokens — to "
        f"{provider.name} ({provider.model}), processed in {provider.spec.jurisdiction}.",
        "The contents of your skills, hooks, instruction files and MCP servers are "
        "transmitted. This is what review does.",
    ]
    if redacted:
        lines.append(
            f"{redacted} line(s) containing credentials were redacted before sending."
        )
    return "\n".join(lines)
