"""Provider adapters, built on the standard library only.

Argus is a security tool, so its dependency surface is part of its threat model.
Adding the official SDKs for four providers would pull a large transitive tree in
for what is, per provider, a single JSON POST. ``urllib.request`` covers it.

Two shapes are needed, not four:

* **OpenAI-compatible** — OpenAI, Moonshot (Kimi) and DeepSeek all expose
  ``POST /chat/completions`` with the same body and a bearer token.
* **Anthropic** — ``POST /v1/messages``, with ``x-api-key`` and a version header,
  and ``system`` as a top-level field rather than a message role.

API keys are read from environment variables only. They are never accepted from
``argus.yaml``, because that is a file Argus itself scans and reports on.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "argus-auditor/1.0 (+https://github.com/vivashu27/Argus)"


class LLMError(RuntimeError):
    """A provider call failed. Never fatal — the scan continues without review."""


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    provider: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    endpoint: str
    default_model: str
    key_env: str
    style: str  # "openai" | "anthropic"
    #: Data-residency note surfaced to the operator before anything is sent.
    jurisdiction: str = ""


#: Every provider the operator can select. ``jurisdiction`` is shown in the consent
#: line, because "which country processes my agent configuration" is a real
#: compliance question and silence on it would be a disservice.
SPECS: dict[str, ProviderSpec] = {
    "openai": ProviderSpec(
        name="openai",
        endpoint="https://api.openai.com/v1/chat/completions",
        default_model="gpt-4o-mini",
        key_env="OPENAI_API_KEY",
        style="openai",
        jurisdiction="United States",
    ),
    "anthropic": ProviderSpec(
        name="anthropic",
        endpoint="https://api.anthropic.com/v1/messages",
        default_model="claude-sonnet-4-5",
        key_env="ANTHROPIC_API_KEY",
        style="anthropic",
        jurisdiction="United States",
    ),
    "moonshot": ProviderSpec(
        name="moonshot",
        endpoint="https://api.moonshot.cn/v1/chat/completions",
        default_model="moonshot-v1-32k",
        key_env="MOONSHOT_API_KEY",
        style="openai",
        jurisdiction="China (PRC)",
    ),
    "deepseek": ProviderSpec(
        name="deepseek",
        endpoint="https://api.deepseek.com/chat/completions",
        default_model="deepseek-chat",
        key_env="DEEPSEEK_API_KEY",
        style="openai",
        jurisdiction="China (PRC)",
    ),
}


@dataclass
class Provider:
    spec: ProviderSpec
    api_key: str
    model: str
    timeout: int = 60
    max_output_tokens: int = 2000
    #: Injected in tests so the suite never touches the network.
    transport: object | None = field(default=None, repr=False)

    @property
    def name(self) -> str:
        return self.spec.name

    def _body(self, system: str, user: str) -> dict:
        if self.spec.style == "anthropic":
            return {
                "model": self.model,
                "max_tokens": self.max_output_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }
        return {
            "model": self.model,
            "max_tokens": self.max_output_tokens,
            "temperature": 0,  # a security verdict should not vary run to run
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }

    def _headers(self) -> dict[str, str]:
        common = {"content-type": "application/json", "user-agent": USER_AGENT}
        if self.spec.style == "anthropic":
            return {**common, "x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        return {**common, "authorization": f"Bearer {self.api_key}"}

    def _parse(self, payload: dict) -> LLMResponse:
        try:
            if self.spec.style == "anthropic":
                blocks = payload.get("content") or []
                text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
                usage = payload.get("usage") or {}
                return LLMResponse(
                    text=text,
                    model=str(payload.get("model") or self.model),
                    provider=self.name,
                    prompt_tokens=usage.get("input_tokens"),
                    completion_tokens=usage.get("output_tokens"),
                )
            choices = payload.get("choices") or []
            if not choices:
                raise LLMError(f"{self.name}: response contained no choices")
            text = (choices[0].get("message") or {}).get("content") or ""
            usage = payload.get("usage") or {}
            return LLMResponse(
                text=text,
                model=str(payload.get("model") or self.model),
                provider=self.name,
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
            )
        except LLMError:
            raise
        except Exception as exc:
            raise LLMError(f"{self.name}: could not parse response: {exc}") from exc

    def complete(self, system: str, user: str) -> LLMResponse:
        """Issue one completion. Raises :class:`LLMError` on any failure."""
        raw = json.dumps(self._body(system, user)).encode("utf-8")

        if self.transport is not None:  # test seam
            return self._parse(self.transport(self.spec, raw))  # type: ignore[operator]

        request = urllib.request.Request(  # noqa: S310 — fixed https endpoints from SPECS
            self.spec.endpoint, data=raw, headers=self._headers(), method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise LLMError(f"{self.name}: HTTP {exc.code} — {detail}") from exc
        except urllib.error.URLError as exc:
            raise LLMError(f"{self.name}: network error — {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise LLMError(f"{self.name}: response was not valid JSON") from exc
        except TimeoutError as exc:
            raise LLMError(f"{self.name}: timed out after {self.timeout}s") from exc
        return self._parse(payload)


def build_provider(
    name: str,
    *,
    model: str | None = None,
    timeout: int = 60,
    api_key: str | None = None,
    transport: object | None = None,
) -> Provider:
    """Resolve a provider by name, reading its key from the environment."""
    key = name.strip().lower()
    if key not in SPECS:
        raise LLMError(
            f"unknown provider '{name}'. Choose from: {', '.join(sorted(SPECS))}"
        )
    spec = SPECS[key]

    resolved = api_key or os.environ.get(spec.key_env, "")
    if not resolved and transport is None:
        raise LLMError(
            f"{spec.key_env} is not set. Export it to use --llm-provider {key}; "
            "Argus never reads API keys from argus.yaml."
        )

    return Provider(
        spec=spec,
        api_key=resolved,
        model=model or spec.default_model,
        timeout=timeout,
        transport=transport,
    )


def consent_line(provider: Provider, asset_count: int) -> str:
    """One-line disclosure printed before the first request."""
    return (
        f"LLM review: sending {asset_count} redacted asset excerpt(s) to "
        f"{provider.name} ({provider.model}), processed in {provider.spec.jurisdiction}. "
        "Secrets are redacted and host/user identifiers stripped before transmission."
    )
