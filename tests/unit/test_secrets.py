"""Secret detection: positive, negative, and false-positive regression tests."""

from __future__ import annotations

import pytest

from argus.analysis import secrets
from argus.analysis.redaction import is_placeholder, redact
from tests.conftest import (
    FAKE_ANTHROPIC_KEY,
    FAKE_AWS_KEY,
    FAKE_GITHUB_TOKEN,
    FAKE_PRIVATE_KEY,
)


class TestPositiveDetection:
    @pytest.mark.parametrize(
        ("text", "pattern_id", "kind"),
        [
            (f'aws_key = "{FAKE_AWS_KEY}"', "aws-access-key-id", "cloud"),
            (f'ANTHROPIC_API_KEY={FAKE_ANTHROPIC_KEY}', "anthropic-api-key", "api_key"),
            (f'token: {FAKE_GITHUB_TOKEN}', "github-token", "token"),
            (FAKE_PRIVATE_KEY, "private-key-block", "private_key"),
            ("url = https://user:s3cr3tP4ssw0rd@example.com/db", "basic-auth-url", "plaintext"),
        ],
    )
    def test_detects_structural_secret(self, text, pattern_id, kind):
        matches = secrets.scan_text(text)
        assert any(m.pattern_id == pattern_id and m.kind == kind for m in matches), (
            f"expected {pattern_id} in {[m.pattern_id for m in matches]}"
        )

    def test_high_entropy_generic_assignment(self):
        matches = secrets.scan_text('api_secret = "xQ7vNp2LmZ4rTy8WbK3jFh6Ds9Gc1Aa5"')
        assert any(m.pattern_id == "generic-secret" for m in matches)
        assert all(m.confidence == "MEDIUM" for m in matches if m.pattern_id == "generic-secret")


class TestRedaction:
    def test_never_emits_full_secret(self):
        """The core safety property: no output path may carry a complete credential."""
        text = f'aws_key = "{FAKE_AWS_KEY}"'
        for match in secrets.scan_text(text):
            assert FAKE_AWS_KEY not in match.redacted
            assert FAKE_AWS_KEY not in match.context
            assert FAKE_AWS_KEY not in match.description

    def test_redact_keeps_only_prefix_and_suffix(self):
        redacted = redact(FAKE_AWS_KEY)
        assert redacted.startswith("AKIA")
        assert redacted.endswith("DFGH")
        assert FAKE_AWS_KEY not in redacted
        assert len(redacted) < len(FAKE_AWS_KEY)

    def test_short_values_fully_redacted(self):
        """Revealing 4 of 8 characters would halve an attacker's search space."""
        assert redact("abcd1234") == "…" * 3

    def test_empty_value(self):
        assert redact("") == ""


class TestFalsePositiveRegression:
    """Each case here was a real false positive found scanning a live environment."""

    @pytest.mark.parametrize(
        "text",
        [
            # Code identifiers in SDK documentation
            "const token = extra._meta?.progressToken;",
            "const apiKey = response.data.credentials.accessToken;",
            "self.api_key = config.get('api_key')",
            # Environment indirection is the recommended remediation
            'api_key = "${ANTHROPIC_API_KEY}"',
            'token: "$ANTHROPIC_TOKEN"',
            "API_KEY=%USERPROFILE_TOKEN%",
            "password = os.environ['DB_PASSWORD']",
            # Command substitution
            "TOKEN=$(get-fresh-token-from-somewhere)",
            "SECRET=`vault read -field=value secret/app`",
            # Placeholders
            'api_key = "your-api-key-here"',
            'token = "<YOUR_TOKEN_HERE>"',
            'secret = "xxxxxxxxxxxxxxxxxxxx"',
            'password = "changeme-please-now"',
            # Paths, not credentials
            'key_file = "/etc/ssl/private/server.key"',
            'credential_path = "~/.config/app/credentials.json"',
        ],
    )
    def test_does_not_flag(self, text):
        matches = secrets.scan_text(text)
        assert matches == [], f"false positive on {text!r}: {[m.pattern_id for m in matches]}"

    def test_low_entropy_value_ignored(self):
        assert secrets.scan_text('password = "aaaaaaaaaaaaaaaaaaaa"') == []

    def test_short_value_ignored(self):
        assert secrets.scan_text('token = "abc123"') == []


class TestEntropy:
    def test_uniform_string_has_zero_entropy(self):
        assert secrets.shannon_entropy("aaaaaaaa") == 0.0

    def test_random_string_exceeds_threshold(self):
        assert secrets.shannon_entropy("xQ7vNp2LmZ4rTy8WbK3j") > secrets.ENTROPY_THRESHOLD

    def test_empty_string(self):
        assert secrets.shannon_entropy("") == 0.0


class TestPlaceholders:
    @pytest.mark.parametrize(
        "value", ["xxxxx", "<your-token>", "${VAR}", "changeme", "example-key", "REDACTED"]
    )
    def test_recognised(self, value):
        assert is_placeholder(value)

    def test_real_looking_value_is_not_placeholder(self):
        assert not is_placeholder(FAKE_AWS_KEY)


class TestMappingScan:
    def test_walks_nested_structures(self):
        data = {"servers": {"db": {"env": {"API_KEY": FAKE_AWS_KEY}}}}
        matches = secrets.scan_mapping(data)
        assert len(matches) == 1
        assert matches[0].key == "servers.db.env.API_KEY"
        assert FAKE_AWS_KEY not in matches[0].redacted

    def test_ignores_indirection_in_mapping(self):
        data = {"env": {"API_KEY": "${MY_API_KEY}"}}
        assert secrets.scan_mapping(data) == []

    def test_handles_malformed_input(self):
        for value in (None, [], "string", 42, {"a": [1, 2, {"b": None}]}):
            assert isinstance(secrets.scan_mapping(value), list)


class TestLargeInput:
    def test_skips_minified_lines(self):
        """A single enormous line must not become an entropy-scanning hot loop."""
        assert secrets.scan_text("x" * 5000 + f' api_key="{FAKE_AWS_KEY}"') == []

    def test_respects_max_findings(self):
        text = "\n".join(f'api_key_{i} = "{FAKE_AWS_KEY}"' for i in range(100))
        assert len(secrets.scan_text(text, max_findings=10)) <= 10
