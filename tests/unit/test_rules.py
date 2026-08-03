"""Custom .argus rule tests: schema validation, evaluation, and AI generation.

Generation tests use an injected transport, so the suite never touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.core.models import Asset, Category, Severity, Status, Target
from argus.rules import engine, load_rules
from argus.rules.generate import generate_rule
from argus.rules.loader import RuleError, parse_rule
from argus.rules.providers import LLMError

RULE = """
id: mcp-unpinned-npx
name: MCP server launched via npx with no version pin
severity: high
target: mcp
match:
  all:
    - field: command
      contains: npx
    - field: args
      not_regex: '@\\d+\\.\\d+\\.\\d+'
remediation: Pin the package to an exact version.
tags: [mcp, supply-chain]
"""


def mcp(name: str, command: str, args: list[str], **extra) -> Asset:
    data = {"name": name, "command": command, "args": args, "env": {}, "url": "", **extra}
    return Asset(asset_id=f"mcp:{name}", target=Target.MCP, path=Path("/t/.mcp.json"),
                 data=data, text=json.dumps(data), source="/t/.mcp.json")


def write(tmp_path: Path, body: str, name: str = "r.argus") -> Path:
    path = tmp_path / name
    path.write_text(body)
    return path


class TestSchema:
    def test_valid_rule_parses(self, tmp_path):
        rules, errors = load_rules([write(tmp_path, RULE)])
        assert errors == []
        rule = rules[0]
        assert rule.rule_id == "mcp-unpinned-npx"
        assert rule.severity is Severity.HIGH
        assert rule.target is Target.MCP
        assert rule.check_id == "CUSTOM-MCP-UNPINNED-NPX"

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ("id: rule-x\n", "missing required key"),
            ("id: rule-x\nname: n\nseverity: nope\ntarget: mcp\nmatch:\n  all:\n   - field: c\n     contains: x\n", "unknown severity"),
            ("id: rule-x\nname: n\nseverity: high\ntarget: nope\nmatch:\n  all:\n   - field: c\n     contains: x\n", "unknown target"),
            ("id: rule-x\nname: n\nseverty: high\ntarget: mcp\nmatch:\n  all:\n   - field: c\n     contains: x\n", "unknown key"),
            ("id: rule-x\nname: n\nseverity: high\ntarget: mcp\nmatch:\n  all: []\n", "non-empty list"),
            ("id: rule-x\nname: n\nseverity: high\ntarget: mcp\nmatch:\n  nope:\n   - field: c\n     contains: x\n", r"unknown key\(s\) in 'match'"),
            ("id: rule-x\nname: n\nseverity: high\ntarget: mcp\nmatch:\n  all:\n   - contains: x\n", "exactly one of 'field' or 'text'"),
            ("id: rule-x\nname: n\nseverity: high\ntarget: mcp\nmatch:\n  all:\n   - field: c\n     contains: a\n     regex: b\n", "exactly one operator"),
            ("id: rule-x\nname: n\nseverity: high\ntarget: mcp\nmatch:\n  all:\n   - field: c\n     regex: '([unclosed'\n", "invalid regex"),
            ("id: BAD ID!\nname: n\nseverity: high\ntarget: mcp\nmatch:\n  all:\n   - field: c\n     contains: x\n", "must be 2-64 chars"),
        ],
    )
    def test_invalid_rules_are_rejected_with_a_reason(self, body, expected):
        with pytest.raises(RuleError, match=expected):
            parse_rule(__import__("yaml").safe_load(body), "<t>")

    def test_malformed_yaml_is_reported_not_crashed(self, tmp_path):
        rules, errors = load_rules([write(tmp_path, ": : not yaml : :")])
        assert rules == []
        assert "not valid YAML" in errors[0]

    def test_one_bad_rule_does_not_stop_the_others(self, tmp_path):
        write(tmp_path, RULE, "good.argus")
        write(tmp_path, "id: broken\n", "bad.argus")
        rules, errors = load_rules([tmp_path])
        assert len(rules) == 1 and len(errors) == 1

    def test_duplicate_ids_rejected(self, tmp_path):
        write(tmp_path, RULE, "a.argus")
        write(tmp_path, RULE, "b.argus")
        rules, errors = load_rules([tmp_path])
        assert len(rules) == 1
        assert "duplicate rule id" in errors[0]

    def test_missing_path_reported(self, tmp_path):
        _rules, errors = load_rules([tmp_path / "nope"])
        assert "no such file" in errors[0]

    def test_only_argus_files_loaded_from_a_directory(self, tmp_path):
        write(tmp_path, RULE, "yes.argus")
        write(tmp_path, RULE, "no.yaml")
        rules, _ = load_rules([tmp_path])
        assert len(rules) == 1

    def test_oversized_regex_rejected(self):
        body = ("id: rule-x\nname: n\nseverity: high\ntarget: mcp\nmatch:\n  all:\n"
                f"   - field: c\n     regex: '{'a' * 600}'\n")
        with pytest.raises(RuleError, match="exceeds"):
            parse_rule(__import__("yaml").safe_load(body), "<t>")


class TestEvaluation:
    def _rule(self, tmp_path, body=RULE):
        rules, errors = load_rules([write(tmp_path, body)])
        assert not errors
        return rules[0]

    def test_matches_the_offending_asset(self, tmp_path):
        rule = self._rule(tmp_path)
        matched, evidence = engine.evaluate_rule(rule, mcp("bad", "npx", ["-y", "@x/srv"]))
        assert matched
        assert evidence

    def test_does_not_match_the_pinned_asset(self, tmp_path):
        """The negative case is what keeps a rule from becoming noise."""
        rule = self._rule(tmp_path)
        matched, _ = engine.evaluate_rule(rule, mcp("ok", "npx", ["-y", "@x/srv@1.2.3"]))
        assert not matched

    def test_does_not_match_a_different_command(self, tmp_path):
        rule = self._rule(tmp_path)
        matched, _ = engine.evaluate_rule(rule, mcp("py", "python3", ["/opt/s.py"]))
        assert not matched

    @pytest.mark.parametrize(
        ("operator", "value", "expected"),
        [("contains", "npx", True), ("contains", "uvx", False),
         ("not_contains", "uvx", True), ("equals", "npx", True),
         ("equals", "np", False), ("regex", "^np", True),
         ("not_regex", "^uv", True), ("exists", "", True)],
    )
    def test_operators(self, tmp_path, operator, value, expected):
        clause = f"     {operator}: '{value}'\n" if value else f"     {operator}: true\n"
        body = ("id: op\nname: n\nseverity: low\ntarget: mcp\nmatch:\n  all:\n"
                "   - field: command\n" + clause)
        rule = self._rule(tmp_path, body)
        matched, _ = engine.evaluate_rule(rule, mcp("x", "npx", []))
        assert matched is expected

    def test_not_exists_on_absent_field(self, tmp_path):
        body = ("id: nourl\nname: n\nseverity: low\ntarget: mcp\nmatch:\n  all:\n"
                "   - field: nope.deep\n     not_exists: true\n")
        rule = self._rule(tmp_path, body)
        matched, _ = engine.evaluate_rule(rule, mcp("x", "npx", []))
        assert matched

    def test_any_and_none_combinators(self, tmp_path):
        any_body = ("id: rule-c\nname: n\nseverity: low\ntarget: mcp\nmatch:\n  any:\n"
                    "   - field: command\n     contains: zzz\n"
                    "   - field: command\n     contains: npx\n")
        none_body = any_body.replace("  any:", "  none:")
        asset = mcp("x", "npx", [])
        assert engine.evaluate_rule(self._rule(tmp_path, any_body), asset)[0]
        assert not engine.evaluate_rule(self._rule(tmp_path, none_body, ), asset)[0]

    def test_list_field_matches_any_element(self, tmp_path):
        body = ("id: rule-l\nname: n\nseverity: low\ntarget: mcp\nmatch:\n  all:\n"
                "   - field: args\n     contains: '/etc/shadow'\n")
        rule = self._rule(tmp_path, body)
        assert engine.evaluate_rule(rule, mcp("x", "srv", ["-y", "/etc/shadow"]))[0]
        assert not engine.evaluate_rule(rule, mcp("x", "srv", ["-y", "/tmp/ok"]))[0]

    def test_text_source_searches_raw_text(self, tmp_path):
        body = ("id: rule-t\nname: n\nseverity: low\ntarget: mcp\nmatch:\n  all:\n"
                "   - text: true\n     contains: 'mcpServers'\n")
        rule = self._rule(tmp_path, body)
        asset = mcp("x", "srv", [])
        asset.text = '{"mcpServers": {}}'
        assert engine.evaluate_rule(rule, asset)[0]

    def test_findings_are_real_and_gate(self, tmp_path):
        """Unlike an advisory reviewer, deterministic rules score and gate."""
        from argus.core.scoring import score_findings
        from argus.core.severity import gating_findings

        rule = self._rule(tmp_path)
        findings = engine.run_rules([rule], [mcp("bad", "npx", ["@x/srv"])])
        fails = [f for f in findings if f.status is Status.FAIL]
        assert fails
        assert fails[0].meta.category is Category.MCP, "filed under its target's domain"
        assert score_findings(findings).score < 100
        assert gating_findings(findings, Severity.LOW)

    def test_pass_when_nothing_matches(self, tmp_path):
        rule = self._rule(tmp_path)
        findings = engine.run_rules([rule], [mcp("ok", "npx", ["@x/srv@1.0.0"])])
        assert findings[0].status is Status.PASS

    def test_not_applicable_without_assets(self, tmp_path):
        findings = engine.run_rules([self._rule(tmp_path)], [])
        assert findings[0].status is Status.NOT_APPLICABLE

    def test_custom_rules_have_no_fabricated_aasb_number(self, tmp_path):
        """Rules are not benchmark items, so they report a category slug rather than
        a number. Regression for an int() crash on slug-based check IDs."""
        rule = self._rule(tmp_path)
        findings = engine.run_rules([rule], [mcp("bad", "npx", ["@x/srv"])])
        aasb = findings[0].meta.aasb
        assert aasb == "mcp"
        assert not any(ch.isdigit() for ch in aasb), "must not look like a benchmark number"


class TestGeneration:
    """Only the prompt is transmitted — never scanned configuration."""

    def _transport(self, text, capture=None):
        def _t(spec, raw):
            if capture is not None:
                capture.append(json.loads(raw.decode()))
            return {"model": "mock", "choices": [{"message": {"content": text}}]}

        return _t

    def test_generates_a_valid_rule(self):
        result = generate_rule("flag npx without a pin", api_key="k",
                               transport=self._transport(RULE))
        assert result.rule_id == "mcp-unpinned-npx"
        assert "target: mcp" in result.yaml_text

    def test_strips_code_fences(self):
        fenced = f"```yaml\n{RULE}\n```"
        assert generate_rule("x", api_key="k", transport=self._transport(fenced)).rule_id

    def test_invalid_generation_is_rejected_before_writing(self):
        with pytest.raises(RuleError):
            generate_rule("x", api_key="k", transport=self._transport("id: only\n"))

    def test_non_yaml_generation_rejected(self):
        with pytest.raises(RuleError, match="not valid YAML"):
            generate_rule("x", api_key="k", transport=self._transport(": : ["))

    def test_empty_prompt_rejected(self):
        with pytest.raises(RuleError, match="describe what"):
            generate_rule("   ", api_key="k", transport=self._transport(RULE))

    def test_no_scanned_content_in_the_payload(self):
        captured: list = []
        generate_rule("detect npx without a version pin", api_key="k",
                      transport=self._transport(RULE, captured))
        sent = json.dumps(captured[0])
        assert "detect npx without a version pin" in sent
        for leaked in ("/home/", ".ssh", ".claude.json", "mcpServers"):
            assert leaked not in sent, f"{leaked} reached the provider"

    def test_provider_failure_surfaces(self):
        def boom(spec, raw):
            raise LLMError("upstream down")

        with pytest.raises(LLMError):
            generate_rule("x", api_key="k", transport=boom)

    def test_unknown_provider_rejected(self):
        with pytest.raises(LLMError, match="unknown provider"):
            generate_rule("x", provider="nope", api_key="k")


class TestCategorisation:
    """Rules file themselves by domain so --category picks them up alongside the
    built-in checks. Regression: --category and --exclude silently ran every rule."""

    def _rule(self, tmp_path, extra="", target="skills"):
        body = (f"id: cat-test\nname: n\nseverity: high\ntarget: {target}\n{extra}"
                "match:\n  all:\n   - field: name\n     exists: true\n")
        rules, errors = load_rules([write(tmp_path, body)])
        assert not errors, errors
        return rules[0]

    @pytest.mark.parametrize(
        ("target", "expected"),
        [("skills", Category.SKILLS), ("mcp", Category.MCP), ("hooks", Category.HOOKS),
         ("plugins", Category.PLUGINS), ("instructions", Category.INSTRUCTIONS),
         ("filesystem", Category.FILESYSTEM), ("claude-code", Category.CLAUDE),
         ("claude-desktop", Category.CLAUDE)],
    )
    def test_category_defaults_from_target(self, tmp_path, target, expected):
        assert self._rule(tmp_path, target=target).category is expected

    def test_ide_target_falls_back_to_custom(self, tmp_path):
        """No IDE category exists, so it must not invent one."""
        assert self._rule(tmp_path, target="ide").category is Category.CUSTOM

    def test_explicit_category_overrides_the_default(self, tmp_path):
        rule = self._rule(tmp_path, extra="category: secrets\n")
        assert rule.category is Category.SECRETS
        assert rule.target is Target.SKILLS, "category must not change the target"

    def test_explicit_custom_opts_out_of_domain_filing(self, tmp_path):
        assert self._rule(tmp_path, extra="category: custom\n").category is Category.CUSTOM

    def test_invalid_category_rejected(self, tmp_path):
        body = ("id: cat-bad\nname: n\nseverity: high\ntarget: skills\ncategory: nope\n"
                "match:\n  all:\n   - field: name\n     exists: true\n")
        with pytest.raises(RuleError, match="unknown category"):
            parse_rule(__import__("yaml").safe_load(body), "<t>")

    def test_finding_carries_the_declared_category(self, tmp_path):
        rule = self._rule(tmp_path, extra="category: secrets\n")
        findings = engine.run_rules([rule], [mcp("x", "srv", [])])
        assert findings[0].meta.category is Category.SECRETS


class TestDeadRuleDetection:
    """A rule reading a field its target does not have validates cleanly and then
    never fires. Found when a working skills rule was retargeted at hooks: the
    schema stayed valid, and the rule silently stopped matching anything."""

    def _rule(self, tmp_path, target: str, field: str):
        body = (f"id: dead-check\nname: n\nseverity: high\ntarget: {target}\n"
                f"match:\n  all:\n   - field: {field}\n     contains: x\n")
        rules, errors = load_rules([write(tmp_path, body)])
        assert not errors, errors
        return rules[0]

    def test_field_valid_for_its_target(self, tmp_path):
        assert self._rule(tmp_path, "skills", "body").unknown_fields() == []

    def test_field_absent_from_target_is_reported(self, tmp_path):
        assert self._rule(tmp_path, "hooks", "body").unknown_fields() == ["body"]

    def test_dotted_path_validates_on_its_first_segment(self, tmp_path):
        rule = self._rule(tmp_path, "claude-code", "settings.permissions.allow")
        assert rule.unknown_fields() == []

    def test_a_dead_rule_really_cannot_match(self, tmp_path):
        """The warning is only worth having if it predicts real behaviour."""
        rule = self._rule(tmp_path, "hooks", "body")
        hook = Asset(
            asset_id="hook:PreToolUse#1", target=Target.HOOKS,
            data={"event": "PreToolUse", "command": "xxx", "matcher": "*"},
            text="xxx", source="/t",
        )
        assert rule.unknown_fields()
        assert not engine.evaluate_rule(rule, hook)[0]

    def test_every_target_has_a_field_map(self):
        from argus.rules.model import TARGET_FIELDS

        assert set(TARGET_FIELDS) == set(Target), "a missing target silently skips the check"
