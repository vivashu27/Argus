"""Core model, scoring, registry, config, and safe-IO tests."""

from __future__ import annotations

import datetime as _dt
import os
import stat

import pytest

from argus.config import load_config
from argus.core import safe_io
from argus.core.engine import Exception_, _apply_exceptions
from argus.core.exceptions import ArgusConfigError, FileTooLargeError, UnsafePathError
from argus.core.models import (
    Category,
    CheckMeta,
    Confidence,
    Finding,
    Severity,
    Status,
    Target,
)
from argus.core.registry import all_checks, get_check, select
from argus.core.scoring import grade_for, score_findings
from argus.core.severity import at_or_above, filter_for_display, gating_findings


def meta(check_id="TEST-001", severity=Severity.HIGH, category=Category.CLAUDE, level=1):
    return CheckMeta(
        check_id=check_id,
        title="Test check",
        description="d",
        category=category,
        severity=severity,
        aasb_level=level,
        applies_to=frozenset({Target.CLAUDE_CODE}),
    )


def finding(status=Status.FAIL, severity=Severity.HIGH, confidence=Confidence.HIGH, check_id="TEST-001"):
    return Finding(meta=meta(check_id, severity), status=status, confidence=confidence, asset="a")


class TestModels:
    def test_severity_ranking(self):
        assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank

    def test_severity_parse_is_case_insensitive(self):
        assert Severity.parse("critical") is Severity.CRITICAL
        assert Severity.parse("  HIGH ") is Severity.HIGH
        with pytest.raises(ValueError):
            Severity.parse("nope")

    def test_category_parses_slug_and_display_name(self):
        assert Category.parse("mcp") is Category.MCP
        assert Category.parse("MCP Security") is Category.MCP
        with pytest.raises(ValueError):
            Category.parse("nope")

    def test_aasb_number_is_derived(self):
        assert meta("CLAUDE-001", category=Category.CLAUDE).aasb == "1.1"
        assert meta("MCP-012", category=Category.MCP).aasb == "2.12"
        assert meta("FS-007", category=Category.FILESYSTEM).aasb == "8.7"

    def test_passing_finding_reports_info_severity(self):
        """A PASS must not carry the check's nominal severity into the summary."""
        assert finding(status=Status.PASS, severity=Severity.CRITICAL).severity is Severity.INFO
        assert finding(status=Status.NOT_APPLICABLE).severity is Severity.INFO

    def test_is_open_excludes_accepted_risk(self):
        f = finding()
        assert f.is_open
        f.accepted_risk = True
        assert not f.is_open

    def test_display_status_marks_accepted_risk(self):
        f = finding()
        f.accepted_risk = True
        assert f.display_status == "FAIL — ACCEPTED RISK"

    def test_to_dict_is_serialisable(self):
        data = finding().to_dict()
        assert data["id"] == "TEST-001"
        assert set(data) >= {"id", "aasb", "severity", "status", "confidence", "evidence"}


class TestScoring:
    def test_perfect_score_with_no_issues(self):
        summary = score_findings([finding(status=Status.PASS) for _ in range(5)])
        assert summary.score == 100
        assert summary.grade == "A"

    def test_weighted_deduction(self):
        summary = score_findings([finding(severity=Severity.HIGH)])
        assert summary.score == 90  # 100 - (10 * 1.0 * 1.0)

    def test_warn_counts_half(self):
        summary = score_findings([finding(status=Status.WARN, severity=Severity.HIGH)])
        assert summary.score == 95

    def test_confidence_scales_deduction(self):
        summary = score_findings([finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)])
        assert summary.score == 92  # 100 - (10 * 1.0 * 0.8)

    @pytest.mark.parametrize("status", [Status.MANUAL, Status.NOT_APPLICABLE, Status.ERROR])
    def test_unevaluated_never_deducts(self, status):
        """An unevaluated control is not a passing control, but must not be punished."""
        summary = score_findings([finding(status=status, severity=Severity.CRITICAL)])
        assert summary.score == 100

    def test_score_floors_at_zero(self):
        summary = score_findings([finding(severity=Severity.CRITICAL) for _ in range(10)])
        assert summary.score == 0

    def test_accepted_risk_excluded_by_default(self):
        f = finding(severity=Severity.CRITICAL)
        f.accepted_risk = True
        summary = score_findings([f])
        assert summary.score == 100
        assert summary.accepted_risk == 1

    def test_accepted_risk_counted_when_configured(self):
        f = finding(severity=Severity.CRITICAL)
        f.accepted_risk = True
        assert score_findings([f], score_accepted_risk=True).score == 75

    def test_custom_weights(self):
        summary = score_findings([finding(severity=Severity.HIGH)], weights={Severity.HIGH: 50.0})
        assert summary.score == 50

    def test_breakdown_is_reproducible(self):
        findings = [finding(severity=Severity.HIGH), finding(severity=Severity.MEDIUM)]
        summary = score_findings(findings)
        assert 100 - sum(b.deduction for b in summary.breakdown) == summary.score
        assert summary.breakdown[0].deduction >= summary.breakdown[-1].deduction

    def test_coverage_excludes_na_and_errors(self):
        summary = score_findings(
            [finding(status=Status.PASS), finding(status=Status.NOT_APPLICABLE),
             finding(status=Status.ERROR)]
        )
        assert summary.applicable == 1
        assert summary.coverage == "1/1"

    @pytest.mark.parametrize(
        ("score", "grade"), [(100, "A"), (90, "A"), (85, "B"), (72, "C"), (61, "D"), (0, "F")]
    )
    def test_grade_bands(self, score, grade):
        assert grade_for(score) == grade


class TestSeverityGates:
    def test_at_or_above(self):
        assert at_or_above(Severity.CRITICAL, Severity.HIGH)
        assert at_or_above(Severity.HIGH, Severity.HIGH)
        assert not at_or_above(Severity.MEDIUM, Severity.HIGH)

    def test_display_gate_keeps_unevaluated_results(self):
        """Hiding a MANUAL behind a severity filter would misrepresent coverage."""
        findings = [
            finding(status=Status.FAIL, severity=Severity.LOW),
            finding(status=Status.MANUAL, severity=Severity.LOW),
            finding(status=Status.PASS),
        ]
        kept = filter_for_display(findings, Severity.HIGH)
        assert {f.status for f in kept} == {Status.MANUAL, Status.PASS}

    def test_display_gate_none_keeps_everything(self):
        findings = [finding(severity=Severity.LOW)]
        assert filter_for_display(findings, None) == findings

    def test_only_fails_gate_the_exit_code(self):
        findings = [
            finding(status=Status.WARN, severity=Severity.CRITICAL),
            finding(status=Status.MANUAL, severity=Severity.CRITICAL),
        ]
        assert gating_findings(findings, Severity.LOW) == []

    def test_accepted_risk_does_not_gate(self):
        f = finding(severity=Severity.CRITICAL)
        f.accepted_risk = True
        assert gating_findings([f], Severity.LOW) == []


class TestExceptions:
    def test_active_exception_marks_accepted(self):
        f = finding(check_id="MCP-003")
        f.asset = "mcp:fs"
        expired = _apply_exceptions(
            [f], [Exception_(check_id="MCP-003", asset="mcp:fs", reason="dev", expires="2099-01-01")]
        )
        assert f.accepted_risk and f.acceptance_reason == "dev"
        assert expired == []

    def test_expired_exception_is_not_honoured(self):
        f = finding(check_id="MCP-003")
        f.asset = "mcp:fs"
        expired = _apply_exceptions(
            [f], [Exception_(check_id="MCP-003", asset="mcp:fs", expires="2020-01-01")]
        )
        assert not f.accepted_risk
        assert expired and "expired" in expired[0]

    def test_unparseable_expiry_fails_closed(self):
        """A suppression control with a broken date must not silently keep suppressing."""
        assert Exception_(check_id="X", expires="not-a-date").is_expired()

    def test_exception_without_asset_matches_all(self):
        f = finding(check_id="MCP-003")
        _apply_exceptions([f], [Exception_(check_id="MCP-003", expires="2099-01-01")])
        assert f.accepted_risk

    def test_exception_does_not_match_other_checks(self):
        f = finding(check_id="MCP-004")
        _apply_exceptions([f], [Exception_(check_id="MCP-003", expires="2099-01-01")])
        assert not f.accepted_risk

    def test_no_expiry_never_expires(self):
        assert not Exception_(check_id="X").is_expired()

    def test_boundary_expiry(self):
        today = _dt.date.today()
        assert not Exception_(check_id="X", expires=today.isoformat()).is_expired(today)


class TestRegistry:
    def test_all_checks_registered(self):
        assert len(all_checks()) >= 40

    def test_ids_are_unique(self):
        ids = [c.meta.check_id for c in all_checks()]
        assert len(ids) == len(set(ids))

    def test_lookup_by_id_and_aasb(self):
        assert get_check("MCP-003") is get_check("2.3")
        assert get_check("mcp-003") is get_check("MCP-003")
        assert get_check("NOPE-999") is None

    def test_select_by_category(self):
        selected = select(categories={Category.MCP})
        assert selected and all(c.meta.category is Category.MCP for c in selected)

    def test_select_by_level_is_cumulative(self):
        """Level 2 is a superset baseline, so it includes Level 1."""
        level1 = select(level=1)
        level2 = select(level=2)
        assert all(c.meta.aasb_level == 1 for c in level1)
        assert len(level2) >= len(level1)

    def test_exclude_beats_include(self):
        selected = select(include_ids=["MCP-003"], exclude_ids=["MCP-003"])
        assert selected == []

    def test_select_by_target(self):
        selected = select(targets={Target.HOOKS})
        assert selected and all(Target.HOOKS in c.meta.applies_to for c in selected)

    def test_every_check_declares_required_metadata(self):
        for check in all_checks():
            m = check.meta
            assert m.title and m.description and m.remediation, m.check_id
            assert m.rationale or m.security_impact, m.check_id
            assert m.applies_to, m.check_id
            assert m.aasb_level in (1, 2), m.check_id


class TestSafeIO:
    def test_rejects_oversized_file(self, tmp_path):
        path = tmp_path / "big.txt"
        path.write_text("x" * 2000)
        with pytest.raises(FileTooLargeError):
            safe_io.read_text(path, max_bytes=100)

    def test_reads_within_limit(self, tmp_path):
        path = tmp_path / "ok.txt"
        path.write_text("hello")
        assert safe_io.read_text(path, max_bytes=100) == "hello"

    def test_invalid_encoding_does_not_raise(self, tmp_path):
        path = tmp_path / "bin.txt"
        path.write_bytes(b"\xff\xfe\x00invalid")
        assert isinstance(safe_io.read_text(path), str)

    def test_malformed_json_returns_none(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        assert safe_io.read_json(path) is None

    def test_malformed_yaml_returns_none(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("key: [unclosed")
        assert safe_io.read_yaml(path) is None

    def test_yaml_never_constructs_python_objects(self, tmp_path):
        """safe_load only — a scanned config must not be able to instantiate objects."""
        path = tmp_path / "evil.yaml"
        path.write_text("!!python/object/apply:os.system ['touch /tmp/argus-pwned']\n")
        assert safe_io.read_yaml(path) is None
        assert not os.path.exists("/tmp/argus-pwned")

    def test_resolve_within_allows_inside(self, tmp_path):
        inner = tmp_path / "a" / "b"
        inner.mkdir(parents=True)
        assert safe_io.resolve_within(inner, tmp_path) == inner.resolve()

    def test_resolve_within_blocks_traversal(self, tmp_path):
        with pytest.raises(UnsafePathError):
            safe_io.resolve_within(tmp_path / ".." / ".." / "etc", tmp_path)

    def test_escaping_symlink_detected(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("x")
        link = root / "link"
        link.symlink_to(outside)
        assert safe_io.escapes_root(link, root)

    def test_internal_symlink_not_flagged(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        target = root / "real.txt"
        target.write_text("x")
        link = root / "link"
        link.symlink_to(target)
        assert not safe_io.escapes_root(link, root)

    def test_iter_files_never_traverses_symlinks(self, tmp_path):
        """A directory symlink is the classic route out of the scan root, or into a loop."""
        root = tmp_path / "root"
        (root / "sub").mkdir(parents=True)
        (root / "sub" / "a.txt").write_text("x")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("x")
        (root / "escape").symlink_to(outside)

        found = {p.name for p in safe_io.iter_files(root, suffixes=(".txt",))}
        assert "a.txt" in found
        assert "secret.txt" not in found

    def test_iter_files_skips_noise_directories(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "x.js").write_text("x")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "y.js").write_text("x")
        found = {p.name for p in safe_io.iter_files(tmp_path, suffixes=(".js",))}
        assert found == {"y.js"}

    def test_iter_files_respects_depth(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "deep.txt").write_text("x")
        assert safe_io.iter_files(tmp_path, max_depth=1, suffixes=(".txt",)) == []

    def test_file_mode(self, tmp_path):
        path = tmp_path / "f.txt"
        path.write_text("x")
        path.chmod(0o600)
        assert safe_io.file_mode(path) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="POSIX only")
    def test_unreadable_file_reported_not_crashed(self, tmp_path):
        path = tmp_path / "locked.json"
        path.write_text("{}")
        path.chmod(0o000)
        try:
            assert not safe_io.is_readable(path) or os.geteuid() == 0
        finally:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)


class TestConfig:
    def test_missing_config_yields_defaults(self):
        config = load_config(None)
        assert config.severity_threshold is Severity.HIGH
        assert config.report.formats == ["terminal"]

    def test_parses_full_config(self, tmp_path):
        path = tmp_path / "argus.yaml"
        path.write_text(
            "scan:\n"
            "  include: [mcp, skills]\n"
            "  exclude: [CLAUDE-005]\n"
            "  level: 1\n"
            "severity_threshold: critical\n"
            "scoring:\n"
            "  weights: {CRITICAL: 50}\n"
            "  score_accepted_risk: true\n"
            "report:\n"
            "  formats: [json, html]\n"
            "  output: ./out\n"
            "exceptions:\n"
            "  - check_id: MCP-003\n"
            "    reason: dev\n"
        )
        config = load_config(path)
        assert set(config.include) == {Target.MCP, Target.SKILLS}
        assert config.exclude == ["CLAUDE-005"]
        assert config.level == 1
        assert config.severity_threshold is Severity.CRITICAL
        assert config.weights[Severity.CRITICAL] == 50.0
        assert config.score_accepted_risk is True
        assert config.report.formats == ["json", "html"]
        assert len(config.exceptions) == 1

    @pytest.mark.parametrize(
        "content",
        [
            "scan:\n  include: [not-a-target]\n",
            "severity_threshold: enormous\n",
            "exceptions:\n  - reason: missing check_id\n",
            "exceptions: not-a-list\n",
            "scan: not-a-mapping\n",
            "scan:\n  level: 7\n",
            "- just\n- a\n- list\n",
        ],
    )
    def test_invalid_config_raises_usage_error(self, tmp_path, content):
        path = tmp_path / "argus.yaml"
        path.write_text(content)
        with pytest.raises(ArgusConfigError):
            load_config(path)


class TestBanner:
    """The banner must degrade, never crash — it is the first thing every run prints."""

    def _console(self, width=100, encoding="utf-8"):
        import io

        from rich.console import Console

        stream = io.TextIOWrapper(io.BytesIO(), encoding=encoding, errors="strict")
        return Console(file=stream, width=width, force_terminal=False), stream

    def _text(self, console, stream) -> str:
        console.file.flush()
        return stream.buffer.getvalue().decode(stream.encoding, errors="replace")

    def test_wide_utf8_renders_block_lettering(self):
        from argus.reporters import terminal

        console, stream = self._console()
        terminal.banner(console)
        assert "█" in self._text(console, stream)

    def test_narrow_terminal_falls_back_to_one_line(self):
        from argus.reporters import terminal

        console, stream = self._console(width=40)
        terminal.banner(console)
        output = self._text(console, stream)
        assert "█" not in output
        assert "ARGUS" in output

    def test_ascii_stream_emits_no_non_ascii(self):
        """Regression: the fallback used to be "◉ ARGUS", which is itself non-ASCII
        and raised UnicodeEncodeError on an ASCII stdout."""
        from argus.reporters import terminal

        console, stream = self._console(encoding="ascii")
        terminal.banner(console)  # must not raise
        output = self._text(console, stream)
        assert output.isascii(), f"non-ASCII reached an ASCII stream: {output!r}"
        assert "ARGUS" in output

    def test_ascii_stream_with_metadata(self):
        from argus.core.models import ScanMetadata
        from argus.reporters import terminal

        metadata = ScanMetadata(
            timestamp="2026-01-01T00:00:00+00:00",
            hostname="host",
            platform="Linux",
            scanner_version="1.0.0",
            benchmark="AASB v1.0",
        )
        console, stream = self._console(encoding="ascii")
        terminal.banner(console, metadata)
        assert self._text(console, stream).isascii()
