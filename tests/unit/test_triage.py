"""False-positive triage: fingerprinting, suppression, and disclosure."""

from __future__ import annotations

import pytest

from argus.core.exceptions import ArgusConfigError
from argus.core.models import (
    Category,
    CheckMeta,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Status,
    Target,
)
from argus.core.scoring import score_findings
from argus.core.severity import gating_findings
from argus.core.triage import (
    TriageEntry,
    apply_triage,
    fingerprint,
    load_triage,
    new_entry,
    save_triage,
)

META = CheckMeta(
    check_id="MCP-013", title="t", description="d", category=Category.MCP,
    severity=Severity.CRITICAL, aasb_level=1, applies_to=frozenset({Target.MCP}),
)


def finding(snippet: str = "ignore all previous instructions", asset: str = "mcp:s") -> Finding:
    return Finding(
        meta=META, status=Status.FAIL, confidence=Confidence.HIGH, asset=asset,
        detail="poisoned", evidence=[Evidence(path="/srv/a.py", line=9, key="k", snippet=snippet)],
    )


class TestFingerprint:
    def test_is_stable_across_identical_findings(self):
        assert fingerprint(finding()) == fingerprint(finding())

    def test_changes_when_the_matched_text_changes(self):
        """An edited finding is a new finding and must be re-judged, not inherit a
        verdict given to different text."""
        assert fingerprint(finding()) != fingerprint(finding(snippet="something else"))

    def test_changes_with_the_asset(self):
        assert fingerprint(finding()) != fingerprint(finding(asset="mcp:other"))

    def test_survives_the_code_moving(self):
        """Line numbers shift constantly; churning the file on every edit would make
        the baseline unusable."""
        a, b = finding(), finding()
        b.evidence = [Evidence(path="/srv/a.py", line=400, key="k", snippet=a.evidence[0].snippet)]
        assert fingerprint(a) == fingerprint(b)

    def test_a_finding_without_evidence_still_has_an_identity(self):
        bare = Finding(meta=META, status=Status.FAIL, asset="mcp:s", detail="no evidence")
        assert len(fingerprint(bare)) == 16


class TestTriageFile:
    def _write(self, tmp_path, body: str):
        path = tmp_path / "t.yaml"
        path.write_text(body)
        return path

    def test_missing_file_is_not_an_error(self, tmp_path):
        assert load_triage(tmp_path / "absent.yaml") == []

    def test_round_trip(self, tmp_path):
        path = tmp_path / "t.yaml"
        save_triage(path, [new_entry(finding(), "ours")])
        loaded = load_triage(path)
        assert len(loaded) == 1 and loaded[0].reason == "ours"
        assert loaded[0].fingerprint == fingerprint(finding())

    def test_a_suppression_without_a_reason_is_rejected(self, tmp_path):
        """An unexplained hole in the report is worse than the finding it hides."""
        path = self._write(tmp_path, "version: 1\nsuppressed:\n  - fingerprint: abc123\n")
        with pytest.raises(ArgusConfigError, match="no reason"):
            load_triage(path)

    def test_an_entry_without_a_fingerprint_is_rejected(self, tmp_path):
        path = self._write(tmp_path, "version: 1\nsuppressed:\n  - reason: x\n")
        with pytest.raises(ArgusConfigError, match="no fingerprint"):
            load_triage(path)

    def test_malformed_file_is_rejected_not_ignored(self, tmp_path):
        path = self._write(tmp_path, "suppressed: not-a-list\n")
        with pytest.raises(ArgusConfigError, match="must be a list"):
            load_triage(path)


class TestSuppression:
    def _suppressed(self):
        f = finding()
        apply_triage([f], [new_entry(finding(), "ours")])
        return f

    def test_matching_finding_is_marked_with_its_reason(self):
        f = self._suppressed()
        assert f.suppressed and f.suppression_reason == "ours"

    def test_suppressed_finding_deducts_nothing(self):
        assert score_findings([self._suppressed()]).score == 100
        assert score_findings([finding()]).score < 100

    def test_suppressed_finding_does_not_gate_the_exit_code(self):
        assert gating_findings([self._suppressed()], Severity.HIGH) == []
        assert gating_findings([finding()], Severity.HIGH) != []

    def test_suppressed_finding_is_still_counted_and_labelled(self):
        """Silently dropping it would make a clean report meaningless."""
        f = self._suppressed()
        assert score_findings([f]).suppressed == 1
        assert f.display_status == "FAIL — FALSE POSITIVE"
        assert f.to_dict()["suppression_reason"] == "ours"

    def test_a_different_finding_is_untouched(self):
        other = finding(snippet="a genuine payload")
        apply_triage([other], [new_entry(finding(), "ours")])
        assert not other.suppressed

    def test_an_entry_matching_nothing_is_reported(self):
        stale = apply_triage([], [TriageEntry("deadbeef", "ours", "MCP-013", "mcp:s")])
        assert stale and "no longer matches" in stale[0]

    def test_suppression_is_distinct_from_accepted_risk(self):
        """Accepted risk says the finding is real; suppression says it is wrong."""
        f = self._suppressed()
        assert not f.accepted_risk
        assert score_findings([f]).accepted_risk == 0
