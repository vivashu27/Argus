"""Standalone HTML reporter.

Produces a single self-contained file with no external requests — all CSS is inline
and charts are hand-built SVG, so the report renders identically offline and inside
restrictive CSP environments.

All content is HTML-escaped. Scanned files are untrusted, and their contents reach
this reporter through evidence snippets, so escaping is a security control here and
not a formatting nicety.
"""

from __future__ import annotations

from html import escape
from typing import Any

from ..benchmarks.aasb_v1 import DISCLAIMER, FULL_NAME, benchmark_coverage
from ..core.engine import ScanReport
from ..core.models import Finding, Severity, Status

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)

SEVERITY_COLOR = {
    Severity.CRITICAL: "#b3123a",
    Severity.HIGH: "#c2410c",
    Severity.MEDIUM: "#a16207",
    Severity.LOW: "#0369a1",
    Severity.INFO: "#4b5563",
}

STATUS_COLOR = {
    Status.PASS: "#15803d",
    Status.FAIL: "#b3123a",
    Status.WARN: "#a16207",
    Status.MANUAL: "#6d28d9",
    Status.NOT_APPLICABLE: "#6b7280",
    Status.ERROR: "#374151",
}

CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--ink:#16191d;--muted:#5b6472;--line:#e2e5ea;
--accent:#1d4ed8;--radius:10px;}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--panel:#171b21;--ink:#e8eaed;
--muted:#9aa4b2;--line:#2a3038;--accent:#7ea2ff;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:32px 20px 80px}
header.masthead{border-bottom:3px solid var(--accent);padding-bottom:20px;margin-bottom:28px}
h1{margin:0 0 4px;font-size:30px;letter-spacing:-.02em}
h2{font-size:20px;margin:36px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:0}
.sub{color:var(--muted);font-size:14px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-top:16px}
.meta div{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:10px 12px}
.meta dt{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0}
.meta dd{margin:3px 0 0;font-size:13px;word-break:break-word}
.score-row{display:flex;gap:20px;flex-wrap:wrap;align-items:stretch;margin:20px 0}
.score-card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
padding:20px 24px;display:flex;align-items:center;gap:20px;min-width:260px}
.score-num{font-size:46px;font-weight:700;line-height:1}
.grade{font-size:13px;color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(112px,1fr));gap:10px;flex:1}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
padding:12px;text-align:center}
.tile b{display:block;font-size:22px;line-height:1.2}
.tile span{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
table{width:100%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;font-size:14px}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:rgba(125,125,125,.08);font-size:12px;text-transform:uppercase;
letter-spacing:.05em;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:none}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
.badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;
font-weight:700;letter-spacing:.04em;color:#fff;white-space:nowrap}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:5px;
border-radius:var(--radius);padding:18px 20px;margin-bottom:16px}
.finding-head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;margin-bottom:12px}
.finding-head .id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
gap:8px;margin:12px 0;font-size:12px}
.facts div{background:var(--bg);border-radius:6px;padding:7px 10px}
.facts dt{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.05em;margin:0}
.facts dd{margin:2px 0 0;font-weight:600}
.section-label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;
color:var(--muted);font-weight:700;margin:14px 0 4px}
.evidence{background:var(--bg);border:1px solid var(--line);border-radius:8px;
padding:10px 12px;margin:6px 0;font-size:13px}
.evidence code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
word-break:break-all;background:rgba(125,125,125,.12);padding:1px 5px;border-radius:4px}
.evidence .why{color:var(--muted);font-size:12px;margin-top:4px}
.remediation{background:rgba(21,128,61,.08);border-left:3px solid #15803d;
padding:10px 12px;border-radius:0 8px 8px 0;margin-top:10px;font-size:14px}
.accepted{background:rgba(161,98,7,.1);border-left:3px solid #a16207;
padding:10px 12px;border-radius:0 8px 8px 0;margin-top:10px;font-size:13px}
.bar{display:flex;height:26px;border-radius:6px;overflow:hidden;border:1px solid var(--line)}
.bar span{display:block}
.legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:8px;font-size:12px;color:var(--muted)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
.note{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--accent);
border-radius:0 var(--radius) var(--radius) 0;padding:12px 16px;margin:16px 0;font-size:14px}
footer{margin-top:48px;padding-top:18px;border-top:1px solid var(--line);
color:var(--muted);font-size:12px}
ul.plain{margin:6px 0;padding-left:20px}
"""


def _e(value: Any) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}">{_e(text)}</span>'


def _severity_bar(summary: Any) -> str:
    counts = [(s, getattr(summary, s.value.lower())) for s in SEVERITY_ORDER]
    total = sum(c for _s, c in counts)
    if not total:
        return '<p class="sub">No failing or warning findings to distribute.</p>'
    segments = "".join(
        f'<span style="width:{100 * count / total:.2f}%;background:{SEVERITY_COLOR[sev]}" '
        f'title="{sev.value}: {count}"></span>'
        for sev, count in counts
        if count
    )
    legend = "".join(
        f'<span><i style="background:{SEVERITY_COLOR[sev]}"></i>{sev.value} ({count})</span>'
        for sev, count in counts
        if count
    )
    return f'<div class="bar">{segments}</div><div class="legend">{legend}</div>'


def _category_chart(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        if finding.status in (Status.FAIL, Status.WARN):
            counts[finding.meta.category.display] = counts.get(finding.meta.category.display, 0) + 1
    if not counts:
        return '<p class="sub">No findings by category.</p>'

    peak = max(counts.values())
    rows = []
    for name, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        width = 100 * count / peak
        rows.append(
            f"<tr><td>{_e(name)}</td>"
            f'<td style="width:65%"><div style="background:var(--accent);height:16px;'
            f'width:{width:.1f}%;border-radius:3px;min-width:2px"></div></td>'
            f'<td class="num">{count}</td></tr>'
        )
    return f'<div class="scroll"><table><tbody>{"".join(rows)}</tbody></table></div>'


def _finding_block(finding: Finding) -> str:
    meta = finding.meta
    color = SEVERITY_COLOR[finding.severity]
    parts = [f'<article class="finding" style="border-left-color:{color}">']

    parts.append('<div class="finding-head">')
    parts.append(f'<span class="id">{_e(finding.check_id)}</span>')
    parts.append(f"<h3>{_e(meta.title)}</h3>")
    parts.append(_badge(finding.severity.value, color))
    parts.append(_badge(finding.display_status, STATUS_COLOR[finding.status]))
    parts.append("</div>")

    parts.append('<dl class="facts">')
    for label, value in (
        ("Category", meta.category.display),
        ("AASB", f"{meta.aasb} (L{meta.aasb_level})"),
        ("Confidence", finding.confidence.value),
        ("Affected asset", finding.asset or "—"),
    ):
        parts.append(f"<div><dt>{_e(label)}</dt><dd>{_e(value)}</dd></div>")
    parts.append("</dl>")

    parts.append(f'<div class="section-label">Description</div><p>{_e(meta.description)}</p>')
    if finding.detail:
        parts.append(f'<div class="section-label">Observation</div><p>{_e(finding.detail)}</p>')
    if meta.rationale:
        parts.append(f'<div class="section-label">Technical details</div><p>{_e(meta.rationale)}</p>')
    if meta.security_impact:
        parts.append(f'<div class="section-label">Risk</div><p>{_e(meta.security_impact)}</p>')

    if finding.evidence:
        parts.append('<div class="section-label">Evidence</div>')
        for item in finding.evidence:
            location = _e(item.path or "")
            if item.line:
                location += f":{item.line}"
            bits = []
            if location:
                bits.append(f"<code>{location}</code>")
            if item.key:
                bits.append(f"key <code>{_e(item.key)}</code>")
            if item.snippet:
                bits.append(f"<code>{_e(item.snippet)}</code>")
            parts.append(
                f'<div class="evidence">{" · ".join(bits)}'
                f'<div class="why">{_e(item.reason)}</div></div>'
            )

    if finding.accepted_risk:
        parts.append(
            f'<div class="accepted"><strong>Accepted risk.</strong> '
            f"{_e(finding.acceptance_reason)} This finding remains visible and is excluded "
            f"from the exit-code gate.</div>"
        )

    parts.append(
        f'<div class="remediation"><strong>Remediation.</strong> {_e(meta.remediation)}</div>'
    )

    if meta.compliance:
        mappings = "; ".join(
            f"{framework}: {', '.join(refs)}" for framework, refs in meta.compliance_dict().items()
        )
        parts.append(
            f'<div class="section-label">Compliance mapping</div><p class="sub">{_e(mappings)}</p>'
        )
    if meta.references:
        links = ", ".join(
            f'<a href="{_e(r)}" rel="noreferrer noopener">{_e(r)}</a>' for r in meta.references
        )
        parts.append(f'<div class="section-label">References</div><p class="sub">{links}</p>')

    parts.append("</article>")
    return "".join(parts)


def render(report: ScanReport) -> str:
    summary = report.summary
    metadata = report.result.metadata
    findings = report.result.findings

    issues = [f for f in findings if f.status in (Status.FAIL, Status.WARN)]
    issues.sort(key=lambda f: (-f.severity.rank, f.check_id))
    manual = [f for f in findings if f.status is Status.MANUAL]
    passed = [f for f in findings if f.status is Status.PASS]
    errors = [f for f in findings if f.status is Status.ERROR]

    score_color = (
        "#15803d" if summary.score >= 80 else "#a16207" if summary.score >= 60 else "#b3123a"
    )

    html: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Argus Security Report — {_e(metadata.hostname)}</title>",
        f"<style>{CSS}</style></head><body><div class='wrap'>",
    ]

    # Masthead
    html.append("<header class='masthead'>")
    html.append("<h1>Argus Security Assessment</h1>")
    html.append(f"<p class='sub'>{_e(FULL_NAME)} — AI Agent Security Configuration Auditor</p>")
    html.append("<dl class='meta'>")
    for label, value in (
        ("Scan timestamp", metadata.timestamp),
        ("Host", metadata.hostname),
        ("Platform", metadata.platform),
        ("Scanner version", f"Argus {metadata.scanner_version}"),
        ("Benchmark", metadata.benchmark),
        ("Scan roots", f"{len(metadata.scan_roots)} location(s)"),
    ):
        html.append(f"<div><dt>{_e(label)}</dt><dd>{_e(value)}</dd></div>")
    html.append("</dl></header>")

    # Executive summary
    html.append("<h2>Executive Summary</h2>")
    html.append(
        f"<p>The assessment identified <strong>{summary.critical} Critical</strong>, "
        f"<strong>{summary.high} High</strong>, <strong>{summary.medium} Medium</strong> and "
        f"<strong>{summary.low} Low</strong> findings across {summary.total} checks in "
        f"{metadata.benchmark}.</p>"
    )
    if summary.manual:
        html.append(
            f"<div class='note'><strong>{summary.manual} check(s) require manual review.</strong> "
            "These could not be determined from static evidence and are reported as MANUAL "
            "rather than assumed to pass. They do not contribute to the score.</div>"
        )
    if metadata.used_fixtures:
        html.append(
            "<div class='note'><strong>Fixture data included.</strong> Some findings derive "
            "from test fixtures rather than the live environment.</div>"
        )

    html.append("<div class='score-row'>")
    html.append(
        f"<div class='score-card'><div><div class='score-num' style='color:{score_color}'>"
        f"{summary.score}<span style='font-size:20px;color:var(--muted)'>/100</span></div>"
        f"<div class='grade'>Grade {summary.grade} · coverage {_e(summary.coverage)}</div></div></div>"
    )
    html.append("<div class='tiles'>")
    for tile_label, tile_value, color in (
        ("Passed", summary.passed, STATUS_COLOR[Status.PASS]),
        ("Failed", summary.failed, STATUS_COLOR[Status.FAIL]),
        ("Warnings", summary.warned, STATUS_COLOR[Status.WARN]),
        ("Manual", summary.manual, STATUS_COLOR[Status.MANUAL]),
        ("N/A", summary.not_applicable, STATUS_COLOR[Status.NOT_APPLICABLE]),
        ("Errors", summary.errors, STATUS_COLOR[Status.ERROR]),
    ):
        html.append(
            f"<div class='tile'><b style='color:{color}'>{tile_value}</b>"
            f"<span>{_e(tile_label)}</span></div>"
        )
    html.append("</div></div>")

    # Posture
    html.append("<h2>Security Posture</h2>")
    html.append("<div class='section-label'>Severity distribution</div>")
    html.append(_severity_bar(summary))
    html.append("<div class='section-label' style='margin-top:20px'>Findings by category</div>")
    html.append(_category_chart(findings))

    # Benchmark coverage
    html.append("<h2>Benchmark Coverage</h2><div class='scroll'><table><thead><tr>"
                "<th>#</th><th>Section</th><th class='num'>Checks</th><th class='num'>Passed</th>"
                "<th class='num'>Failed</th><th class='num'>Warn</th><th class='num'>Manual</th>"
                "<th class='num'>N/A</th><th class='num'>Pass rate</th></tr></thead><tbody>")
    for row in benchmark_coverage(findings):
        rate_label = f"{row['pass_rate']}%" if row["pass_rate"] is not None else "—"
        html.append(
            f"<tr><td>{row['section']}</td><td>{_e(row['title'])}</td>"
            f"<td class='num'>{row['checks']}</td><td class='num'>{row['passed']}</td>"
            f"<td class='num'>{row['failed']}</td><td class='num'>{row['warned']}</td>"
            f"<td class='num'>{row['manual']}</td><td class='num'>{row['not_applicable']}</td>"
            f"<td class='num'>{rate_label}</td></tr>"
        )
    html.append("</tbody></table></div>")

    # Findings
    html.append(f"<h2>Detailed Findings ({len(issues)})</h2>")
    if not issues:
        html.append("<p class='sub'>No failing or warning findings were identified.</p>")
    for finding in issues:
        html.append(_finding_block(finding))

    # Manual
    if manual:
        html.append(f"<h2>Requires Manual Review ({len(manual)})</h2>")
        html.append("<div class='scroll'><table><thead><tr><th>Check</th><th>Asset</th>"
                    "<th>Why manual</th></tr></thead><tbody>")
        for finding in manual:
            html.append(
                f"<tr><td><strong>{_e(finding.check_id)}</strong><br>"
                f"<span class='sub'>{_e(finding.meta.title)}</span></td>"
                f"<td><code>{_e(finding.asset)}</code></td><td>{_e(finding.detail)}</td></tr>"
            )
        html.append("</tbody></table></div>")

    # Errors
    if errors:
        html.append(f"<h2>Check Errors ({len(errors)})</h2>")
        html.append("<div class='scroll'><table><thead><tr><th>Check</th><th>Error</th>"
                    "</tr></thead><tbody>")
        for finding in errors:
            html.append(
                f"<tr><td>{_e(finding.check_id)}</td><td>{_e(finding.detail)}</td></tr>"
            )
        html.append("</tbody></table></div>")

    # Passed
    if passed:
        html.append(f"<h2>Passed Checks ({len(passed)})</h2>")
        html.append("<div class='scroll'><table><thead><tr><th>Check</th><th>Title</th>"
                    "<th>Asset</th><th>Result</th></tr></thead><tbody>")
        for finding in passed:
            html.append(
                f"<tr><td>{_e(finding.check_id)}</td><td>{_e(finding.meta.title)}</td>"
                f"<td><code>{_e(finding.asset)}</code></td><td>{_e(finding.detail)}</td></tr>"
            )
        html.append("</tbody></table></div>")

    # Score derivation
    html.append("<h2>Score Derivation</h2>")
    html.append(
        "<p class='sub'>score = 100 − Σ(severity weight × status multiplier × confidence "
        "multiplier). MANUAL, NOT_APPLICABLE and ERROR never deduct; accepted risks deduct "
        "nothing by default.</p>"
    )
    if summary.breakdown:
        html.append("<div class='scroll'><table><thead><tr><th>Check</th><th>Asset</th>"
                    "<th>Severity</th><th>Status</th><th>Confidence</th>"
                    "<th class='num'>Deduction</th></tr></thead><tbody>")
        for item in summary.breakdown:
            html.append(
                f"<tr><td>{_e(item.check_id)}</td><td><code>{_e(item.asset)}</code></td>"
                f"<td>{_e(item.severity)}</td><td>{_e(item.status)}</td>"
                f"<td>{_e(item.confidence)}</td><td class='num'>−{item.deduction:.1f}</td></tr>"
            )
        total = sum(b.deduction for b in summary.breakdown)
        html.append(
            f"<tr><td colspan='5'><strong>Total deduction</strong></td>"
            f"<td class='num'><strong>−{total:.1f}</strong></td></tr>"
        )
        html.append("</tbody></table></div>")
    else:
        html.append("<p class='sub'>No deductions — score is 100.</p>")

    # Scan hygiene
    if metadata.discovery_errors:
        html.append("<h2>Discovery Errors — Coverage Is Incomplete</h2>")
        html.append(
            "<div class='note' style='border-left-color:#b3123a'><strong>One or more "
            "discoverers failed.</strong> Assets in the affected domain were never "
            "examined, so the score above does not cover them.</div><ul class='plain'>"
        )
        for entry in metadata.discovery_errors:
            html.append(f"<li>{_e(entry)}</li>")
        html.append("</ul>")

    if metadata.expired_exceptions:
        html.append("<h2>Expired Exceptions</h2><ul class='plain'>")
        for entry in metadata.expired_exceptions:
            html.append(f"<li>{_e(entry)}</li>")
        html.append("</ul>")

    if metadata.unreadable_paths:
        html.append("<h2>Unreadable Paths</h2>")
        html.append("<p class='sub'>Discovered but unreadable — coverage is incomplete here.</p>")
        html.append("<ul class='plain'>")
        for entry in metadata.unreadable_paths:
            html.append(f"<li><code>{_e(entry)}</code></li>")
        html.append("</ul>")

    html.append(
        f"<footer><p>{_e(DISCLAIMER)}</p>"
        f"<p>Generated by Argus {_e(metadata.scanner_version)} at {_e(metadata.timestamp)}. "
        "Argus is read-only and never executes scanned content. Secrets are redacted "
        "in all output.</p></footer>"
    )
    html.append("</div></body></html>")
    return "".join(html)
