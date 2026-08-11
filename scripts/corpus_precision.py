"""Summarise an Argus JSON report as a precision measurement over a benign corpus.

Every open finding on a corpus of ordinary public repositories is a false-positive
candidate. This script does not decide which are genuine — that requires reading the
file — it groups them so a human can adjudicate a manageable number of cases and
reports the population rate, which is the number that says whether a check
discriminates at all.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--prefix", default="", help="Only checks whose id starts with this.")
    parser.add_argument("--assets", type=int, default=0, help="Population size, for rates.")
    parser.add_argument("--show", type=int, default=6, help="Example evidence lines per check.")
    args = parser.parse_args()

    report = load(args.report)
    findings = report.get("findings", [])

    by_check: dict[str, list[dict]] = defaultdict(list)
    statuses: Counter[str] = Counter()
    assets_seen: set[str] = set()

    for finding in findings:
        check_id = finding.get("id", "")
        if args.prefix and not check_id.startswith(args.prefix):
            continue
        assets_seen.add(finding.get("asset", ""))
        statuses[finding.get("status", "")] += 1
        if finding.get("status") in ("FAIL", "WARN"):
            by_check[check_id].append(finding)

    population = args.assets or len(assets_seen)
    print(f"population: {population} assets")
    print(f"statuses:   {dict(statuses)}\n")

    if not by_check:
        print("no FAIL or WARN findings — clean sweep")
        return 0

    header = f"{'check':<12} {'n':>5} {'rate':>7}  {'sev':<8} title"
    print(header)
    print("-" * len(header))
    for check_id in sorted(by_check, key=lambda c: -len(by_check[c])):
        group = by_check[check_id]
        rate = 100.0 * len(group) / population if population else 0.0
        title = group[0].get("title", "")
        sev = group[0].get("severity", "")
        print(f"{check_id:<12} {len(group):>5} {rate:>6.1f}%  {sev:<8} {title}")

    print()
    for check_id in sorted(by_check, key=lambda c: -len(by_check[c])):
        group = by_check[check_id]
        print(f"\n=== {check_id} — {len(group)} findings ===")
        reasons: Counter[str] = Counter()
        for finding in group:
            for item in finding.get("evidence", []):
                reasons[item.get("reason", "")[:90]] += 1
        for reason, count in reasons.most_common(12):
            print(f"  {count:>4}  {reason}")
        print("  examples:")
        for finding in group[: args.show]:
            evidence = (finding.get("evidence") or [{}])[0]
            path = evidence.get("path", "")
            line = evidence.get("line")
            snippet = (evidence.get("snippet") or "").replace("\n", " ")[:110]
            where = f"{Path(path).parent.name}:{line}" if path else finding.get("asset", "")
            print(f"    {where:<46} {snippet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
