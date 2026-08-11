"""Download the labelled malicious skills from MaliciousAgentSkillsBench.

This is the recall side of the measurement: 157 skills a published benchmark labels
malicious. It exists so that a precision fix can be checked against detection in the
same commit — narrowing a rule to remove false positives is only an improvement if
the true positives survive.

Lays the skills out as ``<out>/.claude/skills/<name>/SKILL.md`` so one Argus run
covers the whole set.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
from pathlib import Path

csv.field_size_limit(10**8)


def raw_url(url: str) -> str:
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)", url)
    if match:
        owner, repo, ref, path = match.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    return url


def download(url: str) -> str | None:
    result = subprocess.run(
        ["curl", "-sSL", "--max-time", "25", url], capture_output=True, text=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--label", default="malicious")
    args = parser.parse_args()

    rows = [
        row
        for row in csv.DictReader(args.dataset.open(encoding="utf-8"))
        if row.get("classification") == args.label
    ]
    print(f"{len(rows)} rows labelled {args.label}")

    root = args.out / ".claude" / "skills"
    root.mkdir(parents=True, exist_ok=True)

    manifest: list[dict] = []
    failed = 0
    for index, row in enumerate(rows, start=1):
        text = download(raw_url(row["url"]))
        if text is None:
            failed += 1
            continue
        name = re.sub(r"[^\w.-]", "_", f"{index:03d}_{row.get('skill_name') or 'skill'}")[:80]
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "SKILL.md").write_text(text, encoding="utf-8")
        manifest.append({"dir": name, "repo": row.get("repo"), "skill": row.get("skill_name")})

    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"downloaded {len(manifest)}, failed {failed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
