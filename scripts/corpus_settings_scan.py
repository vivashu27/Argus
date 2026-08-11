"""Scan a corpus of ``.claude/settings.json`` samples, one project root at a time.

Only one settings file is discovered per project root, so unlike the instruction
corpus this cannot be done in a single pass. Findings are merged into one report
shaped like Argus's own JSON output so the shared summariser can read it.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def scan(argus: str, project: Path) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(  # noqa: S603 — invokes Argus itself, not scanned content
            [argus, "scan", "--path", str(project), "--no-user-scope",
             "--format", "json", "--output", tmp],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode not in (0, 1, 2, 3, 4):
            print(f"  {project.name}: exit {result.returncode} {result.stderr[:160]}",
                  file=sys.stderr)
            return []
        reports = list(Path(tmp).glob("argus-report-*.json"))
        if not reports:
            return []
        data = json.loads(reports[0].read_text(encoding="utf-8"))

    findings = data.get("findings", [])
    for finding in findings:
        # The sample directory is the only thing that distinguishes one settings
        # file from the next; asset ids are identical across the corpus by design.
        finding["sample"] = project.name
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--argus", default=".venv/bin/argus")
    args = parser.parse_args()

    samples = sorted(p for p in args.corpus.iterdir() if p.is_dir())
    print(f"{len(samples)} samples")

    merged: list[dict] = []
    for index, sample in enumerate(samples, start=1):
        merged.extend(scan(args.argus, sample))
        if index % 25 == 0:
            print(f"  {index}/{len(samples)}")

    args.out.write_text(
        json.dumps({"findings": merged, "samples": len(samples)}, indent=2), encoding="utf-8"
    )
    print(f"wrote {args.out} — {len(merged)} findings over {len(samples)} samples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
