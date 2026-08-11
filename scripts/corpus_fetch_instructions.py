"""Fetch a corpus of public ``CLAUDE.md`` files for precision measurement.

Findings on this corpus are false-positive candidates, not ground truth: these are
ordinary repositories, so nearly every one should be clean. The sample is a
convenience sample from GitHub code search, stratified by file size so it is not a
single relevance-ranked slice — small terse files and long elaborate ones fail in
different ways.

Requires an authenticated ``gh``. Writes ``<out>/<slug>/CLAUDE.md``, one directory
per repository, which is the layout Argus's nested-instruction glob discovers in a
single scan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

#: Size buckets in bytes. Stratifying keeps the sample from being all short stubs.
BUCKETS: tuple[tuple[str, str], ...] = (
    ("tiny", "size:<800"),
    ("small", "size:800..2500"),
    ("medium", "size:2500..7000"),
    ("large", "size:>7000"),
)


def gh_json(args: list[str]) -> dict:
    result = subprocess.run(
        ["gh", "api", *args], capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip()[:400])
    return json.loads(result.stdout)


def search(qualifier: str, pages: int) -> list[dict]:
    items: list[dict] = []
    for page in range(1, pages + 1):
        query = f"filename:CLAUDE.md path:/ {qualifier}"
        try:
            data = gh_json(
                [
                    "-X",
                    "GET",
                    "search/code",
                    "-f",
                    f"q={query}",
                    "-f",
                    "per_page=100",
                    "-f",
                    f"page={page}",
                ]
            )
        except RuntimeError as exc:
            print(f"  search failed ({qualifier} p{page}): {exc}", file=sys.stderr)
            break
        batch = data.get("items", [])
        items.extend(batch)
        if len(batch) < 100:
            break
        # Code search allows 10 requests/minute for an authenticated token.
        time.sleep(7)
    return items


def raw_url(item: dict) -> str | None:
    html = item.get("html_url") or ""
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)", html)
    if not match:
        return None
    owner, repo, ref, path = match.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"


def download(url: str) -> str | None:
    result = subprocess.run(
        ["curl", "-sSL", "--max-time", "25", url], capture_output=True, text=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("out", type=Path)
    parser.add_argument("--per-bucket", type=int, default=100)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    seen_repos: set[str] = set()
    seen_hashes: set[str] = set()

    for label, qualifier in BUCKETS:
        print(f"[{label}] searching {qualifier}")
        pages = max(1, (args.per_bucket + 99) // 100)
        candidates = search(qualifier, pages)
        print(f"[{label}] {len(candidates)} candidates")

        kept = 0
        for item in candidates:
            if kept >= args.per_bucket:
                break
            full_name = item.get("repository", {}).get("full_name", "")
            if not full_name or full_name in seen_repos:
                continue
            url = raw_url(item)
            if not url:
                continue
            text = download(url)
            if text is None:
                continue
            digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
            if digest in seen_hashes:
                # Forks and templates duplicate the same file; counting it twice
                # would weight one author's phrasing as if it were many.
                continue

            slug = full_name.replace("/", "__")
            target = args.out / slug
            target.mkdir(parents=True, exist_ok=True)
            (target / "CLAUDE.md").write_text(text, encoding="utf-8")

            seen_repos.add(full_name)
            seen_hashes.add(digest)
            manifest.append(
                {
                    "slug": slug,
                    "repo": full_name,
                    "bucket": label,
                    "bytes": len(text.encode("utf-8", "replace")),
                    "sha256": digest,
                    "html_url": item.get("html_url"),
                }
            )
            kept += 1
        print(f"[{label}] kept {kept}")

    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    total = len(manifest)
    by_bucket: dict[str, int] = {}
    for entry in manifest:
        by_bucket[entry["bucket"]] = by_bucket.get(entry["bucket"], 0) + 1
    print(f"\n{total} files from {total} distinct repositories")
    for label, _ in BUCKETS:
        print(f"  {label:7} {by_bucket.get(label, 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
