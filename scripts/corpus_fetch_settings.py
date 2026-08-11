"""Fetch a corpus of public ``.claude/settings.json`` files.

These drive two sections at once: hooks are declared inside the settings file, and
the permission block is what the CLAUDE-* checks read. As with the instruction
corpus, these are ordinary repositories — a finding here is a false-positive
candidate until the file is read and shown to be genuinely dangerous.

Each sample is written to ``<out>/<slug>/.claude/settings.json``. Unlike instruction
files, only one settings file is discovered per project root, so the scan harness
must invoke Argus once per directory.
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

QUERIES: tuple[tuple[str, str], ...] = (
    ("settings", "filename:settings.json path:.claude"),
    ("settings-local", "filename:settings.local.json path:.claude"),
)


def gh_json(args: list[str]) -> dict:
    result = subprocess.run(["gh", "api", *args], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip()[:400])
    return json.loads(result.stdout)


def search(query: str, pages: int) -> list[dict]:
    items: list[dict] = []
    for page in range(1, pages + 1):
        try:
            data = gh_json(
                ["-X", "GET", "search/code", "-f", f"q={query}",
                 "-f", "per_page=100", "-f", f"page={page}"]
            )
        except RuntimeError as exc:
            print(f"  search failed (p{page}): {exc}", file=sys.stderr)
            break
        batch = data.get("items", [])
        items.extend(batch)
        if len(batch) < 100:
            break
        time.sleep(7)
    return items


def raw_url(item: dict) -> str | None:
    match = re.match(
        r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)", item.get("html_url") or ""
    )
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
    parser.add_argument("--limit", type=int, default=150)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    seen_repos: set[str] = set()
    seen_hashes: set[str] = set()

    for label, query in QUERIES:
        print(f"[{label}] searching")
        candidates = search(query, pages=2)
        print(f"[{label}] {len(candidates)} candidates")
        for item in candidates:
            if len(manifest) >= args.limit:
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
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                # Argus keeps malformed settings as an asset, but for a precision
                # sample we want files that represent real working configuration.
                continue
            if not isinstance(parsed, dict):
                continue
            digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
            if digest in seen_hashes:
                continue

            slug = full_name.replace("/", "__")
            target = args.out / slug / ".claude"
            target.mkdir(parents=True, exist_ok=True)
            (target / Path(item.get("name") or "settings.json").name).write_text(
                text, encoding="utf-8"
            )

            seen_repos.add(full_name)
            seen_hashes.add(digest)
            manifest.append(
                {
                    "slug": slug,
                    "repo": full_name,
                    "file": item.get("name"),
                    "has_hooks": "hooks" in parsed,
                    "has_permissions": "permissions" in parsed,
                    "sha256": digest,
                    "html_url": item.get("html_url"),
                }
            )
        print(f"[{label}] total kept {len(manifest)}")

    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with_hooks = sum(1 for e in manifest if e["has_hooks"])
    with_perms = sum(1 for e in manifest if e["has_permissions"])
    print(f"\n{len(manifest)} settings files")
    print(f"  with a hooks block:       {with_hooks}")
    print(f"  with a permissions block: {with_perms}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
