"""Clone public Claude Code plugin marketplaces into a scannable fake HOME.

Plugin discovery is user-scoped and rooted at ``~/.claude/plugins/marketplaces``, so
a corpus has to be laid out as a home directory rather than a project. The scan is
then run with ``HOME`` pointed at the corpus root.

Every marketplace here is third-party by definition — Anthropic's own is already
installed on a real machine — so PLUGIN-001 is expected to fire on all of them. That
is a provenance statement, not a defect; the interesting numbers are the other seven
checks.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def gh_json(args: list[str]) -> dict:
    result = subprocess.run(["gh", "api", *args], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip()[:400])
    return json.loads(result.stdout)


def find_marketplaces(limit: int) -> list[str]:
    """Repositories that publish a ``.claude-plugin/marketplace.json``."""
    repos: list[str] = []
    seen: set[str] = set()
    for page in (1, 2):
        try:
            data = gh_json(
                ["-X", "GET", "search/code",
                 "-f", "q=filename:marketplace.json path:.claude-plugin",
                 "-f", "per_page=100", "-f", f"page={page}"]
            )
        except RuntimeError as exc:
            print(f"  search failed: {exc}", file=sys.stderr)
            break
        items = data.get("items", [])
        for item in items:
            full_name = item.get("repository", {}).get("full_name", "")
            if full_name and full_name not in seen:
                seen.add(full_name)
                repos.append(full_name)
        if len(items) < 100 or len(repos) >= limit:
            break
    return repos[:limit]


def clone(full_name: str, dest: Path) -> bool:
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet",
         f"https://github.com/{full_name}.git", str(dest)],
        capture_output=True, text=True, timeout=180,
    )
    if result.returncode != 0:
        return False
    shutil.rmtree(dest / ".git", ignore_errors=True)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("home", type=Path, help="Fake HOME root to build.")
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()

    root = args.home / ".claude" / "plugins" / "marketplaces"
    root.mkdir(parents=True, exist_ok=True)

    repos = find_marketplaces(args.limit)
    print(f"{len(repos)} candidate marketplaces")

    manifest: list[dict] = []
    for full_name in repos:
        slug = full_name.replace("/", "__")
        dest = root / slug
        if dest.exists():
            continue
        if not clone(full_name, dest):
            print(f"  clone failed: {full_name}", file=sys.stderr)
            continue
        plugin_parent = dest / "plugins"
        plugins = (
            [p.name for p in sorted(plugin_parent.iterdir()) if p.is_dir()]
            if plugin_parent.is_dir()
            else ["<marketplace root>"]
        )
        manifest.append({"repo": full_name, "slug": slug, "plugins": plugins})
        print(f"  {full_name}: {len(plugins)} plugin(s)")

    (args.home / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    total = sum(len(entry["plugins"]) for entry in manifest)
    print(f"\n{len(manifest)} marketplaces, {total} plugins")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
