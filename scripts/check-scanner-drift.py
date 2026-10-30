#!/usr/bin/env python3
"""
Compare the pinned scanner releases against what each project publishes now.

Why this exists: `tools.lock.yaml` names an exact release per scanner, and
nothing watches those names. Twelve days after the pins were written, three of
the four had moved and no check said so. A pin that quietly ages is not a
security control, it is a date stamp.

This script does NOT bump anything. Changing a pinned version means re-reading
the checksums from the new release and re-verifying that the scanner's rule IDs
still mean what the registry says they mean — a human step, by design
(CONTRIBUTING: "a mapping is a standing obligation").

Sources of truth, both read from the repo so there is no third list to drift:
  internal/update/catalog.go  -- scanner -> GitHub owner/repo, and the version
                                 the catalogue fetches
  tools.lock.yaml             -- scanner -> the version that is pinned

Exit codes:
  0  every pin is current
  1  at least one pin is behind       (the drift this exists to find)
  2  could not determine the answer   (network, API, parse) -- NEVER silent
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "internal", "update", "catalog.go")
LOCK = os.path.join(ROOT, "tools.lock.yaml")

BLOCK = re.compile(r'Name:\s*"([a-z0-9-]+)"(.*?)\n\t\},', re.S)
VERSION = re.compile(r'Version:\s*"([^"]+)"')
REPO = re.compile(r"https://github\.com/([^/]+)/([^/]+)/releases/download")


def catalogue():
    """scanner -> (owner/repo, version the catalogue fetches)"""
    src = open(CATALOG, encoding="utf-8").read()
    out = {}
    for name, body in BLOCK.findall(src):
        v = VERSION.search(body)
        r = REPO.search(body)
        if not v or not r:
            die(f"catalog.go: could not read version/repo for {name!r}")
        out[name] = (f"{r.group(1)}/{r.group(2)}", v.group(1))
    if not out:
        die("catalog.go: parsed no scanners at all -- the file shape changed")
    return out


def pinned():
    """scanner -> version, from the shipped lock."""
    out, cur = {}, None
    for line in open(LOCK, encoding="utf-8"):
        if re.match(r"^  [a-z0-9-]+:\s*$", line):
            cur = line.strip().rstrip(":")
        elif cur:
            m = re.match(r'^    version:\s*"([^"]+)"', line)
            if m:
                out[cur] = m.group(1)
                cur = None
    if not out:
        die("tools.lock.yaml: parsed no versions at all -- the file shape changed")
    return out


def latest(repo):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "tatar-kuber-drift"},
    )
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)["tag_name"].lstrip("v")
    except (urllib.error.URLError, KeyError, ValueError) as e:
        die(f"{repo}: could not read the latest release: {e}")


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def semver(v):
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.\-+]", v)[:3])


def main():
    cat, lock = catalogue(), pinned()
    rows, behind = [], []
    for name in sorted(cat):
        repo, catver = cat[name]
        lockver = lock.get(name)
        if lockver is None:
            die(f"{name}: in the catalogue but not in tools.lock.yaml")
        if lockver != catver:
            die(f"{name}: catalogue fetches {catver} but the lock pins {lockver} "
                "-- fix that before asking about upstream")
        up = latest(repo)
        stale = semver(up) > semver(lockver)
        rows.append((name, repo, lockver, up, stale))
        if stale:
            behind.append((name, repo, lockver, up))

    width = max(len(r[0]) for r in rows)
    for name, repo, have, up, stale in rows:
        mark = "BEHIND" if stale else "ok    "
        print(f"{mark}  {name.ljust(width)}  pinned {have:<10} upstream {up:<10}  {repo}")

    if not behind:
        print("\nEvery pin is current.")
        return 0

    print(f"\n{len(behind)} of {len(rows)} scanner pins are behind upstream.")
    print("Bumping one is not a version edit: re-read the checksums from the new")
    print("release's own published checksum file, then re-verify the rule mappings")
    print("against the new release before the pin moves.")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## Scanner pins behind upstream\n\n")
            fh.write("| scanner | pinned | upstream |\n|---|---|---|\n")
            for name, repo, have, up in behind:
                fh.write(f"| [{name}](https://github.com/{repo}/releases) | `{have}` | `{up}` |\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
