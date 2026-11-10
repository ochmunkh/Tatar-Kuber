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

WHAT COUNTS AS DRIFT, AND WHY IT IS NOT "not the newest".

The first version of this check raised on plain inequality. That was wrong, and
using it showed why within half an hour: while the pins were being verified and
moved on 2026-11-10, trivy, kubescape and checkov all published again. These
projects release constantly, so "behind upstream" is permanently true, an issue
raised on it never closes, and a permanently open issue is the same failure as a
Security tab with twenty alerts nobody reads any more.

A pin is a REVIEWED version, not the newest one. So this raises only when being
behind actually means something:

  * a MINOR or MAJOR version behind. A scanner can change its rule IDs in such a
    release and did: trivy 0.76.1 emits `KSV-0001` where 0.74.0 emitted
    `AVD-KSV0001`, with AVDID empty. That is the class of change that silently
    breaks a mapping, so it is worth a human.
  * the pinned release is older than MAX_PIN_AGE_DAYS. Patches accumulate, and
    a pin nobody has looked at in a season has stopped being a decision.

A patch published this morning is reported as information and raises nothing.

Exit codes:
  0  nothing actionable (current, or only a recent patch behind)
  1  actionable drift   (minor/major behind, or the pin has aged out)
  2  could not determine the answer   (network, API, parse) -- NEVER silent
"""

import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request

# MAX_PIN_AGE_DAYS — пиннэсэн release энэ хугацаанаас хуучирвал, зөвхөн patch
# хоцорсон байсан ч хүн харах ёстой. 90 хоног нь дур зоргын тоо биш ч хатуу
# шинжлэх ухаан ч биш: улирал бүр нэг удаа pin-ээ дахин шийдэх гэсэн үг.
MAX_PIN_AGE_DAYS = 90

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


def release(repo, tag=None):
    """tag=None -> latest. Буцаана: (version, published_at | None)."""
    url = (f"https://api.github.com/repos/{repo}/releases/tags/{tag}" if tag
           else f"https://api.github.com/repos/{repo}/releases/latest")
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "tatar-kuber-drift"},
    )
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
            return d["tag_name"].lstrip("v"), d.get("published_at")
    except urllib.error.HTTPError as e:
        if tag is not None and e.code == 404:
            # Пиннэсэн хувилбар нь өөр нэршилтэй tag-тай байж болно (ж: v-гүй).
            # Насыг нь мэдэхгүй гэдэг нь алдаа биш, зүгээр л мэдэхгүй.
            return None, None
        die(f"{repo}: could not read {tag or 'the latest release'}: {e}")
    except (urllib.error.URLError, KeyError, ValueError) as e:
        die(f"{repo}: could not read {tag or 'the latest release'}: {e}")


def age_days(published_at):
    if not published_at:
        return None
    t = datetime.datetime.strptime(published_at, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc)
    return (datetime.datetime.now(datetime.timezone.utc) - t).days


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def semver(v):
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.\-+]", v)[:3])


def tag_candidates(name, version):
    """Release tag-ийн нэршил төслөөс хамаарна (checkov нь v-гүй)."""
    return [f"v{version}", version]


def main():
    cat, lock = catalogue(), pinned()
    rows = []
    for name in sorted(cat):
        repo, catver = cat[name]
        lockver = lock.get(name)
        if lockver is None:
            die(f"{name}: in the catalogue but not in tools.lock.yaml")
        if lockver != catver:
            die(f"{name}: catalogue fetches {catver} but the lock pins {lockver} "
                "-- fix that before asking about upstream")

        up, _ = release(repo)
        age = None
        for tag in tag_candidates(name, lockver):
            _, published = release(repo, tag)
            if published:
                age = age_days(published)
                break

        have_v, up_v = semver(lockver), semver(up)
        if up_v <= have_v:
            state, why = "ok", "current"
        elif up_v[:2] > have_v[:2]:
            # Minor/major — rule ID өөрчлөгдөж болох ангилал.
            state = "DRIFT"
            why = f"{'major' if up_v[0] > have_v[0] else 'minor'} behind — rule IDs can change in these"
        elif age is not None and age > MAX_PIN_AGE_DAYS:
            state = "DRIFT"
            why = f"patch behind and the pin is {age} days old (limit {MAX_PIN_AGE_DAYS})"
        else:
            state = "info"
            why = "patch behind" + (f", pin is {age} days old" if age is not None else "")
        rows.append((name, repo, lockver, up, state, why))

    width = max(len(r[0]) for r in rows)
    for name, repo, have, up, state, why in rows:
        print(f"{state:<6} {name.ljust(width)}  pinned {have:<10} upstream {up:<10}  {why}")

    drift = [r for r in rows if r[4] == "DRIFT"]
    if not drift:
        print(f"\nNothing actionable. A pin is a reviewed version, not the newest one;")
        print(f"this raises on a minor/major gap or a pin older than {MAX_PIN_AGE_DAYS} days.")
        return 0

    print(f"\n{len(drift)} of {len(rows)} pins need a human.")
    print("Moving a pin is not a version edit: re-read the checksums from the new")
    print("release's own published checksum file, then re-verify that the scanner's")
    print("rule IDs still mean what the registry says, before the pin moves.")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## Scanner pins that need a human\n\n")
            fh.write("| scanner | pinned | upstream | why |\n|---|---|---|---|\n")
            for name, repo, have, up, _, why in drift:
                fh.write(f"| [{name}](https://github.com/{repo}/releases) | `{have}` | `{up}` | {why} |\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
