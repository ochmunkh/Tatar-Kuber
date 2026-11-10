#!/usr/bin/env python3
"""
Check the kubescape rule IDs this project maps against what kubescape publishes.

WHY THIS IS NOT A GO TEST. No test in this repository touches the network, and
that rule is worth keeping: a unit test that fails because GitHub is slow
teaches people to ignore failures. But the thing being checked here genuinely
lives upstream and changes without us, so it has to be fetched. It runs as a
daily job instead, exactly like the pin drift check.

WHY IT IS NEEDED AT ALL. kubescape does not embed its rules: it downloads the
policy library at scan time. So its rule set can change **without any version
bump**, which means pinning the binary pins nothing about the meanings, and
`TestKubescapeMappingsMatchUpstreamMeaning` compares against meanings a human
typed in once. That test proves the registry agrees with what someone wrote
down; only this script proves it still agrees with upstream.

Sources, all read from the repo so there is no third list to drift:
  schema/canonical-controls.yaml        -- which C-ids are mapped
  internal/canonical/mapping_test.go    -- the meaning recorded for each

Exit codes:
  0  every mapped control still exists upstream with the recorded meaning
  1  at least one is gone or renamed    (the drift this exists to find)
  2  could not determine the answer     -- NEVER silent
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "schema", "canonical-controls.yaml")
MEANINGS = os.path.join(ROOT, "internal", "canonical", "mapping_test.go")
PUBLISHED = "https://github.com/kubescape/regolibrary/releases/latest/download/controls"


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def mapped_controls():
    """C-id -> TATAR control, бүртгэлээс. YAML сангүйгээр уншина."""
    out, control = {}, None
    in_ks = False
    for line in open(REGISTRY, encoding="utf-8"):
        m = re.match(r"^\s*- id:\s*(TATAR-[A-Z]+-\d+)", line)
        if m:
            control, in_ks = m.group(1), False
            continue
        if re.match(r"^\s*kubescape:\s*$", line):
            in_ks = True
            continue
        if in_ks:
            m = re.match(r'^\s*-\s*"?(C-\d+)"?\s*$', line)
            if m:
                out[m.group(1)] = control
                continue
            if re.match(r"^\s*-?\s*\w+:", line):
                in_ks = False
    if not out:
        die("бүртгэлээс нэг ч kubescape зураглал уншигдсангүй — файлын хэлбэр өөрчлөгдсөн байж болно")
    return out


def recorded_meanings():
    """C-id -> тестэд бичсэн утга."""
    src = open(MEANINGS, encoding="utf-8").read()
    i = src.find("func TestKubescapeMappingsMatchUpstreamMeaning")
    if i < 0:
        die("mapping_test.go дотор kubescape-ийн тест олдсонгүй")
    block = src[i:src.find("\n}", i)]
    out = dict(re.findall(r'\{"(C-\d+)",\s*`([^`]*)`', block))
    if not out:
        die("тестийн want хүснэгт уншигдсангүй — хэлбэр өөрчлөгдсөн байж болно")
    return out


def published():
    req = urllib.request.Request(PUBLISHED, headers={"User-Agent": "tatar-kuber-rules"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.load(r)
    except (urllib.error.URLError, ValueError) as e:
        die(f"нийтлэгдсэн controls уншиж чадсангүй: {e}")
    out = {c["controlID"]: c.get("name", "") for c in data if c.get("controlID")}
    if len(out) < 50:
        die(f"нийтлэгдсэн жагсаалтад ердөө {len(out)} control — хэлбэр өөрчлөгдсөн байж болно")
    return out


def main():
    mapped, meanings, up = mapped_controls(), recorded_meanings(), published()

    missing_meaning = sorted(set(mapped) - set(meanings))
    gone, renamed, ok = [], [], 0
    for cid in sorted(mapped):
        name = up.get(cid)
        if name is None:
            gone.append((cid, mapped[cid]))
            continue
        want = meanings.get(cid)
        if want and want.strip().lower() != name.strip().lower():
            renamed.append((cid, mapped[cid], want, name))
        else:
            ok += 1

    print(f"нийтлэгдсэн {len(up)} control · зураглагдсан {len(mapped)} · тохирсон {ok}")
    for cid, ctl in gone:
        print(f"ALGA    {cid} -> {ctl}: upstream дээр ийм control БАЙХГҮЙ")
    for cid, ctl, want, got in renamed:
        print(f"ЗӨРӨВ   {cid} -> {ctl}\n          тестэд: {want}\n          upstream: {got}")
    if missing_meaning:
        print("тэмдэглэл: утга нь тестэд бичигдээгүй: " + ", ".join(missing_meaning))

    if not gone and not renamed:
        print("\nЗураглагдсан control бүр upstream дээр бичигдсэн утгаараа хэвээр.")
        return 0

    print("\nЗураглал шалгах шаардлагатай. kubescape нь дүрмээ ТАТДАГ тул энэ нь")
    print("хувилбар солигдолгүйгээр ч өөрчлөгдөж болно — яг тийм учраас энэ шалгалт байна.")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## kubescape rule meanings have moved\n\n")
            for cid, ctl in gone:
                fh.write(f"- `{cid}` -> `{ctl}` — **gone upstream**\n")
            for cid, ctl, want, got in renamed:
                fh.write(f"- `{cid}` -> `{ctl}` — recorded *{want}*, upstream *{got}*\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
