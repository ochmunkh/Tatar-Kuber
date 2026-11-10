#!/usr/bin/env python3
"""
Resolve the rule IDs the PINNED trivy actually emits against the registry.

WHY. trivy embeds its misconfiguration rules in the binary, so a release can
change the rule IDs themselves — and does. 0.76.1 emits `KSV-0001` where 0.74.0
emitted `AVD-KSV0001`, and leaves `AVDID` empty entirely. The normalizer absorbs
that (strip `AVD-`, drop hyphens, collapse leading zeros — the fix that came out
of the v1.0.0 incident), but "absorbs it" was something a human checked once, by
hand, on 2026-11-10. This script is that check, made repeatable.

It also closes a gap the pins had: `real-cluster.yml` and `static-scan.yml`
install scanners with each project's own installer, which fetches **latest** —
not the pinned release. So the daily runs proved the mappings against whatever
shipped that morning, while `tools.lock.yaml` governed only what a user gets
from `tatar-kuber update`, and nothing exercised that. Run this with the binary
`update` installed and the two stop being different questions.

Usage:  check-trivy-rules.py <trivy-config-output.json>

Exit codes:
  0  every control this corpus must reach was reached
  1  a required control was not reached   (a mapping has moved)
  2  could not determine the answer       -- NEVER silent
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "schema", "canonical-controls.yaml")

# Эмзэг манифест дээр trivy ЗААВАЛ хүрэх ёстой control-ууд. Бүх зураглалыг биш,
# энэ корпус бодитоор өдөөдөг нь. Жагсаалтыг богино байлгах нь зориуд: урт
# жагсаалт нь корпус өөрчлөгдөхөд хуурамч улаан өгч, хүнийг уналт үл тоомсорлож
# сургана.
REQUIRED = [
    "TATAR-CON-001",  # privileged
    "TATAR-CON-002",  # runs as root
    "TATAR-CON-003",  # allow privilege escalation
    "TATAR-CON-005",  # host PID/IPC
    "TATAR-CON-006",  # host network
    "TATAR-IMG-003",  # :latest tag
]

LEAD = re.compile(r"([A-Z])0+(\d)")


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def norm(s):
    """internal/canonical.NormalizeRuleID-ийн trivy салбарын хуулбар."""
    s = s.upper().strip()
    if "*" in s:
        return s
    if s.startswith("AVD-"):
        s = s[4:]
    s = s.replace("-", "")
    return LEAD.sub(r"\1\2", s)


def registry_index():
    """нормчилсон trivy rule -> TATAR control. YAML сангүйгээр уншина."""
    out, control, in_trivy = {}, None, False
    for line in open(REGISTRY, encoding="utf-8"):
        m = re.match(r"^\s*- id:\s*(TATAR-[A-Z]+-\d+)", line)
        if m:
            control, in_trivy = m.group(1), False
            continue
        if re.match(r"^\s*trivy:\s*$", line):
            in_trivy = True
            continue
        if in_trivy:
            m = re.match(r'^\s*-\s*"?([A-Za-z0-9_.*-]+)"?\s*$', line)
            if m:
                out[norm(m.group(1))] = control
                continue
            if re.match(r"^\s*-?\s*\w+:", line):
                in_trivy = False
    if not out:
        die("бүртгэлээс нэг ч trivy зураглал уншигдсангүй — файлын хэлбэр өөрчлөгдсөн байж болно")
    return out


def emitted(path):
    try:
        d = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as e:
        die(f"trivy гаралт уншиж чадсангүй: {e}")
    out = {}
    for r in d.get("Results") or []:
        for m in r.get("Misconfigurations") or []:
            rid = (m.get("AVDID") or m.get("ID") or "").strip()
            if rid:
                out.setdefault(rid, m.get("Title", ""))
    if not out:
        die(f"{path}: нэг ч misconfiguration алга — эмзэг манифест дээр энэ боломжгүй")
    return out


def main():
    if len(sys.argv) != 2:
        die("хэрэглээ: check-trivy-rules.py <trivy-config-output.json>")
    idx, found = registry_index(), emitted(sys.argv[1])

    reached, unmapped = {}, []
    for rid, title in sorted(found.items()):
        ctl = idx.get(norm(rid))
        if ctl:
            reached.setdefault(ctl, []).append(rid)
            print(f"  {rid:<14} -> {norm(rid):<9} -> {ctl:<14} [{title}]")
        else:
            unmapped.append((rid, title))

    print(f"\n{len(found)} rule: зураглагдсан {len(found) - len(unmapped)}, зураглалгүй {len(unmapped)}")
    for rid, title in unmapped:
        # Зураглалгүй нь алдаа БИШ: engine үүнийг unmapped_rules болгон ил
        # гаргадаг. Зориудаар зураглаагүй дүрэм байж болно.
        print(f"  зураглалгүй: {rid:<14} {title}")

    missing = [c for c in REQUIRED if c not in reached]
    if missing:
        print("\nЗУРАГЛАЛ ХӨДӨЛСӨН БАЙНА. Энэ корпус дээр заавал хүрэх ёстой control хүрсэнгүй:")
        for c in missing:
            print(f"  {c}")
        print("\nЭнэ нь pin хөдөлж rule ID өөрчлөгдсөн, эсвэл бүртгэлийн зураглал")
        print("эвдэрсэн гэсэн үг. Хоёулангийн аль нь ч чимээгүй өнгөрөх ёсгүй.")
        return 1

    print(f"\nЗаавал хүрэх {len(REQUIRED)} control бүгд хүрэв.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
