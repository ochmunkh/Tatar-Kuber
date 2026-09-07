#!/usr/bin/env python3
"""Архитектурын диаграмыг (EN/MN) HTML болгож үүсгэнэ.

Ажиллуулах:
    python3 docs/img/architecture.gen.py            # HTML-ийг /tmp-д бичнэ
    # дараа нь Chrome headless-ээр PNG болгоно (2x scale):
    #   chrome --headless=new --screenshot=docs/img/architecture.png \
    #          --window-size=1200,1090 --force-device-scale-factor=2 architecture.en.html

Хоёр хэлний бүтэц ЯГ ижил байхыг хангахын тулд нэг template-аас үүсгэдэг —
ингэснээр EN/MN диаграм хэзээ ч зөрөхгүй.
"""
import sys

# ── өнгө: тайлан/README-тэй нэг систем ───────────────────────────────────────
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#eef2f6;font-family:'Segoe UI',Inter,Arial,sans-serif;color:#1a2b3a;
     padding:34px 40px 26px;width:1200px}
h1{font-size:38px;font-weight:800;color:#2A4D69;letter-spacing:-.5px}
h1 span{color:#1F6F54}
.sub{font-size:17px;color:#5f7285;margin-top:6px}
.sub b{color:#2A4D69;font-weight:700}
.legend{display:flex;gap:22px;align-items:center;margin:14px 0 4px;font-size:13.5px;color:#5f7285}
.legend i{display:inline-block;width:15px;height:15px;border-radius:4px;border:2px solid #cbd5e1;
          background:#fff;vertical-align:-3px;margin-right:7px}
.legend .t1 i{border-color:#1F6F54;background:#dff2e7}
.legend .nw i{border-color:#B45309;background:#fdf0dd}
.band{margin-top:16px}
.lbl{font-size:13.5px;color:#7b8a99;margin-bottom:7px}
.lbl b{color:#1F6F54;font-weight:700}
.lbl em{color:#B45309;font-weight:700;font-style:normal}
.row{display:grid;gap:14px}
.c3{grid-template-columns:repeat(3,1fr)}
.c4{grid-template-columns:repeat(4,1fr)}
.box{background:#fff;border:1.6px solid #d5dee6;border-radius:12px;padding:13px 16px 14px}
.box .n{font-size:18px;font-weight:700;color:#1a2b3a;display:flex;align-items:center;gap:8px;
        flex-wrap:wrap;line-height:1.25}
.box .d{font-size:14px;color:#5f7285;margin-top:5px;line-height:1.45}
.box.t1{background:#e7f5ed;border-color:#1F6F54}
.box.t1 .n{color:#155e42}
.box.nw{background:#fdf3e6;border-color:#B45309}
.box.nw .n{color:#8a4708}
.tag{font-size:11px;font-weight:700;letter-spacing:.3px;background:#cfeadb;color:#155e42;
     border-radius:20px;padding:2px 9px}
.tag.nw{background:#f7ddb9;color:#8a4708}
.tag.md{background:#e2e8ef;color:#526478;font-weight:600}
.arrow{text-align:center;color:#a8b6c4;font-size:15px;line-height:1;margin:9px 0 -4px}
.foot{display:flex;justify-content:space-between;align-items:center;margin-top:22px;
      padding-top:14px;border-top:1.5px solid #d5dee6;font-size:13.5px;color:#7b8a99}
.foot b{color:#2A4D69;font-weight:700}
"""

# ── хоёр хэлний бичвэр ───────────────────────────────────────────────────────
T = {
 "en": dict(
  lang="en", title="architecture",
  sub='v1.0.2 — parallel · live/offline · explainable risk · CI gate · SARIF · bilingual · <b>scanner accountability</b>',
  lg_core="Core", lg_t1="Tier 1 (v1.0.0)", lg_new="v1.0.2 — accountability",
  s_src="Sources", s_scan="Scanners — parallel",
  scan_note="concurrent + per-scanner timeout + graceful degrade",
  scan_new="every run recorded",
  s_core="Core engine", s_out="Output",
  s_acct="Accountability &amp; verification", s_adopt="Adoption layer",
  src=[("Live cluster","kubeconfig · read-only (Mode B)","t1","Tier 1"),
       ("Manifests","-f ./k8s  ·  Mode A","",""),
       ("Offline raw","--raw-dir json","","")],
  scan=[("Trivy","cve · secret · config","remote"),
        ("Kubescape","nsa · mitre · rbac","local + remote"),
        ("Checkov","iac · helm","local"),
        ("Popeye","runtime hygiene","remote")],
  core=[("Normalize","raw → finding","",""),
        ("Canonical + dedup","one issue · found_by · MITRE/CIS","",""),
        ("Blind-shot","downgrade · annotate","",""),
        ("Risk score","explainable · risk_factors · breakdown","t1","Tier 1")],
  out=[("JSON","machine-readable","",""),
       ("SARIF","github / gitlab · fingerprints","",""),
       ("HTML","bilingual dashboard","",""),
       ("raw/ evidence","re-processable · --no-raw","nw","new")],
  acct=[("scanner_runs[]","ok · error · timeout · unmapped","nw",""),
        ("Scanner coverage","in-report table — nothing hidden","nw",""),
        ("Meaning-lock","4 scanners pinned to upstream","nw",""),
        ("CI proof","kind (Mode B) · static (Mode A) · verify-lab","nw","")],
  adopt=[("CI/CD gatekeeper",".tatar-kuber.yaml · --fail-on · suppress","t1","Tier 1"),
         ("GitHub Action","sarif upload","t1","Tier 1"),
         ("Distribution","binary · install.sh · brew · docker","t1","Tier 1")],
  foot="one command · 4 scanners · parallel · MITRE ATT&amp;CK · SARIF · CI-ready · bilingual · every scanner accounted for",
 ),
 "mn": dict(
  lang="mn", title="архитектур",
  sub='v1.0.2 — зэрэгцээ · амьд/офлайн · тайлбарлагдах эрсдэл · CI gate · SARIF · хоёр хэлт · <b>scanner-ийн шударга байдал</b>',
  lg_core="Цөм (core)", lg_t1="Tier 1 (v1.0.0)", lg_new="v1.0.2 — шударга байдал",
  s_src="Sources — эх сурвалж", s_scan="Scanner-ууд — зэрэг",
  scan_note="зэрэгцээ + scanner тус бүрийн timeout + graceful degrade",
  scan_new="явц бүр бүртгэгдэнэ",
  s_core="Core engine — цөм", s_out="Output — тайлан",
  s_acct="Шударга байдал ба батлалт", s_adopt="Нэвтрүүлэлт",
  src=[("Амьд cluster","kubeconfig · read-only (Mode B)","t1","Tier 1"),
       ("Манифест","-f ./k8s  ·  Mode A","",""),
       ("Офлайн raw","--raw-dir json","","")],
  scan=[("Trivy","cve · secret · config","remote"),
        ("Kubescape","nsa · mitre · rbac","local + remote"),
        ("Checkov","iac · helm","local"),
        ("Popeye","runtime эрүүл ахуй","remote")],
  core=[("Normalize","raw → finding","",""),
        ("Canonical + dedup","нэгтгэх · found_by · MITRE/CIS","",""),
        ("Blind-shot","бууруулах · тэмдэглэх","",""),
        ("Эрсдэл оноо","тайлбарлагдах · risk_factors","t1","Tier 1")],
  out=[("JSON","машин уншигдах","",""),
       ("SARIF","github / gitlab · fingerprints","",""),
       ("HTML","хоёр хэлт dashboard","",""),
       ("raw/ нотолгоо","дахин боловсруулна · --no-raw","nw","шинэ")],
  acct=[("scanner_runs[]","ok · error · timeout · зураглалгүй","nw",""),
        ("Scanner хамрах хүрээ","тайлан дахь хүснэгт — юу ч нуугдахгүй","nw",""),
        ("Утга бэхэлгээ","4 scanner upstream-тай тулгагдсан","nw",""),
        ("CI батлалт","kind (Mode B) · static (Mode A) · verify-lab","nw","")],
  adopt=[("CI/CD gatekeeper",".tatar-kuber.yaml · --fail-on · suppress","t1","Tier 1"),
         ("GitHub Action","sarif upload","t1","Tier 1"),
         ("Түгээлт","binary · install.sh · brew · docker","t1","Tier 1")],
  foot="нэг команд · 4 scanner · зэрэг · MITRE ATT&amp;CK · SARIF · CI-д бэлэн · хоёр хэлт · scanner бүр тайлагнагдана",
 ),
}


def box(name, desc, cls="", tag="", tagcls=""):
    t = f'<span class="tag {tagcls}">{tag}</span>' if tag else ""
    return (f'<div class="box {cls}"><div class="n">{name}{t}</div>'
            f'<div class="d">{desc}</div></div>')


def render(x):
    src = "".join(box(n, d, c, t) for n, d, c, t in x["src"])
    scan = "".join(box(n, d, "", m, "md") for n, d, m in x["scan"])
    core = "".join(box(n, d, c, t) for n, d, c, t in x["core"])
    out = "".join(box(n, d, c, t) for n, d, c, t in x["out"])
    acct = "".join(box(n, d, c, t) for n, d, c, t in x["acct"])
    adopt = "".join(box(n, d, c, t) for n, d, c, t in x["adopt"])
    A = '<div class="arrow">▼</div>'
    return f"""<!DOCTYPE html><html lang="{x['lang']}"><head><meta charset="utf-8">
<title>TATAR-Kuber — {x['title']}</title><style>{CSS}</style></head><body>
<h1>TATAR-<span>Kuber</span> — {x['title']}</h1>
<div class="sub">{x['sub']}</div>
<div class="legend"><span><i></i>{x['lg_core']}</span>
 <span class="t1"><i></i>{x['lg_t1']}</span>
 <span class="nw"><i></i>{x['lg_new']}</span></div>

<div class="band"><div class="lbl">{x['s_src']}</div><div class="row c3">{src}</div></div>{A}
<div class="band"><div class="lbl">{x['s_scan']}  ·  <b>{x['scan_note']}</b>  ·  <em>{x['scan_new']}</em></div>
 <div class="row c4">{scan}</div></div>{A}
<div class="band"><div class="lbl">{x['s_core']}</div><div class="row c4">{core}</div></div>{A}
<div class="band"><div class="lbl">{x['s_out']}</div><div class="row c4">{out}</div></div>{A}
<div class="band"><div class="lbl">{x['s_acct']}  ·  <em>v1.0.2</em></div><div class="row c4">{acct}</div></div>{A}
<div class="band"><div class="lbl">{x['s_adopt']}  ·  <b>Tier 1</b></div><div class="row c3">{adopt}</div></div>

<div class="foot"><span>{x['foot']}</span><b>github.com/ochmunkh/Tatar-Kuber</b></div>
</body></html>"""


if __name__ == "__main__":
    outdir = sys.argv[1] if len(sys.argv) > 1 else "/tmp"
    for k, x in T.items():
        p = f"{outdir}/architecture.{k}.html"
        open(p, "w", encoding="utf-8").write(render(x))
        print("wrote", p)
