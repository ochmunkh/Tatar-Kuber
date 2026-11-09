package audit

// doc — хуудаслалтад бэлэн аудитын тайлан.
//
// Нэг файл, гадаад нөөцгүй: тайлан нь имэйлээр явж, архивт хэвээр үлдэх ёстой.
// Гадаад CSS, шрифт, зураг татдаг тайлан нь жил хагасын дараа өөр юм болж
// харагдана — аудитын баримт тийм байж болохгүй.
const doc = `<!DOCTYPE html>
<html lang="{{.Lang}}"><head><meta charset="utf-8">
<title>{{.L.DocTitle}} — {{.Res.Metadata.ClusterName}}</title>
<style>
  @page { size: A4; margin: 18mm 16mm 20mm 16mm; }
  * { box-sizing: border-box; }
  body { font: 10.5pt/1.5 "Segoe UI", system-ui, -apple-system, Arial, sans-serif;
         color: #16191d; margin: 0; }
  h1, h2, h3 { color: #0b1f3a; line-height: 1.25; }
  h1 { font-size: 22pt; margin: 0 0 6mm; }
  h2 { font-size: 14pt; margin: 10mm 0 3mm; padding-bottom: 1.5mm;
       border-bottom: 1.5pt solid #0b1f3a; break-after: avoid; page-break-after: avoid; }
  h3 { font-size: 11pt; margin: 6mm 0 2mm; break-after: avoid; page-break-after: avoid; }
  p  { margin: 0 0 3mm; }
  .cover { height: 247mm; display: flex; flex-direction: column; justify-content: center;
           break-after: page; page-break-after: always; }
  .cover h1 { font-size: 28pt; }
  .sub { font-size: 12pt; color: #44505f; margin-bottom: 12mm; }
  .conf { margin-top: 10mm; padding: 3mm 4mm; border-left: 3pt solid #b3261e;
          background: #fdf3f2; font-size: 9.5pt; }
  .meta { width: 100%; border-collapse: collapse; margin-top: 8mm; font-size: 10pt; }
  .meta td { padding: 1.6mm 0; vertical-align: top; }
  .meta td:first-child { width: 42mm; color: #5a6675; }
  .mono { font-family: "Cascadia Mono", Consolas, monospace; font-size: 8.5pt; word-break: break-all; }
  table.g { width: 100%; border-collapse: collapse; margin: 3mm 0 5mm; font-size: 9.5pt; }
  table.g th { text-align: left; background: #eef1f5; color: #0b1f3a;
               padding: 2mm; border-bottom: 1pt solid #c9d2dd; }
  table.g td { padding: 2mm; border-bottom: 0.5pt solid #dde3ea; vertical-align: top; }
  tr { break-inside: avoid; page-break-inside: avoid; }
  .sev { font-weight: 700; white-space: nowrap; }
  .CRITICAL { color: #8c1d18; } .HIGH { color: #b3261e; }
  .MEDIUM  { color: #8a5a00; } .LOW  { color: #3a6ea5; } .INFO { color: #5a6675; }
  .bad { color: #b3261e; font-weight: 700; }
  .ok  { color: #1f6b3a; }
  .ctl { break-inside: avoid-page; page-break-inside: avoid; margin-bottom: 7mm; }
  .ctl > .head { display: flex; justify-content: space-between; gap: 4mm; align-items: baseline; }
  .tag { font-size: 8.5pt; color: #44505f; background: #eef1f5; padding: 0.8mm 2mm; border-radius: 2pt; }
  .note { font-size: 9pt; color: #5a6675; }
  .fix { background: #f3f7f3; border-left: 2.5pt solid #1f6b3a; padding: 2mm 3mm; margin: 2mm 0; }
  .expired { background: #fdf3f2; }
  ul { margin: 0 0 3mm 5mm; padding: 0; }
  li { margin: 0.6mm 0; }
  .intro { background: #f7f9fb; border-left: 2.5pt solid #0b1f3a; padding: 2.5mm 3.5mm; margin: 0 0 4mm; }
  @media print { .cover { height: 247mm; } }
</style></head><body>

<section class="cover">
  <h1>{{.L.DocTitle}}</h1>
  <div class="sub">{{.L.Subtitle}}</div>
  <table class="meta">
    <tr><td>{{.L.Cluster}}</td><td><strong>{{.Res.Metadata.ClusterName}}</strong></td></tr>
    <tr><td>{{.L.Generated}}</td><td>{{.Res.Metadata.FinishedAt}}</td></tr>
    <tr><td>{{.L.Mode}}</td><td>{{.Res.Metadata.ScanMode}}</td></tr>
    <tr><td>{{.L.Tool}}</td><td>TATAR-Kuber {{.Res.Metadata.TatarVersion}}</td></tr>
    <tr><td>{{.L.Score}}</td><td><strong>{{.Res.Summary.RiskScore}} / 100</strong> — {{.Res.Summary.RiskBand}}</td></tr>
    <tr><td>{{.L.Total}}</td><td>{{.Res.Summary.TotalFindings}}</td></tr>
    <tr><td>{{.L.Hash}}</td><td class="mono">{{.Res.Metadata.ResultHash}}</td></tr>
  </table>
  <div class="conf">{{.L.Confidential}}</div>
</section>

<h2>{{.L.SecScope}}</h2>
<p>{{.L.ScopeBody}}</p>

<h2>{{.L.SecMethod}}</h2>
<p>{{.L.MethodBody}}</p>
<p class="note">{{.L.NotScanner}}</p>

<h2>{{.L.SecCoverage}}</h2>
<div class="intro">{{.L.CoverageBody}}</div>
{{if .HasRuns}}
<table class="g">
  <tr><th>{{.L.Scanner}}</th><th>{{.L.Status}}</th><th>{{.L.Version}}</th>
      <th>{{.L.Normalized}}</th><th>{{.L.Unmapped}}</th><th>{{.L.Dur}}</th></tr>
  {{range .Runs}}<tr>
    <td>{{.Scanner}}</td>
    <td class="{{if .Bad}}bad{{else}}ok{{end}}">{{.Status}}</td>
    <td>{{.Version}}</td><td>{{.Findings}}</td><td>{{.Unmapped}}</td><td>{{.Duration}}</td>
  </tr>{{end}}
</table>
{{else}}<p class="note">{{.L.CoverageNone}}</p>{{end}}

<h2>{{.L.SecScore}}</h2>
<div class="intro">{{.L.ScoreBody}}</div>
<table class="meta">
  <tr><td>{{.L.Score}}</td><td><strong>{{.Res.Summary.RiskScore}}</strong> ({{.L.Band}}: {{.Res.Summary.RiskBand}})</td></tr>
  {{with .Res.Summary.RiskBreakdown}}
  <tr><td>{{$.L.Formula}}</td><td class="mono">{{.Formula}}</td></tr>
  <tr><td>{{$.L.Penalty}}</td><td>{{num .TotalPenalty}}</td></tr>
  {{end}}
</table>
<table class="g">
  <tr><th>{{.L.Severity}}</th><th>{{.L.Total}}</th></tr>
  {{range .Counts}}<tr><td class="sev {{.Severity}}">{{.Severity}}</td><td>{{.N}}</td></tr>{{end}}
</table>
{{with .Res.Summary.RiskBreakdown}}{{if .TopContributors}}
<h3>{{$.L.Contributor}}</h3>
<table class="g">
  <tr><th>{{$.L.Control}}</th><th>{{$.L.Resource}}</th><th>{{$.L.Severity}}</th><th>{{$.L.Share}}</th></tr>
  {{range .TopContributors}}<tr>
    <td class="mono">{{.CanonicalControl}}</td><td>{{.Resource}}</td>
    <td class="sev {{.Severity}}">{{.Severity}}</td><td>{{pct .Share}}</td>
  </tr>{{end}}
</table>
{{end}}{{end}}

<h2>{{.L.SecAttest}}</h2>
<div class="intro">{{.L.AttestBody}}</div>
{{if .HasAtt}}
<table class="g">
  <tr><th>{{.L.Control}}</th><th>{{.L.Decision}}</th><th>{{.L.Severity}}</th>
      <th>{{.L.By}}</th><th>{{.L.Until}}</th></tr>
  {{range .Res.Attestations}}<tr{{if eq (printf "%s" .Status) "expired"}} class="expired"{{end}}>
    <td class="mono">{{.Control}}<br><span class="note">{{.Title}}</span></td>
    <td>{{index $.L.Decisions (printf "%s" .Decision)}}</td>
    <td class="sev {{.Severity}}">{{.Severity}}</td>
    <td>{{.AttestedBy}}<br><span class="note">{{.AttestedAt}}</span></td>
    <td>{{if eq (printf "%s" .Status) "expired"}}<span class="bad">{{$.L.Expired}}</span><br>{{end}}{{.Expires}}</td>
  </tr>
  <tr{{if eq (printf "%s" .Status) "expired"}} class="expired"{{end}}>
    <td colspan="5"><span class="note">{{$.L.Rationale}}:</span> {{.Rationale}}
    {{if .Scope}}<br><span class="note">{{$.L.ScopeCol}}:</span> {{.Scope}}{{end}}
    {{if .Evidence}}<br><span class="note">{{$.L.Evidence}}:</span> <span class="mono">{{join .Evidence}}</span>{{end}}</td>
  </tr>{{end}}
</table>
{{else}}<p class="note">{{.L.AttestNone}}</p>{{end}}

<h2>{{.L.SecFind}}</h2>
<div class="intro">{{.L.FindBody}}</div>
{{if not .Groups}}<p class="note">{{.L.NoFindings}}</p>{{end}}
{{range .Groups}}
<div class="ctl">
  <div class="head">
    <h3>{{.Control}} — {{.Title}}</h3>
    <span class="sev {{.Severity}}">{{.Severity}}</span>
  </div>
  <p><span class="tag">{{$.L.FoundBy}}: {{join .FoundBy}}</span>
     <span class="tag">{{$.L.Confidence}}: {{.Confidence}}{{if .Reason}} — {{.Reason}}{{end}}</span>
     {{range .Attack}}<span class="tag">{{$.L.Attack}}: {{.Technique}} {{.Name}}</span>{{end}}</p>
  {{if .Description}}<p>{{.Description}}</p>{{end}}
  <table class="g">
    <tr><th>{{$.L.Resource}}</th><th>{{$.L.Severity}}</th><th>{{$.L.Evidence}}</th></tr>
    {{range .Rows}}<tr>
      <td>{{if .Namespace}}<span class="note">{{.Namespace}}/</span>{{end}}{{.Resource}}</td>
      <td class="sev {{.Severity}}">{{.Severity}}{{if .BlindShot}}<br><span class="note">{{$.L.Downgraded}}: {{.BSReason}}</span>{{end}}</td>
      <td class="mono">{{join .Evidence}}</td>
    </tr>{{end}}
  </table>
  {{if .Remediation}}<div class="fix"><strong>{{$.L.Fix}}:</strong> {{.Remediation}}</div>{{end}}
  {{if .References}}<p class="note">{{$.L.Refs}}: {{join .References}}</p>{{end}}
</div>
{{end}}

<h2>{{.L.SecAppendix}}</h2>
<table class="meta">
  <tr><td>{{.L.Hash}}</td><td class="mono">{{.Res.Metadata.ResultHash}}</td></tr>
  <tr><td>{{.L.Lang}}</td><td>{{.Lang}}</td></tr>
  {{with .Res.Metadata.Rollup}}<tr><td>{{$.L.Rollup}}</td><td>{{.Moved}}</td></tr>{{end}}
  {{range $k, $v := .Res.Metadata.ScannerVersions}}<tr><td>{{$k}}</td><td>{{$v}}</td></tr>{{end}}
  {{range $k, $v := .Res.Metadata.Inventory}}<tr><td>{{$.L.Inventory}} — {{$k}}</td><td>{{$v}}</td></tr>{{end}}
</table>

</body></html>
`
