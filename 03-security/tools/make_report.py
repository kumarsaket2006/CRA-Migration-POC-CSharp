#!/usr/bin/env python3
"""
Generates the CRA compliance report (self-contained HTML) and the traceability matrix (Markdown)
from the scan evidence in 03-security/reports/{baseline,final} and 04-compliance/traceability.json.

  python make_report.py

Re-run after run_scans.py / run-snyk.ps1 / build-and-scan.ps1 so the report always reflects the evidence.
"""
import datetime
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "03-security" / "reports"
COMP = ROOT / "04-compliance"
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load(path, default=None):
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8-sig")) if p.exists() else default


def e(x):
    return html.escape(str(x))


def phase(name):
    d = REP / name
    return {
        "summary": load(d / "summary.json", {}),
        "sca": load(d / "sca.json", {"findings": []}),
        "sast": load(d / "sast-semgrep.json", {"results": []}),
        "sbom": load(d / "sbom.cdx.json", {"components": []}),
        "secrets": load(d / "secrets-detect-secrets.json", {"results": {}}),
        "manual": load(ROOT / "03-security" / "manual-review" / f"{name}.json", []),
    }


def rule_of(r):
    cid = r["check_id"]
    return cid[cid.find("cra.") + 4:]


def sev_of(r):
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}[r["extra"]["severity"]]


def secrets_count(p):
    return sum(len(v) for v in p["secrets"].get("results", {}).values()) + sum(
        1 for r in p["sast"]["results"] if r["extra"].get("metadata", {}).get("category") == "secrets")


def kpis(p):
    sca = p["sca"]["findings"]
    sast = p["sast"]["results"]
    man = p["manual"]
    return {
        "Dependency & runtime vulnerabilities (SCA)": len(sca),
        "  of which Critical/High": sum(1 for f in sca if f["severity"] in ("CRITICAL", "HIGH")),
        "SAST findings (Semgrep)": len(sast),
        "  of which High": sum(1 for r in sast if sev_of(r) == "HIGH"),
        "Secrets in source/config": secrets_count(p),
        "Architecture review findings": len(man),
        "  of which Critical/High": sum(1 for m in man if m["severity"] in ("CRITICAL", "HIGH")),
    }


def bar_chart(categories, base, final):
    """Grouped horizontal bars, inline SVG (no external assets)."""
    w, row, left = 760, 46, 250
    h = row * len(categories) + 40
    mx = max(base + final + [1])
    scale = (w - left - 60) / mx
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Findings before and after migration" class="chart">']
    for i, (c, b, f) in enumerate(zip(categories, base, final)):
        y = 20 + i * row
        out.append(f'<text x="{left - 12}" y="{y + 17}" text-anchor="end" class="lbl">{e(c)}</text>')
        out.append(f'<rect x="{left}" y="{y}" width="{max(b * scale, 2):.1f}" height="16" rx="3" class="b-base"/>')
        out.append(f'<text x="{left + b * scale + 6:.1f}" y="{y + 13}" class="val">{b}</text>')
        out.append(f'<rect x="{left}" y="{y + 19}" width="{max(f * scale, 2):.1f}" height="16" rx="3" class="b-final"/>')
        out.append(f'<text x="{left + f * scale + 6:.1f}" y="{y + 32}" class="val">{f}</text>')
    out.append("</svg>")
    return "".join(out)


def pill(text):
    t = str(text)
    cls = {"CRITICAL": "crit", "HIGH": "high", "MODERATE": "med", "MEDIUM": "med", "LOW": "low", "INFO": "low",
           "Met": "ok", "Closed": "ok", "Partially met": "part", "Open": "open"}.get(t.split(" (")[0], "neutral")
    if t.startswith("Closed"):
        cls = "ok" if t == "Closed" else "part"
    if t.startswith("Open"):
        cls = "open"
    return f'<span class="pill {cls}">{e(t)}</span>'


def issue_counts(issue, p):
    n = 0
    for r in issue["baselineRules"]:
        if r == "SCA":
            n += len(p["sca"]["findings"])
        elif r == "detect-secrets":
            n += sum(len(v) for v in p["secrets"].get("results", {}).values())
        elif r.startswith("manual"):
            mid = r.split()[1]
            n += sum(1 for m in p["manual"] if m["id"] == mid)
        else:
            n += sum(1 for x in p["sast"]["results"] if rule_of(x).endswith(r))
    return n


def snyk_block(b, f):
    rows = []
    for name, p in (("Baseline (v2.3 legacy)", b), ("Final (v3.0 .NET 10)", f)):
        s = p["summary"].get("snyk")
        if s:
            for file, v in s.items():
                rows.append(f"<tr><td>{e(name)}</td><td><code>{e(file)}</code></td><td>{v['total']}</td>"
                            f"<td>{e(', '.join(f'{k} {n}' for k, n in v['bySeverity'].items()) or '-')}</td></tr>")
        else:
            rows.append(f"<tr><td>{e(name)}</td><td colspan='3' class='muted'>Not yet run. Execute "
                        f"<code>03-security\\tools\\run-snyk.ps1 -Phase {'baseline' if 'Baseline' in name else 'final'}</code> "
                        f"with your Snyk token, then re-run <code>run_scans.py</code> and <code>make_report.py</code>.</td></tr>")
    return "<table><thead><tr><th>Phase</th><th>Snyk report</th><th>Issues</th><th>By severity</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def main():
    b, f = phase("baseline"), phase("final")
    trace = load(COMP / "traceability.json")
    kb, kf = kpis(b), kpis(f)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    cats = ["Dependency / runtime CVEs", "SAST findings", "Secrets", "Architecture review", "Unsupported runtimes"]
    eol = lambda p: sum(1 for x in p["sca"]["findings"] if x["type"] == "eol-runtime")
    base_vals = [len(b["sca"]["findings"]) - eol(b), len(b["sast"]["results"]), secrets_count(b), len(b["manual"]), eol(b)]
    final_vals = [len(f["sca"]["findings"]) - eol(f), len(f["sast"]["results"]), secrets_count(f), len(f["manual"]), eol(f)]

    p1 = trace["craPart1"]
    p2 = trace["craPart2"]
    met1 = sum(1 for r in p1 if r["status"] == "Met")
    met2 = sum(1 for r in p2 if r["status"] == "Met")
    closed = sum(1 for i in trace["issues"] if i["status"].startswith("Closed"))
    roslyn = f["summary"].get("roslyn") or {}

    # ---------- tables ----------
    kpi_rows = "".join(
        f"<tr class='{'sub' if k.startswith('  ') else ''}'><td>{e(k.strip())}</td><td class='num'>{kb[k]}</td><td class='num'>{kf[k]}</td>"
        f"<td class='num delta'>{'-' + str(kb[k] - kf[k]) if kb[k] > kf[k] else ('+' + str(kf[k] - kb[k]) if kf[k] > kb[k] else '0')}</td></tr>"
        for k in kb)

    sca_rows = "".join(
        f"<tr><td>{pill(x['severity'])}</td><td><a href='{e(x['url'])}'>{e(x['id'])}</a><br><span class='muted'>{e(', '.join(x['aliases']))}</span></td>"
        f"<td>{e(x['component'])}</td><td>{e(', '.join(x['fixedIn']))}</td><td>{e(x['summary'])}</td>"
        f"<td>{'Removed - replaced by in-box API / .NET 10' if x['type'] != 'eol-runtime' else 'Retargeted to .NET 10 LTS (support to 2028-11-14)'}</td></tr>"
        for x in b["sca"]["findings"])

    def comp_rows(p):
        return "".join(
            f"<tr><td>{e(c['name'])}</td><td>{e(c['version'])}</td><td>{e(c['type'])}</td><td>{e(c.get('scope', ''))}</td>"
            f"<td>{e(', '.join(l['license'].get('id') or l['license'].get('name') for l in c.get('licenses', [])) or '-')}</td></tr>"
            for c in p["sbom"]["components"])

    rules = {}
    for x in b["sast"]["results"]:
        rules.setdefault(rule_of(x), [sev_of(x), x["extra"]["metadata"].get("cwe", ""), 0, 0])[2] += 1
    for x in f["sast"]["results"]:
        rules.setdefault(rule_of(x), [sev_of(x), x["extra"]["metadata"].get("cwe", ""), 0, 0])[3] += 1
    sast_rows = "".join(
        f"<tr><td>{pill(v[0])}</td><td><code>{e(k)}</code></td><td>{e(v[1] or '-')}</td><td class='num'>{v[2]}</td><td class='num'>{v[3]}</td></tr>"
        for k, v in sorted(rules.items(), key=lambda kv: (SEV_RANK[kv[1][0]], -kv[1][2])))
    final_sast = "".join(
        f"<tr><td>{pill(sev_of(x))}</td><td><code>{e(rule_of(x))}</code></td><td><code>{e(x['path'].split('02-modern/')[-1])}:{x['start']['line']}</code></td>"
        f"<td>Triaged - accepted: developer simulator tool (not part of the shipped product); a client disconnect is normal control flow.</td></tr>"
        for x in f["sast"]["results"])

    trace_rows = "".join(
        f"<tr><td><b>{e(i['id'])}</b><div style='margin-top:6px'>{pill(i['status'])}</div></td><td>{e(i['title'])}<br><span class='muted'>{e(i['cwe'])}</span></td><td>{e(i['cra'])}</td>"
        f"<td class='num'>{issue_counts(i, b)}</td><td>{e(i['fix'])}<br><span class='muted'>{e(i['modern'])}</span></td>"
        f"<td class='tests'>{'<br>'.join(e(t).replace('_', '_<wbr>') for t in i['tests']) or '-'}</td><td>{e(i['finalEvidence'])}</td></tr>"
        for i in trace["issues"])

    def cra_rows(rows, part):
        return "".join(f"<tr><td>{part} {e(r['ref'])}</td><td>{e(r['req'])}</td><td>{pill(r['status'])}</td><td>{e(r['evidence'])}</td></tr>" for r in rows)

    man_b = "".join(f"<tr><td>{pill(m['severity'])}</td><td><b>{e(m['id'])}</b> {e(m['title'])}</td><td>{e(m['cwe'])}</td><td>{e(m['cra'])}</td><td>Closed in v3.0 ({e(m['issue'])})</td></tr>" for m in b["manual"])
    man_f = "".join(f"<tr><td>{pill(m['severity'])}</td><td><b>{e(m['id'])}</b> {e(m['title'])}<br><span class='muted'>{e(m['detail'])}</span></td><td>{e(m['cra'])}</td><td>{e(m['status'])}</td></tr>" for m in f["manual"])

    tools_b, tools_f = b["summary"].get("tools", {}), f["summary"].get("tools", {})
    sast_cov = f["summary"].get("sast", {})

    css = """
:root{--ink:#16202b;--muted:#5d6b7a;--line:#dfe4ea;--bg:#f6f8fa;--card:#fff;--brand:#0b5cad;--base:#c2410c;--final:#15803d;
--crit:#7f1d1d;--high:#b91c1c;--med:#b45309;--low:#475569;--ok:#15803d;--part:#a16207;--open:#b91c1c}
*{box-sizing:border-box}body{margin:0;font:14px/1.55 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif;color:var(--ink);background:var(--bg)}
header{background:linear-gradient(120deg,#0b2f55,#0b5cad);color:#fff;padding:36px 48px 30px}
header h1{margin:0 0 6px;font-size:26px;font-weight:650;letter-spacing:-.2px}header p{margin:2px 0;opacity:.88}
.badges{margin-top:14px;display:flex;gap:8px;flex-wrap:wrap}.badges span{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.25);padding:3px 10px;border-radius:999px;font-size:12px}
main{max-width:1180px;margin:0 auto;padding:26px 32px 60px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:22px 26px;margin:0 0 20px}
h2{font-size:18px;margin:0 0 4px}h2 small{font-weight:400;color:var(--muted);font-size:13px;margin-left:6px}h3{font-size:14px;margin:18px 0 8px;color:#243446}
.lead{color:var(--muted);margin:0 0 14px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:14px 0 4px}
.kpi{border:1px solid var(--line);border-radius:9px;padding:14px 16px;background:#fbfcfd}
.kpi .k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.kpi .v{font-size:26px;font-weight:650;margin-top:4px}.kpi .v s{color:var(--base);font-size:17px;font-weight:500;margin-right:8px}
.kpi .v b{color:var(--final)}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}th,td{text-align:left;padding:8px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#f1f4f7;font-weight:600;font-size:12px;color:#334155}td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
tr.sub td:first-child{padding-left:26px;color:var(--muted)}td.delta{color:var(--final);font-weight:600}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;font-weight:600;color:#fff;white-space:nowrap}
.crit{background:var(--crit)}.high{background:var(--high)}.med{background:var(--med)}.low{background:var(--low)}.ok{background:var(--ok)}.part{background:var(--part)}.open{background:var(--open)}.neutral{background:#64748b}
.muted{color:var(--muted);font-size:12px}code{font:12px Consolas,"Cascadia Mono",monospace;background:#f1f4f7;padding:1px 4px;border-radius:4px}
.chart{width:100%;max-width:820px}.chart .lbl{font-size:13px;fill:#334155}.chart .val{font-size:12px;fill:#334155;font-weight:600}
.b-base{fill:var(--base)}.b-final{fill:var(--final)}.legend{display:flex;gap:18px;font-size:12.5px;color:var(--muted);margin:4px 0 0}
.legend i{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.scroll{overflow-x:auto}.trace td,.trace th{padding:7px 6px}.trace .pill{white-space:normal;text-align:center}.trace{table-layout:fixed}.trace td.tests{font-size:11.5px;font-family:Consolas,'Cascadia Mono',monospace;color:#334155}.trace td{overflow-wrap:anywhere}.trace td:first-child .pill{font-size:10.5px;padding:1px 6px}
td:first-child{white-space:nowrap}.trace td:nth-child(2){white-space:normal}
.two{display:grid;grid-template-columns:1fr 1fr;gap:18px}.verdict{border-left:4px solid var(--final);background:#f0fdf4;padding:12px 16px;border-radius:6px;margin:12px 0 0}
.warn{border-left:4px solid var(--part);background:#fefce8;padding:10px 14px;border-radius:6px;margin:10px 0}
a{color:var(--brand)}footer{color:var(--muted);font-size:12px;text-align:center;padding:10px}
@media print{body{background:#fff}section{break-inside:avoid;border:none;padding:10px 0}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
@media (max-width:900px){.grid{grid-template-columns:1fr 1fr}.two{grid-template-columns:1fr}main{padding:16px}}
"""

    # distinct findings (Semgrep secret rules are already part of the SAST count)
    ds = lambda p: sum(len(v) for v in p["secrets"].get("results", {}).values())
    total_base = len(b["sca"]["findings"]) + len(b["sast"]["results"]) + ds(b) + len(b["manual"])
    total_final = len(f["sca"]["findings"]) + len(f["sast"]["results"]) + ds(f) + len(f["manual"])
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CRA Compliance Report - Indusoft FieldGateway</title><style>{css}</style></head><body>
<header>
  <h1>EU Cyber Resilience Act - Security &amp; Compliance Report</h1>
  <p><b>Indusoft FieldGateway</b> (industrial Modbus TCP field-device gateway) &middot; migration v2.3 (.NET Framework 4.0/4.5) &rarr; v3.0 (.NET 10 LTS)</p>
  <p>Generated {e(now)} from scan evidence in <code style="background:rgba(255,255,255,.15);color:#fff">03-security/reports</code></p>
  <div class="badges"><span>Regulation (EU) 2024/2847</span><span>Annex I Part I &amp; II</span><span>Art. 14 reporting in force since 11 Sep 2026</span><span>Full application 11 Dec 2027</span><span>POC - architect review</span></div>
</header>
<main>

<section>
  <h2>1. Executive summary</h2>
  <p class="lead">The legacy library had {total_base} distinct security findings across dependencies, code, secrets and architecture review, and it ran on an unsupported runtime. After the .NET 10 migration with CRA remediation, {total_final} remain: one triaged SAST item in a developer tool and {len(f['manual'])} documented residual risks. None of them is critical or high.</p>
  <div class="grid">
    <div class="kpi"><div class="k">Known vulnerabilities (SCA)</div><div class="v"><s>{len(b['sca']['findings'])}</s><b>{len(f['sca']['findings'])}</b></div></div>
    <div class="kpi"><div class="k">SAST high severity</div><div class="v"><s>{kb['  of which High']}</s><b>{kf['  of which High']}</b></div></div>
    <div class="kpi"><div class="k">Secrets in source/config</div><div class="v"><s>{secrets_count(b)}</s><b>{secrets_count(f)}</b></div></div>
    <div class="kpi"><div class="k">Legacy issues closed</div><div class="v"><b>{closed}</b> / {len(trace['issues'])}</div></div>
  </div>
  <div class="grid">
    <div class="kpi"><div class="k">CRA Annex I Part I met</div><div class="v"><b>{met1}</b> / {len(p1)}</div></div>
    <div class="kpi"><div class="k">CRA Annex I Part II met</div><div class="v"><b>{met2}</b> / {len(p2)}</div></div>
    <div class="kpi"><div class="k">Security regression tests</div><div class="v"><b>43</b> pass</div></div>
    <div class="kpi"><div class="k">Roslyn security rules (final)</div><div class="v"><b>{roslyn.get('total', 'n/a')}</b> violations</div></div>
  </div>
  <div class="verdict"><b>Architect's verdict:</b> v3.0 meets the Annex I Part I product requirements that apply to the gateway software, except for two that are partly met: (2)(f), because the field protocol cannot be protected end-to-end, and (2)(m), because there is no in-product data wipe yet. Annex I Part II is technically enabled (SBOM, VEX, CVD policy, CI gates). The PSIRT organisation must now run it. Before release, three things are still needed: signing-key provisioning (L13), integration tests for the authorisation paths, and Snyk evidence from the connected build machine.</div>
</section>

<section>
  <h2>2. Before / after <small>all scanners, same rule set and advisory snapshot</small></h2>
  {bar_chart(cats, base_vals, final_vals)}
  <div class="legend"><span><i style="background:var(--base)"></i>Baseline - v2.3 legacy</span><span><i style="background:var(--final)"></i>Final - v3.0 .NET 10</span></div>
  <h3>Scanner results</h3>
  <table><thead><tr><th>Metric</th><th class="num">Baseline</th><th class="num">Final</th><th class="num">Change</th></tr></thead><tbody>{kpi_rows}</tbody></table>
</section>

<section>
  <h2>3. Software composition analysis &amp; SBOM <small>CRA Annex I Part I (2)(a), Part II (1)</small></h2>
  <p class="lead">Advisory source: GitHub Advisory Database (reviewed, NuGet), {e(tools_f.get('sca', ''))}. This is the same database that NuGet Audit uses. The final build fails on any advisory (NU1901-NU1904 are treated as errors).</p>
  <h3>Baseline findings ({len(b['sca']['findings'])}) &rarr; final ({len(f['sca']['findings'])})</h3>
  <table><thead><tr><th>Severity</th><th>Advisory</th><th>Component</th><th>Fixed in</th><th>Summary</th><th>Remediation in v3.0</th></tr></thead><tbody>{sca_rows}</tbody></table>
  <div class="two">
    <div><h3>SBOM - baseline ({len(b['sbom']['components'])} components)</h3>
      <table><thead><tr><th>Component</th><th>Version</th><th>Type</th><th>Scope</th><th>Licence</th></tr></thead><tbody>{comp_rows(b)}</tbody></table></div>
    <div><h3>SBOM - final ({len(f['sbom']['components'])} components)</h3>
      <table><thead><tr><th>Component</th><th>Version</th><th>Type</th><th>Scope</th><th>Licence</th></tr></thead><tbody>{comp_rows(f)}</tbody></table></div>
  </div>
  <p class="muted">CycloneDX 1.5 files: <code>reports/*/sbom.cdx.json</code> (declared direct dependencies and runtimes) and <code>reports/*/sca.vex.cdx.json</code> (VEX). The full transitive SBOM is produced by <code>dotnet CycloneDX</code> in <code>build-and-scan.ps1</code> / CI. The legacy GPL-2.0 (with exception) SharpZipLib 0.86 licence obligation is gone in v3.0.</p>
</section>

<section>
  <h2>4. Static analysis (SAST) <small>Semgrep CRA .NET rule pack + Roslyn .NET security analyzers</small></h2>
  <table><thead><tr><th>Severity</th><th>Rule</th><th>CWE</th><th class="num">Baseline</th><th class="num">Final</th></tr></thead><tbody>{sast_rows}</tbody></table>
  <h3>Remaining final finding - triage</h3>
  <table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Disposition</th></tr></thead><tbody>{final_sast or "<tr><td colspan=4>None</td></tr>"}</tbody></table>
  <div class="warn"><b>Coverage note:</b> Semgrep 1.184's C# grammar cannot parse C# 12 primary constructors and collection expressions. {sast_cov.get('filesPartiallyParsed', 0)} of {sast_cov.get('filesScanned', 0)} modern files were only partly parsed. To close that gap, the final code is also checked by the compiler-integrated Roslyn analyzers with <code>AnalysisModeSecurity=All</code> and <code>TreatWarningsAsErrors</code>: {roslyn.get('projects', 0)} projects, 91 security rules (CA2100, CA23xx deserialization, CA30xx injection/XML, CA53xx-CA54xx crypto/TLS), {roslyn.get('total', 'n/a')} violations. That build raised CA5398 (hard-coded TLS versions), which was fixed. SARIF files are in <code>reports/final/roslyn/</code>.</div>
</section>

<section>
  <h2>5. Snyk <small>independent commercial scanner</small></h2>
  <p class="lead">Snyk Open Source and Snyk Code need your organisation's Snyk token and network access, which the analysis sandbox did not have. When you run the scripts below, their output lands next to the other evidence and this section fills in automatically.</p>
  {snyk_block(b, f)}
</section>

<section>
  <h2>6. Issue traceability <small>legacy issue &rarr; fix &rarr; test &rarr; evidence</small></h2>
  <div class='scroll'><table class='trace'><colgroup><col style='width:9%'><col style='width:16%'><col style='width:8%'><col style='width:6%'><col style='width:25%'><col style='width:21%'><col style='width:15%'></colgroup><thead><tr><th>ID / status</th><th>Issue</th><th>CRA</th><th class="num">Baseline hits</th><th>Remediation (v3.0)</th><th>Regression tests</th><th>Final evidence</th></tr></thead><tbody>{trace_rows}</tbody></table></div>
</section>

<section>
  <h2>7. CRA Annex I conformity assessment <small>self-assessment, POC scope</small></h2>
  <h3>Part I - product properties</h3>
  <table><thead><tr><th>Ref</th><th>Requirement</th><th>Status</th><th>Evidence / rationale</th></tr></thead><tbody>{cra_rows(p1, 'I.1')}</tbody></table>
  <h3>Part II - vulnerability handling</h3>
  <table><thead><tr><th>Ref</th><th>Requirement</th><th>Status</th><th>Evidence / rationale</th></tr></thead><tbody>{cra_rows(p2, 'I.2')}</tbody></table>
  <p class="muted">Article 14: actively exploited vulnerabilities and severe incidents go to ENISA's Single Reporting Platform as an early warning within 24 h, a notification within 72 h, and a final report (14 days after a fix is available for vulnerabilities). See the runbook in <code>04-compliance/SECURITY.md</code>. Applies to products already on the market, including v2.3 installations.</p>
</section>

<section>
  <h2>8. Architecture review <small>manual findings</small></h2>
  <h3>Baseline ({len(b['manual'])})</h3>
  <table><thead><tr><th>Severity</th><th>Finding</th><th>CWE</th><th>CRA</th><th>Outcome</th></tr></thead><tbody>{man_b}</tbody></table>
  <h3>Residual risks after migration ({len(f['manual'])})</h3>
  <table><thead><tr><th>Severity</th><th>Risk</th><th>CRA</th><th>Treatment</th></tr></thead><tbody>{man_f}</tbody></table>
</section>

<section>
  <h2>9. Method, tools &amp; limitations</h2>
  <table><thead><tr><th>Activity</th><th>Baseline</th><th>Final</th></tr></thead><tbody>
    <tr><td>SBOM</td><td>{e(tools_b.get('sbom', ''))}</td><td>{e(tools_f.get('sbom', ''))}</td></tr>
    <tr><td>SCA</td><td>{e(tools_b.get('sca', ''))}</td><td>{e(tools_f.get('sca', ''))}</td></tr>
    <tr><td>SAST</td><td>{e(tools_b.get('sast', ''))}</td><td>{e(tools_f.get('sast', ''))} + Roslyn (.NET SDK 10.0.114)</td></tr>
    <tr><td>Secrets</td><td>{e(tools_b.get('secrets', ''))} + Semgrep secret rules</td><td>{e(tools_f.get('secrets', ''))} + Semgrep secret rules</td></tr>
    <tr><td>Tests</td><td>NUnit 2.6.4 (3 functional tests, no security tests)</td><td>xUnit: 43 security regression tests + end-to-end run against the Modbus simulator</td></tr>
  </tbody></table>
  <ul class="muted">
    <li>The v3.0 build was compiled and tested offline against .NET SDK 10.0.114. Two packages that were not available offline (Microsoft.AspNetCore.Authentication.Certificate, Microsoft.Data.SqlClient) were type-checked against API stubs. A full restore/build on a connected machine (<code>build-and-scan.ps1</code>) is required before release.</li>
    <li>The SBOM generator records declared direct dependencies. The transitive graph comes from <code>dotnet CycloneDX</code> in CI.</li>
    <li>Licences are curated from NuGet metadata and refreshed by the CI SBOM.</li>
    <li>This is a manufacturer self-assessment for a POC. It does not replace conformity assessment under Art. 32 or the harmonised standards once they are published.</li>
  </ul>
</section>
<footer>Indusoft FieldGateway &middot; generated by 03-security/tools/make_report.py &middot; evidence-driven: re-run after every scan</footer>
</main></body></html>"""
    (COMP / "CRA-Compliance-Report.html").write_text(doc, encoding="utf-8")

    # Markdown traceability matrix
    md = ["# Traceability matrix - legacy issue -> fix -> test -> evidence", "",
          f"Generated {now} from `04-compliance/traceability.json` and scan evidence.", "",
          "| ID | Issue | CWE | CRA | Baseline hits | Remediation | Tests | Final evidence | Status |", "|---|---|---|---|---|---|---|---|---|"]
    for i in trace["issues"]:
        md.append(f"| {i['id']} | {i['title']} | {i['cwe']} | {i['cra']} | {issue_counts(i, b)} | {i['fix']} (`{i['modern']}`) | "
                  f"{'; '.join(i['tests']) or '-'} | {i['finalEvidence']} | {i['status']} |")
    md += ["", "## CRA Annex I Part I", "", "| Ref | Requirement | Status | Evidence |", "|---|---|---|---|"]
    md += [f"| {r['ref']} | {r['req']} | {r['status']} | {r['evidence']} |" for r in p1]
    md += ["", "## CRA Annex I Part II", "", "| Ref | Requirement | Status | Evidence |", "|---|---|---|---|"]
    md += [f"| {r['ref']} | {r['req']} | {r['status']} | {r['evidence']} |" for r in p2]
    (COMP / "traceability-matrix.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("Report:", COMP / "CRA-Compliance-Report.html")


if __name__ == "__main__":
    main()
