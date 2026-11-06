#!/usr/bin/env python3
"""
Runs the CRA security scan suite against one code baseline and writes all evidence
into 03-security/reports/<phase>/.

  python run_scans.py baseline ../../01-legacy  2.3.0
  python run_scans.py final    ../../02-modern  3.0.0

Prerequisites: python3, semgrep, detect-secrets, and a local copy of the GitHub
Advisory Database (git clone --depth 1 https://github.com/github/advisory-database).
Set ADVISORY_DB to its path (default: ../../.cache/advisory-database).

Optional: Snyk / dotnet results placed in reports/<phase>/snyk/ and
reports/<phase>/dotnet/ by run-snyk.ps1 / build-and-scan.ps1 are summarised too.
"""
import json
import os
import subprocess
import sys
import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEC = HERE.parent
SEV_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def run(cmd, **kw):
    print("  $", " ".join(str(c) for c in cmd))
    return subprocess.run(cmd, check=False, text=True, capture_output=True, **kw)


def tool_version(cmd):
    try:
        return subprocess.run(cmd, text=True, capture_output=True).stdout.strip().splitlines()[0]
    except Exception:
        return "n/a"


def sast(src: Path, out: Path):
    rules = HERE / "semgrep" / "cra-dotnet-rules.yml"
    repo = SEC.parent  # run from repo root with relative paths so evidence files carry no machine-specific paths
    base = ["semgrep", "--metrics=off", "--disable-version-check", "-q", "--config",
            os.path.relpath(rules, repo), os.path.relpath(src, repo)]
    run(base + ["--json", "-o", str(out / "sast-semgrep.json")], cwd=str(repo))
    run(base + ["--sarif", "-o", str(out / "sast-semgrep.sarif")], cwd=str(repo))
    data = json.loads((out / "sast-semgrep.json").read_text())
    findings = []
    for r in data["results"]:
        md = r["extra"].get("metadata", {})
        findings.append({
            "rule": r["check_id"][r["check_id"].find("cra.") + 4:],
            "severity": SEV_MAP.get(r["extra"]["severity"], "LOW"),
            "file": os.path.relpath(SEC.parent / r["path"], src).replace("\\", "/"),
            "line": r["start"]["line"],
            "cwe": md.get("cwe", ""), "cra": md.get("cra", ""), "category": md.get("category", ""),
            "message": r["extra"]["message"],
        })
    findings.sort(key=lambda f: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[f["severity"]], f["file"], f["line"]))
    lines = ["# SAST report (Semgrep, CRA .NET rule pack)", "",
             "Rules: `03-security/tools/semgrep/cra-dotnet-rules.yml`  |  Findings: {}".format(len(findings)), "",
             "| Severity | Rule | CWE | File:Line | Message |", "|---|---|---|---|---|"]
    for f in findings:
        lines.append("| {severity} | {rule} | {cwe} | `{file}:{line}` | {message} |".format(**f))
    if not findings:
        lines.append("| - | - | - | - | No findings |")
    (out / "sast-semgrep.md").write_text("\n".join(lines) + "\n")
    coverage = {"filesScanned": len(data.get("paths", {}).get("scanned", [])),
                "filesPartiallyParsed": len({e.get("path") for e in data.get("errors", []) if e.get("type", [""])[0] == "PartialParsing"})}
    return findings, data.get("errors", []), coverage


def secrets(src: Path, out: Path):
    r = run(["detect-secrets", "scan", "--all-files", "."], cwd=str(src))
    data = json.loads(r.stdout)
    findings = []
    for f, items in data.get("results", {}).items():
        for s in items:
            findings.append({"file": f.replace("\\", "/"), "line": s["line_number"], "type": s["type"],
                             "hashed_secret": s["hashed_secret"]})
    (out / "secrets-detect-secrets.json").write_text(json.dumps(data, indent=2))
    lines = ["# Secrets scan (detect-secrets, values redacted)", "", "Findings: {}".format(len(findings)), "",
             "| File:Line | Detector |", "|---|---|"]
    lines += ["| `{file}:{line}` | {type} |".format(**f) for f in findings] or ["| - | No secrets detected |"]
    (out / "secrets-detect-secrets.md").write_text("\n".join(lines) + "\n")
    return findings


def roslyn_summary(out: Path):
    """Summarise Roslyn analyzer SARIF logs (dotnet build -p:ErrorLog=...) placed in reports/<phase>/roslyn/."""
    d = out / "roslyn"
    if not d.exists():
        return None
    total, rules, files = 0, {}, 0
    for f in d.glob("*.sarif"):
        files += 1
        j = json.loads(f.read_text(encoding="utf-8-sig"))
        for run_ in j.get("runs", []):
            for r in run_.get("results", []):
                if r.get("level") in ("error", "warning"):
                    total += 1
                    rules[r.get("ruleId")] = rules.get(r.get("ruleId"), 0) + 1
    return {"projects": files, "total": total, "byRule": rules}


def snyk_summary(out: Path):
    """Summarise Snyk JSON written by run-snyk.ps1, if present."""
    res = {}
    d = out / "snyk"
    if not d.exists():
        return None
    for f in d.glob("*.json"):
        try:
            j = json.loads(f.read_text(encoding="utf-8-sig"))
        except Exception:
            continue
        counts = {}
        if isinstance(j, list):  # multi-project `snyk test --all-projects --json`
            vulns = [v for p in j for v in p.get("vulnerabilities", [])]
        elif "vulnerabilities" in j:
            vulns = j["vulnerabilities"]
        elif "runs" in j:  # snyk code SARIF
            vulns = [{"severity": {"error": "high", "warning": "medium", "note": "low"}.get(r.get("level"), "low")}
                     for run_ in j["runs"] for r in run_.get("results", [])]
        else:
            vulns = []
        for v in vulns:
            s = v.get("severity", "low").upper()
            counts[s] = counts.get(s, 0) + 1
        res[f.name] = {"total": len(vulns), "bySeverity": counts}
    return res or None


def main():
    phase, src, version = sys.argv[1], Path(sys.argv[2]).resolve(), sys.argv[3]
    db = Path(os.environ.get("ADVISORY_DB", SEC.parent / ".cache" / "advisory-database")).resolve()
    out = SEC / "reports" / phase
    out.mkdir(parents=True, exist_ok=True)
    print("[{}] scanning {}".format(phase, src))

    run([sys.executable, str(HERE / "sbom.py"), str(src), "Indusoft.FieldGateway", version, str(out / "sbom.cdx.json")])
    r = run([sys.executable, str(HERE / "sca.py"), str(out / "sbom.cdx.json"), str(db / "advisories" / "github-reviewed"), str(out / "sca")])
    print(r.stdout.strip(), r.stderr.strip()[-500:])
    sca = json.loads((out / "sca.json").read_text())
    sast_findings, sast_errors, sast_cov = sast(src, out)
    sec_findings = secrets(src, out)

    manual_file = SEC / "manual-review" / "{}.json".format(phase)
    manual = json.loads(manual_file.read_text()) if manual_file.exists() else []

    db_commit = run(["git", "-C", str(db), "rev-parse", "--short", "HEAD"]).stdout.strip() or "n/a"
    db_date = run(["git", "-C", str(db), "log", "-1", "--format=%cs"]).stdout.strip() or "n/a"

    def sev_counts(items, key="severity"):
        c = {}
        for i in items:
            c[i[key]] = c.get(i[key], 0) + 1
        return c

    summary = {
        "phase": phase, "product": "Indusoft.FieldGateway", "version": version,
        "source": os.path.relpath(src, SEC.parent).replace("\\", "/"),
        "scannedAt": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "tools": {
            "sbom": "indusoft sbom.py (CycloneDX 1.5)",
            "sca": "indusoft sca.py + GitHub Advisory Database @ {} ({})".format(db_commit, db_date),
            "sast": "semgrep " + tool_version(["semgrep", "--version"]) + " (CRA .NET rule pack)",
            "secrets": "detect-secrets " + tool_version(["detect-secrets", "--version"]),
        },
        "sbom": {"components": len(json.loads((out / "sbom.cdx.json").read_text())["components"])},
        "sca": {"total": sca["total"], "bySeverity": sca["summary"]},
        "sast": {"total": len(sast_findings), "bySeverity": sev_counts(sast_findings), "errors": len(sast_errors), **sast_cov},
        "roslyn": roslyn_summary(out),
        "secrets": {"total": len(sec_findings) + sum(1 for f in sast_findings if f["category"] == "secrets")},
        "manualReview": {"total": len(manual), "bySeverity": sev_counts(manual) if manual else {}},
        "snyk": snyk_summary(out),
        "dotnet": (json.loads((out / "dotnet" / "summary.json").read_text(encoding="utf-8-sig"))
                   if (out / "dotnet" / "summary.json").exists() else None),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("sca", "sast", "secrets", "manualReview")}, indent=1))


if __name__ == "__main__":
    main()
