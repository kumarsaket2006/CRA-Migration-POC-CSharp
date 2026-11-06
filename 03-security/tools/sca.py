#!/usr/bin/env python3
"""
Software Composition Analysis: matches SBOM components against the GitHub Advisory
Database (OSV format, github-reviewed advisories, ecosystem NuGet). This is the same
advisory source that NuGet Audit / `dotnet list package --vulnerable` uses.

Also flags runtime platforms that are past Microsoft end-of-support (CRA Annex I
Part I (2)(c): products must be supported with security updates).

Usage: sca.py <sbom.json> <advisory-db-root> <out-prefix>
Writes <out-prefix>.json, <out-prefix>.md and <out-prefix>.vex.cdx.json
"""
import json
import re
import sys
import datetime
from pathlib import Path

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def parse_ver(v):
    v = v.strip()
    main, _, pre = v.partition("-")
    main = main.split("+")[0]
    nums = [int(x) if x.isdigit() else 0 for x in main.split(".")]
    while len(nums) < 4:
        nums.append(0)
    # release sorts after any prerelease
    pre_key = (1,) if not pre else (0,) + tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.]", pre))
    return tuple(nums[:4]), pre_key


def in_range(version, events):
    """OSV ECOSYSTEM range semantics."""
    v = parse_ver(version)
    affected = False
    for e in events:
        if "introduced" in e:
            intro = e["introduced"]
            if intro == "0" or v >= parse_ver(intro):
                affected = True
        elif "fixed" in e:
            if v >= parse_ver(e["fixed"]):
                affected = False
        elif "last_affected" in e:
            if v > parse_ver(e["last_affected"]):
                affected = False
    return affected


def load_db(root: Path):
    index = {}
    for f in root.rglob("*.json"):
        try:
            adv = json.loads(f.read_text())
        except Exception:
            continue
        if adv.get("withdrawn"):
            continue
        for aff in adv.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") == "NuGet":
                index.setdefault(pkg["name"].lower(), []).append((adv, aff))
    return index


def fixed_versions(aff):
    out = []
    for r in aff.get("ranges", []):
        for e in r.get("events", []):
            if "fixed" in e:
                out.append(e["fixed"])
    return out


def main():
    sbom_path, db_root, prefix = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    sbom = json.loads(sbom_path.read_text())
    index = load_db(db_root)
    today = datetime.date.today()
    findings = []

    for c in sbom["components"]:
        if c["type"] == "platform":
            eol = next((p["value"] for p in c.get("properties", []) if p["name"] == "indusoft:endOfSupport"), None)
            if eol and datetime.date.fromisoformat(eol) < today:
                findings.append({
                    "id": "EOL-" + c["bom-ref"].split(":")[1].upper(),
                    "aliases": [], "component": "{} {}".format(c["name"], c["version"]), "purl": c["bom-ref"],
                    "severity": "HIGH", "cvss": None,
                    "summary": "Runtime past end of support since {} - no security updates".format(eol),
                    "fixedIn": [".NET 10 (LTS)"], "cwe": ["CWE-1104"], "url": "https://learn.microsoft.com/lifecycle/products/microsoft-net-framework",
                    "type": "eol-runtime",
                })
            continue
        for adv, aff in index.get(c["name"].lower(), []):
            hit = c["version"] in aff.get("versions", []) or any(
                in_range(c["version"], r.get("events", [])) for r in aff.get("ranges", []) if r.get("type") in ("ECOSYSTEM", "SEMVER"))
            if not hit:
                continue
            sev = (adv.get("database_specific", {}).get("severity") or "UNKNOWN").upper()
            cvss = next((s["score"] for s in adv.get("severity", []) if s.get("type", "").startswith("CVSS")), None)
            findings.append({
                "id": adv["id"],
                "aliases": [a for a in adv.get("aliases", []) if a.startswith("CVE")],
                "component": "{} {}".format(c["name"], c["version"]), "purl": c["purl"],
                "severity": sev, "cvss": cvss,
                "summary": adv.get("summary", "").strip(),
                "fixedIn": fixed_versions(aff),
                "cwe": adv.get("database_specific", {}).get("cwe_ids", []),
                "url": "https://github.com/advisories/" + adv["id"],
                "published": adv.get("published", "")[:10],
                "type": "vulnerable-dependency",
            })

    findings.sort(key=lambda f: (-SEV_ORDER.get(f["severity"], 0), f["component"], f["id"]))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    result = {
        "tool": "indusoft-sca.py (GitHub Advisory Database, github-reviewed, NuGet)",
        "advisoryDbPackages": len(index),
        "scannedAt": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "sbom": sbom_path.name,
        "componentsScanned": len(sbom["components"]),
        "summary": counts, "total": len(findings), "findings": findings,
    }
    Path(prefix + ".json").write_text(json.dumps(result, indent=2))

    # Markdown
    lines = ["# SCA report - {}".format(sbom["metadata"]["component"]["name"] + " " + sbom["metadata"]["component"]["version"]), "",
             "- Source: GitHub Advisory Database (github-reviewed, NuGet ecosystem, {} packages indexed)".format(len(index)),
             "- Scanned: {}  |  Components: {}  |  Findings: {}".format(result["scannedAt"], result["componentsScanned"], len(findings)),
             "- By severity: " + (", ".join("{} {}".format(k, v) for k, v in sorted(counts.items(), key=lambda kv: -SEV_ORDER.get(kv[0], 0))) or "none"), "",
             "| Severity | Advisory | CVE | Component | Fixed in | Summary |", "|---|---|---|---|---|---|"]
    for f in findings:
        lines.append("| {} | [{}]({}) | {} | {} | {} | {} |".format(
            f["severity"], f["id"], f["url"], ", ".join(f["aliases"]) or "-", f["component"],
            ", ".join(f["fixedIn"]) or "no fix", f["summary"].replace("|", "/")))
    if not findings:
        lines.append("| - | - | - | - | - | No known vulnerabilities |")
    Path(prefix + ".md").write_text("\n".join(lines) + "\n")

    # CycloneDX VEX (vulnerabilities linked to SBOM bom-refs)
    vex = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"timestamp": result["scannedAt"], "component": sbom["metadata"]["component"]},
        "vulnerabilities": [{
            "id": f["aliases"][0] if f["aliases"] else f["id"],
            "source": {"name": "GitHub Advisory Database" if f["type"] != "eol-runtime" else "Microsoft Lifecycle", "url": f["url"]},
            "references": [{"id": f["id"], "source": {"name": "GHSA", "url": f["url"]}}] if f["id"].startswith("GHSA") else [],
            "ratings": [{"severity": f["severity"].lower().replace("moderate", "medium"), **({"vector": f["cvss"]} if f["cvss"] else {})}],
            "cwes": [int(c.split("-")[1]) for c in f["cwe"] if c.startswith("CWE-")],
            "description": f["summary"],
            "recommendation": "Upgrade to " + (", ".join(f["fixedIn"]) or "a supported alternative"),
            "analysis": {"state": "exploitable" if f["type"] == "eol-runtime" else "in_triage"},
            "affects": [{"ref": f["purl"]}],
        } for f in findings],
    }
    Path(prefix + ".vex.cdx.json").write_text(json.dumps(vex, indent=2))
    print("SCA: {} findings {} -> {}.json".format(len(findings), counts, prefix))


if __name__ == "__main__":
    main()
