#!/usr/bin/env python3
"""
Offline CycloneDX 1.5 SBOM generator for .NET solutions.

Reads dependency declarations directly from source:
  * packages.config                      (legacy .NET Framework projects)
  * *.csproj <PackageReference>          (SDK-style projects)
  * Directory.Packages.props <PackageVersion> (NuGet Central Package Management)
  * <TargetFramework(s)> / <TargetFrameworkVersion>  -> runtime "platform" component

Scope note: this lists DIRECT (declared) dependencies. For the full resolved
transitive graph run `dotnet CycloneDX` in CI (see build-and-scan.ps1); both
outputs use the same purl scheme so they can be diffed.

Usage: sbom.py <solution-root> <product-name> <product-version> <out.json>
"""
import json
import re
import sys
import uuid
import datetime
import xml.etree.ElementTree as ET
from pathlib import Path

# Licence identifiers as published in each package's NuGet metadata (nuspec <license>/<licenseUrl>).
# Curated offline; build-and-scan.ps1 regenerates them from nuget.org on a connected machine.
KNOWN_LICENSES = [  # (exact id or "prefix.", version prefix or None, licence) - first match wins
    ("log4net", None, "Apache-2.0"),
    ("newtonsoft.json", None, "MIT"),
    ("sharpziplib", "0.", "GPL-2.0-with-classpath-exception"),  # 0.8x shipped under GPL + linking exception
    ("sharpziplib", "1.", "MIT"),
    ("nunit", "2.", "LicenseRef-NUnit-2.6"),
    ("system.net.http", "4.", "LicenseRef-MS-NET-Library"),
    ("securitycodescan.vs2019", None, "LGPL-3.0-only"),
    ("coverlet.collector", None, "MIT"),
    ("xunit", None, "Apache-2.0"),
    ("xunit.", None, "Apache-2.0"),
    ("microsoft.", None, "MIT"),
    ("system.", None, "MIT"),
]

# Runtime support status (Microsoft lifecycle policy)
RUNTIME_LIFECYCLE = {
    "net40":   (".NET Framework", "4.0",   "2016-01-12"),
    "net45":   (".NET Framework", "4.5",   "2016-01-12"),
    "net451":  (".NET Framework", "4.5.1", "2016-01-12"),
    "net452":  (".NET Framework", "4.5.2", "2022-04-26"),
    "net48":   (".NET Framework", "4.8",   None),           # follows Windows lifecycle
    "net8.0":  (".NET", "8.0",  "2026-11-10"),
    "net10.0": (".NET", "10.0", "2028-11-14"),
    "aspnetcore": ("ASP.NET Core Runtime", "10.0", "2028-11-14"),
}


def license_for(pkg_id, version):
    pid = pkg_id.lower()
    for prefix, vprefix, lic in KNOWN_LICENSES:
        if pid == prefix or (prefix.endswith(".") and pid.startswith(prefix)):
            if vprefix is None or version.startswith(vprefix):
                return lic
    return "NOASSERTION"


def tfm_from_legacy(v):
    return "net" + v.lstrip("v").replace(".", "")


def strip_ns(root):
    for el in root.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def collect(root: Path):
    deps = {}        # (id_lower) -> dict
    runtimes = set()
    central = {}
    for props in root.rglob("Directory.Packages.props"):
        r = strip_ns(ET.parse(props).getroot())
        for pv in r.iter("PackageVersion"):
            central[pv.get("Include").lower()] = pv.get("Version")

    def add(pid, ver, project, scope):
        key = (pid.lower(), ver)
        d = deps.setdefault(key, {"id": pid, "version": ver, "projects": set(), "scope": scope})
        d["projects"].add(project)
        if scope == "required":
            d["scope"] = "required"

    for pc in root.rglob("packages.config"):
        project = pc.parent.name
        is_test = "test" in project.lower()
        r = ET.parse(pc).getroot()
        for p in r.iter("package"):
            add(p.get("id"), p.get("version"), project, "optional" if is_test or p.get("developmentDependency") == "true" else "required")

    for props in root.rglob("Directory.Build.props"):
        r = strip_ns(ET.parse(props).getroot())
        for tag in ("TargetFramework", "TargetFrameworks"):
            for t in r.iter(tag):
                for tf in (t.text or "").split(";"):
                    if tf.strip():
                        runtimes.add(re.sub(r"-windows.*$", "", tf.strip()))

    for proj in root.rglob("*.csproj"):
        project = proj.stem
        if "Microsoft.NET.Sdk.Web" in proj.read_text(encoding="utf-8", errors="ignore"):
            runtimes.add("aspnetcore")
        is_test = "test" in project.lower()
        r = strip_ns(ET.parse(proj).getroot())
        for t in r.iter("TargetFrameworkVersion"):
            runtimes.add(tfm_from_legacy(t.text.strip()))
        for tag in ("TargetFramework", "TargetFrameworks"):
            for t in r.iter(tag):
                for tf in t.text.split(";"):
                    if tf.strip():
                        runtimes.add(re.sub(r"-windows.*$", "", tf.strip()))
        for pr in r.iter("PackageReference"):
            pid = pr.get("Include")
            ver = pr.get("Version") or pr.findtext("Version") or central.get(pid.lower())
            if not ver:
                continue
            private = (pr.get("PrivateAssets") or pr.findtext("PrivateAssets") or "").lower() == "all"
            add(pid, ver, project, "optional" if (is_test or private) else "required")
    return deps, runtimes


def main():
    root, name, version, out = Path(sys.argv[1]), sys.argv[2], sys.argv[3], Path(sys.argv[4])
    deps, runtimes = collect(root)
    components = []
    for (_, ver), d in sorted(deps.items()):
        purl = "pkg:nuget/{}@{}".format(d["id"], ver)
        components.append({
            "type": "library",
            "bom-ref": purl,
            "name": d["id"],
            "version": ver,
            "scope": d["scope"],
            "purl": purl,
            "licenses": [{"license": {"id": lic}} if not lic.startswith(("LicenseRef", "NOASSERTION")) else {"license": {"name": lic}}
                         for lic in [license_for(d["id"], ver)]],
            "properties": [{"name": "indusoft:usedBy", "value": ", ".join(sorted(d["projects"]))}],
        })
    for tfm in sorted(runtimes):
        fam, ver, eol = RUNTIME_LIFECYCLE.get(tfm, (tfm, "", None))
        props = [{"name": "indusoft:tfm", "value": tfm}]
        if eol:
            props.append({"name": "indusoft:endOfSupport", "value": eol})
        components.append({
            "type": "platform", "bom-ref": "runtime:" + tfm, "name": fam, "version": ver,
            "scope": "required", "properties": props,
        })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "{}:{}".format(name, version))),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            "tools": {"components": [{"type": "application", "name": "indusoft-sbom.py", "version": "1.0.0"}]},
            "component": {"type": "application", "bom-ref": "app:" + name, "name": name, "version": version,
                          "supplier": {"name": "Indusoft Automation"}},
            "properties": [{"name": "indusoft:scope", "value": "direct dependencies (declared); transitive graph via dotnet-CycloneDX in CI"}],
        },
        "components": components,
        "dependencies": [{"ref": "app:" + name, "dependsOn": [c["bom-ref"] for c in components]}],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2))
    print("SBOM: {} components ({} libraries, {} runtimes) -> {}".format(
        len(components), len(deps), len(runtimes), out))


if __name__ == "__main__":
    main()
