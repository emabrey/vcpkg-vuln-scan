"""
Check a vcpkg-based project's dependencies against OSV.dev.

    python scan.py <project-root> [options]

Looks at <root>/vcpkg.json for the top-level deps and, if you point it at a
vcpkg checkout under <root>/vcpkg/, at each port's own vcpkg.json for the
resolved version.

See suppressions.example.json for the suppressions file format.

Standard library only, needs Python 3.9+. Exits 1 when there are active
findings so CI can gate on it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable


OSV_ENDPOINT = "https://api.osv.dev/v1/query"
TOOL_NAME = "vcpkg-vuln-scan"
TOOL_VERSION = "0.5.0"
TOOL_URI = "https://github.com/emabrey/vcpkg-vuln-scan"


def load_manifest(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for d in data.get("dependencies", []):
        if isinstance(d, str):
            names.append(d)
        elif isinstance(d, dict) and "name" in d:
            names.append(d["name"])
    return names


def locate_dep_line(manifest_text: str, name: str) -> int | None:
    """
    1-indexed line number where a dependency appears in vcpkg.json.
    Handles both bare "name" strings and {"name": "name", ...} object forms.
    Returns None if not found.
    """
    pat_object = re.compile(r'"name"\s*:\s*"' + re.escape(name) + r'"')
    pat_bare = re.compile(r'^\s*"' + re.escape(name) + r'"\s*,?\s*$')
    for i, line in enumerate(manifest_text.splitlines(), start=1):
        if pat_object.search(line) or pat_bare.match(line):
            return i
    return None


def locate_version_line(manifest_text: str) -> int | None:
    """1-indexed line of the first version-ish key in a port manifest."""
    pat = re.compile(r'"(?:version|version-semver|version-date|version-string)"\s*:')
    for i, line in enumerate(manifest_text.splitlines(), start=1):
        if pat.search(line):
            return i
    return None


def port_version(vcpkg_root: Path, name: str) -> str | None:
    m = vcpkg_root / "ports" / name / "vcpkg.json"
    if not m.exists():
        return None
    data = json.loads(m.read_text(encoding="utf-8"))
    for key in ("version", "version-semver", "version-date", "version-string"):
        if key in data:
            return str(data[key])
    return None


def port_deps(vcpkg_root: Path, name: str) -> list[str]:
    m = vcpkg_root / "ports" / name / "vcpkg.json"
    if not m.exists():
        return []
    data = json.loads(m.read_text(encoding="utf-8"))
    out: list[str] = []
    for d in data.get("dependencies", []):
        if isinstance(d, str):
            out.append(d)
        elif isinstance(d, dict) and "name" in d:
            # host-only deps are build tools, they don't end up linked
            if d.get("host"):
                continue
            out.append(d["name"])
    return out


def resolve_closure(vcpkg_root: Path, seeds: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    queue = list(seeds)
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        queue.extend(port_deps(vcpkg_root, name))
    return sorted(seen)


def load_suppressions(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    if not path.exists():
        print(f"warning: suppressions file {path} not found, ignoring", file=sys.stderr)
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for entry in data.get("suppressions", []):
        cid = entry.get("id")
        if cid:
            out[cid.upper()] = entry.get("reason", "")
    return out


class OSVCache:
    def __init__(self, cache_dir: Path | None, ttl_seconds: int) -> None:
        self.enabled = cache_dir is not None
        self.ttl = ttl_seconds
        if self.enabled:
            cache_dir.mkdir(parents=True, exist_ok=True)
            self.dir = cache_dir

    def _key_path(self, name: str, version: str | None) -> Path:
        h = hashlib.sha256(f"{name}\0{version or ''}".encode("utf-8")).hexdigest()[:16]
        return self.dir / f"{h}.json"

    def get(self, name: str, version: str | None) -> list[dict] | None:
        if not self.enabled:
            return None
        p = self._key_path(name, version)
        if not p.exists():
            return None
        if time.time() - p.stat().st_mtime > self.ttl:
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def put(self, name: str, version: str | None, vulns: list[dict]) -> None:
        if not self.enabled:
            return
        try:
            self._key_path(name, version).write_text(
                json.dumps(vulns), encoding="utf-8"
            )
        except OSError:
            # don't fail the run just because the cache write blew up
            pass


def normalize_version(v: str) -> str:
    # vcpkg tacks on a #N port-version bump and sometimes +/~ metadata; strip them.
    return re.split(r"[#+~]", v, maxsplit=1)[0].strip()


def osv_query(name: str, version: str | None, timeout: float = 30.0) -> list[dict]:
    body: dict = {"package": {"name": name}}
    if version:
        body["version"] = normalize_version(version)
    req = urllib.request.Request(
        OSV_ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  ! HTTP {e.code} querying {name}: {e.reason}", file=sys.stderr)
        return []
    except urllib.error.URLError as e:
        print(f"  ! network error querying {name}: {e.reason}", file=sys.stderr)
        return []
    return payload.get("vulns", []) or []


CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
GHSA_RE = re.compile(r"^GHSA-[\w-]+$", re.IGNORECASE)
# OSV mirrors CVEs under a bunch of distro/index prefixes. We collapse the
# obvious ones so DEBIAN-CVE-2018-25032 and UBUNTU-CVE-2018-25032 both fold
# onto CVE-2018-25032 instead of showing up as three separate findings.
DISTRO_PREFIX_RE = re.compile(
    r"^(?:DEBIAN|UBUNTU|ALPINE|BELL|SUSE|OPENSUSE|REDHAT|ROCKY|ALMA|FEDORA|ORACLE|MAGEIA|CGA|ECHO|DLA|DSA|USN)-",
    re.IGNORECASE,
)


def canonical_id(vuln: dict) -> str:
    ids = [vuln.get("id", "")] + list(vuln.get("aliases", []))
    for i in ids:
        if CVE_RE.match(i):
            return i.upper()
    for i in ids:
        stripped = DISTRO_PREFIX_RE.sub("", i, count=1)
        if CVE_RE.match(stripped):
            return stripped.upper()
    for i in ids:
        if GHSA_RE.match(i):
            return i.upper()
    return (vuln.get("id") or "?").upper()


def is_withdrawn(vuln: dict) -> bool:
    return "withdrawn" in vuln and vuln["withdrawn"]


# CPE target_sw values that identify a language runtime, not a native library.
# When every CPE on a vuln lands in this set, the record is about that
# language's package with a matching name (e.g. Ruby's zlib gem), not our
# C library.
LANGUAGE_TARGET_SW = {
    "ruby", "python", "node.js", "nodejs", "node_js",
    "php", "perl", "java", "dotnet", ".net",
    "rust", "go", "javascript", "typescript",
    "erlang", "elixir", "swift", "dart",
}

# OSV ecosystems that only host language-specific packages.
LANGUAGE_ECOSYSTEMS = {
    "RubyGems", "PyPI", "npm", "crates.io", "Go",
    "Packagist", "NuGet", "Maven", "Hex", "Pub",
    "SwiftURL", "Bitnami",
}


def is_language_specific(vuln: dict) -> bool:
    """
    True when every ecosystem hint on the vuln points at a language-runtime
    package rather than a native library. Prevents Ruby/Python/npm packages
    that happen to share a name with a C library (zlib, curl, libxml, ...)
    from showing up as findings against the C library.

    Only returns True when at least one signal was seen; a vuln with no
    ecosystem or CPE metadata is kept, since we can't rule it out.
    """
    saw_signal = False

    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package") or {}
        eco = pkg.get("ecosystem")
        if eco:
            saw_signal = True
            if eco not in LANGUAGE_ECOSYSTEMS:
                return False

        cpe_sources: list[dict] = []
        ds = aff.get("database_specific")
        if isinstance(ds, dict):
            cpe_sources.append(ds)
        for r in aff.get("ranges", []) or []:
            rds = r.get("database_specific")
            if isinstance(rds, dict):
                cpe_sources.append(rds)

        for src in cpe_sources:
            cpe = src.get("cpe")
            if not cpe:
                continue
            saw_signal = True
            parts = cpe.split(":")
            if len(parts) < 11:
                return False  # unparseable, err on keeping
            target_sw = parts[10].lower()
            if target_sw in ("*", "-", ""):
                return False  # unbounded, might apply to us
            if target_sw not in LANGUAGE_TARGET_SW:
                return False  # narrows to something else, don't presume

    return saw_signal


SEMVER_TUPLE_RE = re.compile(r"^(?:v)?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?")

# Markers that identify a Debian/Ubuntu package version (as opposed to plain
# upstream semver). When present, we do a bit of extra unwrapping to get at
# the upstream version number.
DEBIAN_MARKER_RE = re.compile(r"^\d+:|dfsg|deb\d|ubuntu|\+ds", re.IGNORECASE)


def parse_version_tuple(v: str) -> tuple[int, ...] | None:
    """
    Best-effort numeric tuple for version comparison. Handles plain semver
    ("1.3.2", "v2.4.0", "3.3.1.1") and the common Debian/Ubuntu variants
    ("1:1.2.12.dfsg-1", "1.2.11-1ubuntu2", "1.2.11+dfsg-1+deb10u2"). Returns
    None on RPM epoch strings, date-based versions, or anything we can't
    parse cleanly.
    """
    v = v.strip()
    if DEBIAN_MARKER_RE.search(v):
        # Debian-format: strip epoch, revision, and upstream metadata tags
        # to leave the upstream version behind.
        v = re.sub(r"^\d+:", "", v)                                              # epoch
        v = re.sub(r"-[^-]*$", "", v)                                            # Debian revision
        v = re.sub(r"[.+](?:dfsg|orig|ds|deb)\S*", "", v, flags=re.IGNORECASE)   # metadata suffixes
    v = normalize_version(v)
    m = SEMVER_TUPLE_RE.match(v)
    if not m:
        return None
    parts = tuple(int(g) for g in m.groups() if g is not None)
    return parts if parts else None


def likely_fixed(vuln: dict, current_version: str | None) -> bool:
    """
    True when at least one 'affected' entry says a fix landed at a version
    that's <= ours, and no 'introduced' event pushes past our version.
    Only returns True when we can confidently compare. When in doubt we
    keep the finding, so this errs toward false positives, not false negatives.
    """
    if not current_version:
        return False
    ours = parse_version_tuple(current_version)
    if ours is None:
        return False

    for aff in vuln.get("affected", []) or []:
        for r in aff.get("ranges", []) or []:
            introduced: tuple[int, ...] | None = None
            fixed: tuple[int, ...] | None = None
            for ev in r.get("events", []) or []:
                if "introduced" in ev and ev["introduced"] not in ("0", 0):
                    parsed = parse_version_tuple(str(ev["introduced"]))
                    if parsed is not None:
                        introduced = parsed
                if "fixed" in ev:
                    parsed = parse_version_tuple(str(ev["fixed"]))
                    if parsed is not None:
                        fixed = parsed
            if fixed is None:
                continue
            if introduced is not None and ours < introduced:
                continue  # we're before the vulnerable window
            if ours >= fixed:
                return True
    return False


def dedupe_vulns(vulns: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for v in vulns:
        cid = canonical_id(v)
        if cid not in out:
            out[cid] = v
    return out


def cvss_score(vuln: dict) -> float | None:
    for s in vuln.get("severity", []):
        if s.get("type") in ("CVSS_V4", "CVSS_V3"):
            sc = s.get("score", "")
            if re.match(r"^[\d.]+$", sc):
                try:
                    return float(sc)
                except ValueError:
                    pass
    ds = vuln.get("database_specific") or {}
    if isinstance(ds, dict):
        for k in ("cvss_score", "severity"):
            val = ds.get(k)
            if isinstance(val, (int, float)):
                return float(val)
            if isinstance(val, str) and re.match(r"^[\d.]+$", val):
                return float(val)
    return None


def cvss_vector(vuln: dict) -> str | None:
    for s in vuln.get("severity", []):
        if s.get("type") in ("CVSS_V4", "CVSS_V3") and s.get("score"):
            return str(s["score"])
    return None


def severity_bucket(score: float | None, vuln: dict) -> str:
    # Maps to SARIF's error/warning/note. Falls back to the qualitative
    # database specific severity when we don't have a numeric CVSS.
    if score is None:
        ds = vuln.get("database_specific") or {}
        sev = str(ds.get("severity", "")).lower() if isinstance(ds, dict) else ""
        if "critical" in sev or "high" in sev:
            return "error"
        if "medium" in sev or "moderate" in sev:
            return "warning"
        return "note"
    if score >= 7.0:
        return "error"
    if score >= 4.0:
        return "warning"
    return "note"


def _physical_location(uri: str, line: int | None) -> dict:
    loc = {"artifactLocation": {"uri": uri}}
    if line is not None:
        loc["region"] = {"startLine": line}
    return loc


def build_sarif(findings: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        v = f["vuln"]
        cid = f["canonical_id"]
        summary = v.get("summary") or (v.get("details", "").splitlines()[:1] or [""])[0]
        details = v.get("details") or summary
        help_uri = ""
        for ref in v.get("references", []):
            if ref.get("type") in ("ADVISORY", "REPORT", "WEB"):
                help_uri = ref.get("url", "")
                break

        if cid not in rules:
            rule = {
                "id": cid,
                "shortDescription": {"text": summary[:120] or cid},
                "fullDescription": {"text": (summary or cid)[:1000]},
                "help": {"text": details[:8000]},
            }
            if help_uri:
                rule["helpUri"] = help_uri
            vec = cvss_vector(v)
            if vec:
                rule["properties"] = {"security-severity": str(cvss_score(v) or "")}
            rules[cid] = rule

        # Prefer the top-level manifest line when the dep is direct; fall back
        # to the port manifest for transitive deps that only appear there.
        primary_uri = f.get("primary_uri")
        primary_line = f.get("primary_line")
        related: list[dict] = []
        port_uri = f.get("port_uri")
        port_line = f.get("port_line")
        if port_uri and port_uri != primary_uri:
            related.append({
                "physicalLocation": _physical_location(port_uri, port_line),
                "message": {"text": f"{f['package']} port manifest"},
            })

        result = {
            "ruleId": cid,
            "level": severity_bucket(cvss_score(v), v),
            "message": {"text": f"{f['package']} {f['version'] or '(unknown version)'}: {summary or cid}"},
            "locations": [{
                "physicalLocation": _physical_location(primary_uri or "vcpkg.json", primary_line),
                "logicalLocations": [{"name": f["package"], "kind": "package"}],
            }],
            "partialFingerprints": {
                "packageAndCve": f"{f['package']}@{f['version']}:{cid}",
            },
        }
        if related:
            result["relatedLocations"] = related
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": TOOL_URI,
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }


def format_finding(package: str, version: str | None, cid: str, vuln: dict, suppressed_reason: str | None) -> str:
    score = cvss_score(vuln)
    sev = f" [CVSS {score:.1f}]" if score is not None else ""
    summary = vuln.get("summary") or (vuln.get("details", "").splitlines()[:1] or [""])[0]
    tag = "SUPPRESSED " if suppressed_reason else ""
    line = f"    - {tag}{cid}{sev}: {summary}"
    if suppressed_reason:
        line += f"\n      reason: {suppressed_reason}"
    return line


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("root", type=Path, help="Path to project root containing vcpkg.json")
    ap.add_argument("--transitive", action="store_true")
    ap.add_argument("--json", dest="json_out", type=Path)
    ap.add_argument("--sarif", dest="sarif_out", type=Path)
    ap.add_argument("--suppressions", type=Path)
    ap.add_argument("--cache-dir", type=Path,
                    default=Path.home() / ".cache" / "vcpkg-vuln-scan")
    ap.add_argument("--cache-ttl", type=float, default=24.0, help="Cache validity in hours")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--delay", type=float, default=0.1)
    args = ap.parse_args()

    manifest_path = args.root / "vcpkg.json"
    vcpkg_root = args.root / "vcpkg"

    if not manifest_path.exists():
        print(f"error: {manifest_path} not found", file=sys.stderr)
        return 2
    if not vcpkg_root.exists():
        print(f"warning: no vcpkg checkout at {vcpkg_root}; versions and transitive walking off", file=sys.stderr)

    suppressions = load_suppressions(args.suppressions)
    cache = OSVCache(
        None if args.no_cache else args.cache_dir,
        int(args.cache_ttl * 3600),
    )

    top = load_manifest(manifest_path)
    manifest_text = manifest_path.read_text(encoding="utf-8")
    top_set = set(top)
    print(f"Top-level deps ({len(top)}): {', '.join(top)}\n")

    if args.transitive and vcpkg_root.exists():
        closure = resolve_closure(vcpkg_root, top)
        print(f"Transitive closure: {len(closure)} packages\n")
    else:
        closure = sorted(set(top))

    grouped: dict[str, dict] = {}
    sarif_findings: list[dict] = []
    total_active = 0
    total_suppressed = 0
    total_withdrawn = 0
    total_fixed = 0
    total_other_ecosystem = 0

    for name in closure:
        version = port_version(vcpkg_root, name) if vcpkg_root.exists() else None

        # Locations for SARIF: manifest line for direct deps, port manifest for the version.
        port_manifest_path = vcpkg_root / "ports" / name / "vcpkg.json"
        port_uri: str | None = None
        port_line: int | None = None
        if port_manifest_path.exists():
            port_uri = f"vcpkg/ports/{name}/vcpkg.json"
            try:
                port_line = locate_version_line(port_manifest_path.read_text(encoding="utf-8"))
            except OSError:
                port_line = None

        if name in top_set:
            primary_uri = "vcpkg.json"
            primary_line = locate_dep_line(manifest_text, name)
        elif port_uri:
            primary_uri = port_uri
            primary_line = port_line
        else:
            primary_uri = "vcpkg.json"
            primary_line = None

        cached = cache.get(name, version)
        if cached is not None:
            vulns_raw = cached
            cache_marker = "c"
        else:
            vulns_raw = osv_query(name, version)
            cache.put(name, version, vulns_raw)
            time.sleep(args.delay)
            cache_marker = " "

        unique = dedupe_vulns(vulns_raw)

        active: list[tuple[str, dict, str | None]] = []
        for cid, v in unique.items():
            if is_withdrawn(v):
                total_withdrawn += 1
                continue
            if is_language_specific(v):
                total_other_ecosystem += 1
                continue
            if likely_fixed(v, version):
                total_fixed += 1
                continue
            reason = suppressions.get(cid)
            if reason is not None:
                total_suppressed += 1
                active.append((cid, v, reason))
            else:
                total_active += 1
                active.append((cid, v, None))
                sarif_findings.append({
                    "package": name,
                    "version": version,
                    "canonical_id": cid,
                    "vuln": v,
                    "primary_uri": primary_uri,
                    "primary_line": primary_line,
                    "port_uri": port_uri,
                    "port_line": port_line,
                })

        active_count = sum(1 for _, _, r in active if r is None)
        suppressed_count = sum(1 for _, _, r in active if r)
        marker = "!" if active_count else " "
        print(f"{marker}{cache_marker} {name} {version or '(no version)'}: "
              f"{active_count} active, {suppressed_count} suppressed "
              f"(from {len(vulns_raw)} raw, {len(unique)} unique)")
        for cid, v, reason in active:
            print(format_finding(name, version, cid, v, reason))

        grouped[name] = {
            "version": version,
            "raw_count": len(vulns_raw),
            "unique_count": len(unique),
            "active": [
                {"id": cid, "reason": r} for cid, _, r in active if r is None
            ],
            "suppressed": [
                {"id": cid, "reason": r} for cid, _, r in active if r
            ],
        }

    print(
        f"\nSummary: {total_active} active, "
        f"{total_suppressed} suppressed, "
        f"{total_fixed} likely-fixed, "
        f"{total_other_ecosystem} other-ecosystem, "
        f"{total_withdrawn} withdrawn "
        f"across {len(closure)} package(s)."
    )

    if args.json_out:
        args.json_out.write_text(json.dumps(grouped, indent=2), encoding="utf-8")
        print(f"Wrote {args.json_out}")

    if args.sarif_out:
        sarif = build_sarif(sarif_findings)
        args.sarif_out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        print(f"Wrote {args.sarif_out}")

    return 1 if total_active else 0


if __name__ == "__main__":
    # Windows cmd defaults to cp1252 and mangles non-ASCII in CVE descriptions.
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    sys.exit(main())
