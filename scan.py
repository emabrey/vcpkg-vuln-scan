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
TOOL_VERSION = "0.2.0"
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


def build_sarif(findings: list[dict], manifest_uri: str) -> dict:
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

        results.append({
            "ruleId": cid,
            "level": severity_bucket(cvss_score(v), v),
            "message": {"text": f"{f['package']} {f['version'] or '(unknown version)'}: {summary or cid}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": manifest_uri},
                },
                "logicalLocations": [{"name": f["package"], "kind": "package"}],
            }],
            "partialFingerprints": {
                "packageAndCve": f"{f['package']}@{f['version']}:{cid}",
            },
        })

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

    for name in closure:
        version = port_version(vcpkg_root, name) if vcpkg_root.exists() else None

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
        f"{total_withdrawn} withdrawn "
        f"across {len(closure)} package(s)."
    )

    if args.json_out:
        args.json_out.write_text(json.dumps(grouped, indent=2), encoding="utf-8")
        print(f"Wrote {args.json_out}")

    if args.sarif_out:
        sarif = build_sarif(sarif_findings, manifest_uri="vcpkg.json")
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
