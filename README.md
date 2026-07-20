# vcpkg-vuln-scan

A small vulnerability scanner for projects that get their C/C++ dependencies
from vcpkg. Reads `vcpkg.json`, resolves versions from the port checkout,
queries OSV.dev, prints anything that looks bad.

## Why this exists

OSV-Scanner, Trivy, Grype and GitHub's own dependency graph all skip `vcpkg.json`
entirely, so if your project pulls in dependencies through vcpkg, none of the usual
OSS scanners will tell you when a CVE lands. This script addresses that gap by scanning
vcpkg and identifying CVEs.

## Usage

```
python scan.py <project-root>
```

`<project-root>` is a directory that has a `vcpkg.json` at its root. If it
also has a `vcpkg/` submodule (with `vcpkg/ports/<name>/vcpkg.json` files),
the scanner will use those to resolve versions and, with `--transitive`,
walk the port graph.

Common flags:

```
--transitive              Include transitive port dependencies.
--sarif out.sarif         Emit SARIF 2.1.0 for GitHub Code Scanning upload.
--json out.json           Emit machine-readable grouped results.
--suppressions file.json  Hide findings you've reviewed and accepted.
--no-cache                Skip the on-disk OSV response cache.
```

Exits 1 if there are any active (un-suppressed, non-withdrawn) findings, so
you can gate CI on it.

## Suppressions

CVE Ids you've triaged and don't want to see anymore go in a JSON file:

```json
{
  "suppressions": [
    { "id": "CVE-2013-0340", "reason": "XXE guarded by our own handler." }
  ]
}
```

Suppressed findings still print, tagged `SUPPRESSED` with the reason, but
don't count toward the exit code.

## Cache

OSV responses are cached under `~/.cache/vcpkg-vuln-scan/` keyed by
`(package, version)`. Default TTL is 24 hours. Cache lines show a `c` marker
in the per-package output so you know when the data came from disk vs. a
fresh request. Turn it off with `--no-cache` or move it with `--cache-dir`.

## GitHub Actions

This repo ships an `action.yml` so you can use it as a composite action:

```yaml
- uses: actions/checkout@v4
  with:
    submodules: true   # so scan can read vcpkg/ports/*/vcpkg.json for versions
- uses: emabrey/vcpkg-vuln-scan@v1
  id: scan
  with:
    project-root: .
    transitive: true
    suppressions: .github/vcpkg-suppressions.json
    sarif: vcpkg-vuln.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: vcpkg-vuln.sarif
    category: vcpkg-vuln-scan
```

Inputs (all optional):

```
project-root       Directory containing vcpkg.json (default: .)
transitive         Walk transitive port deps (default: false)
suppressions       Path to suppressions JSON (default: none)
sarif              Path to write SARIF 2.1.0 (default: none)
json               Path to write grouped JSON (default: none)
fail-on-findings   Fail the step on active findings (default: true)
python-version     Python to install (default: 3.11)
cache-ttl-hours    OSV cache TTL (default: 24)
```

Outputs:

```
active-count   Number of active findings from the run
sarif-path     The path passed to `sarif:`, echoed back for convenience
```

Findings land on the Code Scanning tab alongside CodeQL, with severity
inherited from the CVSS score when OSV gives us one.

If you'd rather run the script directly instead of through the action:

```yaml
- run: python path/to/scan.py . --sarif vcpkg-vuln.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vcpkg-vuln.sarif
    category: vcpkg-vuln-scan
```

## What it won't catch

- CVEs against packages that vcpkg patches. If the vcpkg port applies a
  patch that fixes the CVE, we don't know. We only see the version number.
- Vulnerabilities that were never assigned a CVE, or that OSV.dev hasn't
  indexed. If it isn't in OSV, this tool doesn't see it.
- Ecosystem-mismatch cases. OSV has no `vcpkg` ecosystem, so we query by
  bare package name. Sometimes the same name means different projects in
  different ecosystems (there's more than one "expat" out there). False
  positives happen; suppressions are the fix.

## Requires

Python 3.9 or newer.
