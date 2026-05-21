# Dep Sentinel

Dep Sentinel audits Go dependencies locally, without paid APIs:
- **CVEs** via `govulncheck` (with OSV database fallback)
- **License compliance** — flags AGPL, GPL, SSPL, and similar
- **Outdated modules** — current vs latest, with major-bump priority

Agent #5 in the Git Archaeologist ecosystem. Fully standalone — runs on any Go project with a `go.mod`.

---

## Install

```bash
cd cmd/dep && go install .
cd ../dep-mcp && go install .
```

Install govulncheck for best results (falls back to OSV database otherwise):

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

---

## CLI

```bash
# Full scan (writes dep-sentinel.db in the project dir)
dep scan --dir /path/to/project

# Skip network calls (no latest-version checks)
dep scan --dir /path/to/project --no-network

# Query results from last scan
dep vulns     --dir /path/to/project --min-severity high
dep licenses  --dir /path/to/project
dep outdated  --dir /path/to/project --major-only
dep status    --dir /path/to/project
```

All commands accept `--db <path>` to use a custom SQLite database location.

---

## MCP server

```bash
dep-mcp --dir /path/to/project
```

Exposes three tools over JSON-RPC 2.0 stdio (MCP protocol):

| Tool | Input | Output |
|---|---|---|
| `vulnerability_report` | `min_severity?` (critical/high/medium/low) | CVEs grouped by module, with fix version |
| `license_audit` | — | Modules with problematic or unknown licenses |
| `outdated_modules` | `major_only?` | Modules with available updates |

---

## What it detects

### Vulnerabilities

Runs `govulncheck -json ./...` for precise results (only flags vulns reachable from your code).

Falls back to the OSV database (`https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip`) if govulncheck is not installed. The OSV zip is cached locally (default: 24h TTL) for offline use.

Severity is sourced from CVSS scores or OSV `database_specific.severity`. Entries are filtered by SEMVER range — a module is only flagged if the current version falls within an affected range (`current >= introduced AND current < fixed`).

### License compliance

Reads license files from the module cache (`$GOPATH/pkg/mod`). Identifies SPDX licenses by text matching.

| Status | Licenses |
|---|---|
| OK | MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, LGPL-2.1, LGPL-3.0, Unlicense, CC0-1.0 |
| Problematic | AGPL-3.0, GPL-2.0, GPL-3.0, SSPL-1.0, Commons-Clause |
| Unknown | License file not found or not recognized |

### Outdated modules

Queries `proxy.golang.org/{module}/@latest` concurrently (10 workers) to find the latest stable version for each dependency. Compares against the version in `go.mod`. The `--major-only` flag limits output to breaking-change upgrades (v1 → v2, etc.).

---

## SQLite schema

```sql
dep_modules         -- one row per dependency
dep_vulnerabilities -- CVE findings linked to modules
dep_meta            -- last_scan timestamp, scanned_dir
```

---

## Architecture

```
cmd/
  dep/        CLI: scan | vulns | licenses | outdated | status
  dep-mcp/    MCP stdio binary
internal/
  store/      SQLite layer — WAL mode, schema migration
  scanner/    Orchestrates all scan steps
  vulns/      govulncheck parser + OSV database loader
  modules/    go list, proxy.golang.org, license file detection
  licenses/   SPDX classification
  mcpserver/  Three MCP tools
```

Scan steps:
1. `go list -m -json all` — enumerate all modules
2. Concurrent `proxy.golang.org` calls — fetch latest versions (10 parallel)
3. Upsert modules with license detection from module cache
4. `govulncheck` (or OSV fallback) — find vulnerabilities
