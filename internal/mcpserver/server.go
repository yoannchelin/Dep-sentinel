package mcpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/leazelaya/dep-sentinel/internal/store"
)

// Server implements the MCP stdio protocol for Dep Sentinel.
type Server struct {
	store *store.Store
	in    io.Reader
	out   io.Writer
}

func New(s *store.Store) *Server {
	return &Server{store: s, in: os.Stdin, out: os.Stdout}
}

func (srv *Server) Run() error {
	dec := json.NewDecoder(srv.in)
	for {
		var req map[string]json.RawMessage
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("decode: %w", err)
		}
		resp := srv.handle(req)
		if err := json.NewEncoder(srv.out).Encode(resp); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
	}
}

func (srv *Server) handle(req map[string]json.RawMessage) map[string]any {
	id := req["id"]
	var method string
	_ = json.Unmarshal(req["method"], &method)

	switch method {
	case "initialize":
		return result(id, map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]any{"name": "dep-sentinel", "version": "0.1.0"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		})
	case "tools/list":
		return result(id, map[string]any{"tools": toolList()})
	case "tools/call":
		var p struct {
			Name      string                     `json:"name"`
			Arguments map[string]json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(req["params"], &p)
		text, err := srv.callTool(p.Name, p.Arguments)
		if err != nil {
			return rpcError(id, -32603, err.Error())
		}
		return result(id, map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
		})
	default:
		return rpcError(id, -32601, "method not found: "+method)
	}
}

func (srv *Server) callTool(name string, args map[string]json.RawMessage) (string, error) {
	switch name {
	case "vulnerability_report":
		return srv.toolVulnReport(args)
	case "license_audit":
		return srv.toolLicenseAudit(args)
	case "outdated_modules":
		return srv.toolOutdated(args)
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

// ---- tool: vulnerability_report ----

func (srv *Server) toolVulnReport(args map[string]json.RawMessage) (string, error) {
	minSev := stringArg(args, "min_severity", "low")

	vulns, err := srv.store.QueryVulns(minSev)
	if err != nil {
		return "", err
	}
	if len(vulns) == 0 {
		return "## Vulnerability Report\n\nNo vulnerabilities found.", nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Vulnerability Report (%d findings)\n\n", len(vulns))

	// Group by module.
	type group struct {
		module  string
		version string
		latest  string
		items   []store.VulnRow
	}
	order := []string{}
	groups := map[string]*group{}
	for _, v := range vulns {
		if _, ok := groups[v.ModulePath]; !ok {
			order = append(order, v.ModulePath)
			groups[v.ModulePath] = &group{module: v.ModulePath, version: v.ModuleVersion, latest: v.LatestVersion}
		}
		groups[v.ModulePath].items = append(groups[v.ModulePath].items, v)
	}

	for _, path := range order {
		g := groups[path]
		updateHint := ""
		if g.latest != "" && g.latest != g.version {
			updateHint = fmt.Sprintf(" → update to %s", g.latest)
		}
		fmt.Fprintf(&sb, "### %s %s%s\n", g.module, g.version, updateHint)
		for _, v := range g.items {
			cvssStr := ""
			if v.CVSSScore > 0 {
				cvssStr = fmt.Sprintf(" CVSS=%.1f", v.CVSSScore)
			}
			fixStr := ""
			if v.FixedIn != "" {
				fixStr = fmt.Sprintf(" (fixed in %s)", v.FixedIn)
			}
			blastStr := ""
			if v.BlastRisk > 0 {
				blastStr = fmt.Sprintf(" blast_risk=%.1f", v.BlastRisk)
			}
			fmt.Fprintf(&sb, "- [%s%s] %s%s%s — %s\n", v.Severity, cvssStr, v.VulnID, fixStr, blastStr, v.Summary)
		}
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// ---- tool: license_audit ----

func (srv *Server) toolLicenseAudit(_ map[string]json.RawMessage) (string, error) {
	mods, err := srv.store.QueryBadLicenses()
	if err != nil {
		return "", err
	}
	if len(mods) == 0 {
		return "## License Audit\n\nAll module licenses are acceptable.", nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## License Audit (%d modules need review)\n\n", len(mods))

	var problematic, unknown []store.Module
	for _, m := range mods {
		if m.License == "" {
			unknown = append(unknown, m)
		} else {
			problematic = append(problematic, m)
		}
	}

	if len(problematic) > 0 {
		sb.WriteString("### Problematic licenses\n\n")
		for _, m := range problematic {
			direct := "transitive"
			if m.Direct == 1 {
				direct = "direct"
			}
			fmt.Fprintf(&sb, "- **%s** (%s) `%s` — %s\n", m.Path, m.Version, m.License, direct)
		}
		sb.WriteByte('\n')
	}

	if len(unknown) > 0 {
		sb.WriteString("### Unknown licenses\n\n")
		for _, m := range unknown {
			direct := "transitive"
			if m.Direct == 1 {
				direct = "direct"
			}
			fmt.Fprintf(&sb, "- %s (%s) — %s\n", m.Path, m.Version, direct)
		}
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// ---- tool: outdated_modules ----

func (srv *Server) toolOutdated(args map[string]json.RawMessage) (string, error) {
	majorOnly := boolArg(args, "major_only", false)

	mods, err := srv.store.QueryOutdated(majorOnly)
	if err != nil {
		return "", err
	}

	title := "Outdated Modules"
	if majorOnly {
		title = "Outdated Modules (major updates only)"
	}

	if len(mods) == 0 {
		return fmt.Sprintf("## %s\n\nAll modules are up to date.", title), nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## %s (%d modules)\n\n", title, len(mods))
	for _, m := range mods {
		direct := ""
		if m.Direct == 1 {
			direct = " *(direct)*"
		}
		fmt.Fprintf(&sb, "- **%s**%s: %s → %s\n", m.Path, direct, m.Version, m.LatestVersion)
	}
	return sb.String(), nil
}

// ---- tool list ----

func toolList() []map[string]any {
	return []map[string]any{
		{
			"name":        "vulnerability_report",
			"description": "CVEs and security vulnerabilities in Go and npm dependencies, grouped by package with fix versions",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"min_severity": map[string]any{
						"type":        "string",
						"description": "Minimum severity to include: critical, high, medium (default), low",
					},
				},
			},
		},
		{
			"name":        "license_audit",
			"description": "Go modules and npm packages with problematic (AGPL, GPL, SSPL) or unknown licenses that require legal review",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "outdated_modules",
			"description": "Go modules and npm packages where a newer version is available",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"major_only": map[string]any{
						"type":        "boolean",
						"description": "Only show modules with a major version bump available (default false)",
					},
				},
			},
		},
	}
}

// ---- helpers ----

func result(id json.RawMessage, v any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": v}
}

func rpcError(id json.RawMessage, code int, msg string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}}
}

func stringArg(args map[string]json.RawMessage, key, def string) string {
	if raw, ok := args[key]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
	}
	return def
}

func boolArg(args map[string]json.RawMessage, key string, def bool) bool {
	if raw, ok := args[key]; ok {
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			return b
		}
	}
	return def
}
