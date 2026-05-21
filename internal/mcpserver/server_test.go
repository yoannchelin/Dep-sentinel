package mcpserver

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/leazelaya/dep-sentinel/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	// Seed a module with a known-bad license.
	mid1, _ := s.UpsertModule(store.Module{
		Path: "github.com/bad/agpl", Version: "v1.0.0",
		License: "AGPL-3.0", LicenseOK: 0, Direct: 1,
	})
	// Seed a module with a vuln.
	mid2, _ := s.UpsertModule(store.Module{
		Path: "github.com/vuln/pkg", Version: "v1.0.0",
		LatestVersion: "v1.1.0", License: "MIT", LicenseOK: 1, Direct: 1,
	})
	// Seed an outdated but OK module.
	s.UpsertModule(store.Module{
		Path: "github.com/old/dep", Version: "v1.0.0",
		LatestVersion: "v2.0.0", License: "MIT", LicenseOK: 1, Direct: 0,
	})
	_ = mid1
	s.InsertVuln(store.Vuln{
		ModuleID: mid2, VulnID: "CVE-2024-9999", Severity: "high",
		CVSSScore: 8.5, Summary: "Remote code execution", FixedIn: "v1.1.0",
	})
	return New(s)
}

func roundtrip(t *testing.T, srv *Server, req map[string]any) map[string]json.RawMessage {
	t.Helper()
	reqBytes, _ := json.Marshal(req)
	in := bytes.NewReader(append(reqBytes, '\n'))
	var out bytes.Buffer
	srv.in = in
	srv.out = &out
	if err := srv.Run(); err != nil {
		t.Fatalf("server.Run: %v", err)
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("parse response %q: %v", out.String(), err)
	}
	return resp
}

func toolText(t *testing.T, resp map[string]json.RawMessage) string {
	t.Helper()
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp["result"], &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("empty content")
	}
	return result.Content[0].Text
}

func TestServer_Initialize(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{},
	})
	var result map[string]any
	json.Unmarshal(resp["result"], &result)
	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("protocolVersion = %v", result["protocolVersion"])
	}
}

func TestServer_ToolsList(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": map[string]any{},
	})
	var result struct {
		Tools []struct{ Name string `json:"name"` } `json:"tools"`
	}
	json.Unmarshal(resp["result"], &result)
	names := map[string]bool{}
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"vulnerability_report", "license_audit", "outdated_modules"} {
		if !names[want] {
			t.Errorf("tool %q missing from tools/list", want)
		}
	}
}

func TestServer_VulnerabilityReport(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "vulnerability_report",
			"arguments": map[string]any{"min_severity": "low"},
		},
	})
	text := toolText(t, resp)
	if !strings.Contains(text, "CVE-2024-9999") {
		t.Errorf("expected CVE-2024-9999 in output, got:\n%s", text)
	}
	if !strings.Contains(text, "github.com/vuln/pkg") {
		t.Errorf("expected module path in output, got:\n%s", text)
	}
	if !strings.Contains(text, "v1.1.0") {
		t.Errorf("expected fix version in output, got:\n%s", text)
	}
}

func TestServer_VulnerabilityReport_SeverityFilter(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "vulnerability_report",
			"arguments": map[string]any{"min_severity": "critical"},
		},
	})
	text := toolText(t, resp)
	// Only high severity vuln seeded — should return no findings at "critical" threshold.
	if strings.Contains(text, "CVE-2024-9999") {
		t.Errorf("high severity vuln should not appear at critical threshold")
	}
}

func TestServer_LicenseAudit(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "license_audit", "arguments": map[string]any{}},
	})
	text := toolText(t, resp)
	if !strings.Contains(text, "github.com/bad/agpl") {
		t.Errorf("expected AGPL module in license audit, got:\n%s", text)
	}
	if !strings.Contains(text, "AGPL-3.0") {
		t.Errorf("expected AGPL-3.0 license in output, got:\n%s", text)
	}
}

func TestServer_OutdatedModules(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "outdated_modules",
			"arguments": map[string]any{"major_only": false},
		},
	})
	text := toolText(t, resp)
	if !strings.Contains(text, "github.com/vuln/pkg") {
		t.Errorf("expected vuln/pkg in outdated output, got:\n%s", text)
	}
	if !strings.Contains(text, "github.com/old/dep") {
		t.Errorf("expected old/dep in outdated output, got:\n%s", text)
	}
}

func TestServer_OutdatedModules_MajorOnly(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "outdated_modules",
			"arguments": map[string]any{"major_only": true},
		},
	})
	text := toolText(t, resp)
	// old/dep: v1 → v2 (major bump), vuln/pkg: v1.0.0 → v1.1.0 (minor, skip).
	if !strings.Contains(text, "github.com/old/dep") {
		t.Errorf("expected old/dep (v1→v2) in major-only output, got:\n%s", text)
	}
	if strings.Contains(text, "github.com/vuln/pkg") {
		t.Errorf("vuln/pkg (minor bump) should not appear in major-only output, got:\n%s", text)
	}
}

func TestServer_UnknownMethod(t *testing.T) {
	srv := newTestServer(t)
	resp := roundtrip(t, srv, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "unknown/method", "params": map[string]any{},
	})
	if _, hasErr := resp["error"]; !hasErr {
		t.Errorf("expected error for unknown method, got: %v", resp)
	}
}
