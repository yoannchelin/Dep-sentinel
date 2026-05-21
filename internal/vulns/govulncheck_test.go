package vulns

import "testing"

func TestParseGovulncheckJSON(t *testing.T) {
	// Minimal govulncheck -json output with one vulnerability.
	input := `
{"message":{"vulnerability":{"id":"GO-2024-1234","aliases":["CVE-2024-9999"],"details":"Remote code execution via crafted input.\nAttacker can run arbitrary code.","modules":[{"path":"github.com/vuln/pkg","found_version":"v1.0.0","fixed_version":"v1.0.1"}]}}}
{"message":{"config":{}}}
`
	findings, err := parseGovulncheckJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ModulePath != "github.com/vuln/pkg" {
		t.Errorf("ModulePath = %q", f.ModulePath)
	}
	if f.FixedIn != "v1.0.1" {
		t.Errorf("FixedIn = %q", f.FixedIn)
	}
	if f.VulnID != "GO-2024-1234" {
		t.Errorf("VulnID = %q", f.VulnID)
	}
}

func TestParseGovulncheckJSON_Dedup(t *testing.T) {
	// Same vuln appearing twice should be deduplicated.
	input := `
{"message":{"vulnerability":{"id":"GO-2024-1234","aliases":[],"details":"test","modules":[{"path":"github.com/x/y","found_version":"v1.0.0","fixed_version":"v1.0.1"}]}}}
{"message":{"vulnerability":{"id":"GO-2024-1234","aliases":[],"details":"test","modules":[{"path":"github.com/x/y","found_version":"v1.0.0","fixed_version":"v1.0.1"}]}}}
`
	findings, _ := parseGovulncheckJSON([]byte(input))
	if len(findings) != 1 {
		t.Errorf("dedup failed: got %d findings, want 1", len(findings))
	}
}

func TestBestCVEID(t *testing.T) {
	if got := BestCVEID("GO-2024-1", []string{"CVE-2024-999", "GHSA-xxxx"}); got != "CVE-2024-999" {
		t.Errorf("got %q, want CVE-2024-999", got)
	}
	if got := BestCVEID("GO-2024-2", []string{"GHSA-xxxx"}); got != "GO-2024-2 (GHSA-xxxx)" {
		t.Errorf("got %q", got)
	}
	if got := BestCVEID("GO-2024-3", nil); got != "GO-2024-3" {
		t.Errorf("got %q", got)
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("line one\nline two"); got != "line one" {
		t.Errorf("got %q", got)
	}
	if got := firstLine("single"); got != "single" {
		t.Errorf("got %q", got)
	}
}
