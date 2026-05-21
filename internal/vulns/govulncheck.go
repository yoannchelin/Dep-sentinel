package vulns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// GovulncheckAvailable returns true if govulncheck is on PATH.
func GovulncheckAvailable() bool {
	_, err := exec.LookPath("govulncheck")
	return err == nil
}

// Finding is a single vulnerability result.
type Finding struct {
	ModulePath string
	VulnID     string // e.g. GO-2024-1234
	Aliases    []string
	Severity   string
	CVSSScore  float64
	Summary    string
	FixedIn    string
}

// RunGovulncheck runs `govulncheck -json ./...` in dir and returns findings.
func RunGovulncheck(dir string) ([]Finding, error) {
	cmd := exec.Command("govulncheck", "-json", "./...")
	cmd.Dir = dir
	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	// govulncheck exits non-zero when vulnerabilities are found — that's OK.
	_ = cmd.Run()

	return parseGovulncheckJSON(out.Bytes())
}

// govulncheck -json emits a stream of typed JSON objects.
type gvcMessage struct {
	Message struct {
		Vulnerability *gvcVuln `json:"vulnerability"`
	} `json:"message"`
}

type gvcVuln struct {
	ID      string     `json:"id"`
	Aliases []string   `json:"aliases"`
	Details string     `json:"details"`
	Modules []gvcModule `json:"modules"`
}

type gvcModule struct {
	Path         string `json:"path"`
	FoundVersion string `json:"found_version"`
	FixedVersion string `json:"fixed_version"`
}

func parseGovulncheckJSON(data []byte) ([]Finding, error) {
	var findings []Finding
	seen := map[string]bool{}

	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var msg gvcMessage
		if err := dec.Decode(&msg); err != nil {
			continue
		}
		v := msg.Message.Vulnerability
		if v == nil {
			continue
		}
		for _, mod := range v.Modules {
			key := v.ID + "|" + mod.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			f := Finding{
				ModulePath: mod.Path,
				VulnID:     v.ID,
				Aliases:    v.Aliases,
				Summary:    firstLine(v.Details),
				FixedIn:    mod.FixedVersion,
				Severity:   severityFromID(v.ID, v.Aliases),
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// severityFromID maps a Go vuln ID or CVE alias to a severity string.
// govulncheck JSON doesn't include CVSS scores — we use OSV for that.
func severityFromID(id string, aliases []string) string {
	// Look for a GHSA alias which sometimes encodes severity.
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return "high" // conservative default for known CVEs
		}
	}
	_ = id
	return "medium"
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// BestCVEID returns the most recognisable ID from a vuln (CVE > GHSA > GO-*).
func BestCVEID(vulnID string, aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "GHSA-") {
			return fmt.Sprintf("%s (%s)", vulnID, a)
		}
	}
	return vulnID
}
