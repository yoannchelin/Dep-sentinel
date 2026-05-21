package npm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Finding is a vulnerability from npm audit or OSV.
type Finding struct {
	PackageName string
	Severity    string
	CVSSScore   float64
	VulnID      string // CVE-*, GHSA-*, or "npm:<name>"
	Summary     string
	FixedIn     string
}

// AuditAvailable returns true if npm is on PATH.
func AuditAvailable() bool {
	_, err := exec.LookPath("npm")
	return err == nil
}

// RunAudit runs `npm audit --json` and returns findings.
// npm exits non-zero when vulnerabilities are found — the exit code is intentionally ignored.
func RunAudit(dir string) ([]Finding, error) {
	cmd := exec.Command("npm", "audit", "--json")
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()
	if out.Len() == 0 {
		return nil, fmt.Errorf("npm audit produced no output")
	}
	return parseAuditJSON(out.Bytes())
}

func parseAuditJSON(data []byte) ([]Finding, error) {
	var meta struct {
		AuditReportVersion int `json:"auditReportVersion"`
	}
	json.Unmarshal(data, &meta)
	if meta.AuditReportVersion >= 2 {
		return parseAuditV7(data)
	}
	return parseAuditV6(data)
}

// parseAuditV7 handles npm audit report v2 format (npm v7+).
func parseAuditV7(data []byte) ([]Finding, error) {
	var report struct {
		Vulnerabilities map[string]struct {
			Name         string            `json:"name"`
			Severity     string            `json:"severity"`
			Via          []json.RawMessage `json:"via"`
			FixAvailable json.RawMessage   `json:"fixAvailable"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	var out []Finding
	for _, vuln := range report.Vulnerabilities {
		id, summary, cvss := extractVia(vuln.Via)
		if id == "" {
			id = "npm:" + vuln.Name
		}
		out = append(out, Finding{
			PackageName: vuln.Name,
			Severity:    vuln.Severity,
			CVSSScore:   cvss,
			VulnID:      id,
			Summary:     summary,
			FixedIn:     extractFixVersion(vuln.FixAvailable),
		})
	}
	return out, nil
}

func extractVia(raws []json.RawMessage) (id, summary string, cvss float64) {
	for _, raw := range raws {
		var via struct {
			Title string `json:"title"`
			URL   string `json:"url"`
			CVSS  struct {
				Score float64 `json:"score"`
			} `json:"cvss"`
		}
		if err := json.Unmarshal(raw, &via); err != nil || via.Title == "" {
			continue // string entries are transitive dep references, not advisories
		}
		if summary == "" {
			summary = via.Title
		}
		if via.CVSS.Score > cvss {
			cvss = via.CVSS.Score
		}
		if id == "" {
			id = idFromURL(via.URL)
		}
	}
	return
}

func extractFixVersion(raw json.RawMessage) string {
	var fa struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &fa) == nil {
		return fa.Version
	}
	return ""
}

func idFromURL(url string) string {
	parts := strings.Split(url, "/")
	for _, p := range parts {
		if strings.HasPrefix(p, "CVE-") || strings.HasPrefix(p, "GHSA-") {
			return p
		}
	}
	return ""
}

// parseAuditV6 handles npm audit report v1 format (npm v6).
func parseAuditV6(data []byte) ([]Finding, error) {
	var report struct {
		Advisories map[string]struct {
			ModuleName      string   `json:"module_name"`
			Severity        string   `json:"severity"`
			CVEs            []string `json:"cves"`
			Overview        string   `json:"overview"`
			PatchedVersions string   `json:"patched_versions"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	var out []Finding
	for _, adv := range report.Advisories {
		id := "npm-advisory"
		if len(adv.CVEs) > 0 {
			id = adv.CVEs[0]
		}
		fixedIn := strings.TrimPrefix(strings.TrimSpace(adv.PatchedVersions), ">=")
		out = append(out, Finding{
			PackageName: adv.ModuleName,
			Severity:    adv.Severity,
			VulnID:      id,
			Summary:     adv.Overview,
			FixedIn:     strings.TrimSpace(fixedIn),
		})
	}
	return out, nil
}
