package vulns

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const osvURL = "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip"

// OSVEntry is a minimal parsed OSV vulnerability record.
type OSVEntry struct {
	ID       string
	Aliases  []string
	Summary  string
	Severity string
	CVSS     float64
	Affected []OSVAffected
}

type OSVAffected struct {
	Package  string
	Ranges   []OSVRange
}

type OSVRange struct {
	Type   string
	Events []OSVEvent
}

type OSVEvent struct {
	Introduced string
	Fixed      string
}

// LoadOSVDB loads the OSV Go database. If cachePath exists and is recent enough
// (within maxAge), it reads from cache; otherwise downloads and caches.
func LoadOSVDB(cachePath string, maxAge time.Duration) ([]OSVEntry, error) {
	var zipData []byte

	info, err := os.Stat(cachePath)
	if err == nil && time.Since(info.ModTime()) < maxAge {
		zipData, err = os.ReadFile(cachePath)
		if err != nil {
			return nil, fmt.Errorf("read osv cache: %w", err)
		}
	} else {
		zipData, err = downloadOSV()
		if err != nil {
			// If we have a stale cache, use it rather than failing.
			if _, serr := os.Stat(cachePath); serr == nil {
				zipData, _ = os.ReadFile(cachePath)
			}
			if zipData == nil {
				return nil, fmt.Errorf("download osv: %w", err)
			}
		} else {
			_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)
			_ = os.WriteFile(cachePath, zipData, 0o644)
		}
	}

	return parseOSVZip(zipData)
}

func downloadOSV() ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(osvURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func parseOSVZip(data []byte) ([]OSVEntry, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open osv zip: %w", err)
	}

	var out []OSVEntry
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		entry, err := parseOSVRecord(raw)
		if err != nil {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

type osvRaw struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
	Details string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func parseOSVRecord(data []byte) (OSVEntry, error) {
	var raw osvRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return OSVEntry{}, err
	}

	summary := raw.Summary
	if summary == "" {
		summary = firstLine(raw.Details)
	}

	sev, cvss := extractSeverity(raw)

	var affected []OSVAffected
	for _, a := range raw.Affected {
		af := OSVAffected{Package: a.Package.Name}
		for _, rng := range a.Ranges {
			r := OSVRange{Type: rng.Type}
			for _, ev := range rng.Events {
				r.Events = append(r.Events, OSVEvent{
					Introduced: ev.Introduced,
					Fixed:      ev.Fixed,
				})
			}
			af.Ranges = append(af.Ranges, r)
		}
		affected = append(affected, af)
	}

	return OSVEntry{
		ID:       raw.ID,
		Aliases:  raw.Aliases,
		Summary:  summary,
		Severity: sev,
		CVSS:     cvss,
		Affected: affected,
	}, nil
}

func extractSeverity(raw osvRaw) (string, float64) {
	// Try database_specific.severity first (most explicit).
	if raw.DatabaseSpecific.Severity != "" {
		return strings.ToLower(raw.DatabaseSpecific.Severity), 0
	}
	// Try CVSS scores.
	for _, s := range raw.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V4" {
			score := parseCVSSScore(s.Score)
			return cvssToSeverity(score), score
		}
	}
	for _, a := range raw.Affected {
		for _, s := range a.Severity {
			score := parseCVSSScore(s.Score)
			if score > 0 {
				return cvssToSeverity(score), score
			}
		}
	}
	return "medium", 0
}

func parseCVSSScore(vector string) float64 {
	// CVSS vectors end with "/score" or we look for the base score prefix.
	// Simple approach: look for a numeric pattern at the end.
	parts := strings.Split(vector, "/")
	if len(parts) == 0 {
		return 0
	}
	// Last part of a CVSS v3 vector is not the score — the score is separate.
	// govulncheck provides the score directly as a numeric string sometimes.
	var f float64
	fmt.Sscanf(parts[len(parts)-1], "%f", &f)
	if f > 10 {
		return 0
	}
	return f
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// LookupModule finds OSV entries affecting a given module path.
func LookupModule(db []OSVEntry, modulePath string) []OSVEntry {
	var out []OSVEntry
	for _, e := range db {
		for _, a := range e.Affected {
			if a.Package == modulePath || strings.HasPrefix(modulePath, a.Package) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// FixedVersion returns the first "fixed" version from an OSV entry for a module.
func FixedVersion(entry OSVEntry, modulePath string) string {
	for _, a := range entry.Affected {
		if a.Package != modulePath {
			continue
		}
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}
