package store

import "strings"

// Module represents a dependency (Go module or npm package).
type Module struct {
	ID            int64
	Path          string
	Version       string
	LatestVersion string
	License       string
	LicenseOK     int    // 1 = OK, 0 = problematic or unknown
	LastCommitTS  int64
	IsAbandoned   int
	Direct        int    // 1 = direct dependency, 0 = transitive
	Ecosystem     string // "go" or "npm"
}

// Vuln is a vulnerability to insert.
type Vuln struct {
	ModuleID  int64
	VulnID    string
	Severity  string
	CVSSScore float64
	Summary   string
	FixedIn   string
	BlastRisk float64
}

// VulnRow is a vulnerability row joined with module info.
type VulnRow struct {
	VulnID        string
	Severity      string
	CVSSScore     float64
	Summary       string
	FixedIn       string
	BlastRisk     float64
	ModulePath    string
	ModuleVersion string
	LatestVersion string
}

// isMajorBump returns true if latest has a higher major version than current.
func isMajorBump(current, latest string) bool {
	cm := majorOf(current)
	lm := majorOf(latest)
	return lm > cm
}

func majorOf(ver string) int {
	ver = strings.TrimPrefix(ver, "v")
	dot := strings.Index(ver, ".")
	if dot < 0 {
		return parseDigit(ver)
	}
	return parseDigit(ver[:dot])
}

func parseDigit(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
