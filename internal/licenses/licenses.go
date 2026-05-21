package licenses

// OK contains SPDX identifiers considered safe for most use cases.
var OK = map[string]bool{
	"MIT":          true,
	"Apache-2.0":   true,
	"BSD-2-Clause": true,
	"BSD-3-Clause": true,
	"ISC":          true,
	"MPL-2.0":      true,
	"Unlicense":    true,
	"CC0-1.0":      true,
	"LGPL-2.1":     true,
	"LGPL-3.0":     true,
}

// Problematic contains SPDX identifiers that require legal review.
var Problematic = map[string]bool{
	"AGPL-3.0":       true, // SaaS loophole: must open-source server code
	"GPL-2.0":        true, // copyleft — contaminates the whole binary
	"GPL-3.0":        true,
	"SSPL-1.0":       true, // MongoDB licence — very broad copyleft
	"Commons-Clause": true, // restricts commercial use
}

// Classify returns "ok", "problematic", or "unknown".
func Classify(spdxID string) string {
	if spdxID == "" {
		return "unknown"
	}
	if OK[spdxID] {
		return "ok"
	}
	if Problematic[spdxID] {
		return "problematic"
	}
	return "unknown"
}

// IsOK returns 1 if the license is in the OK set, 0 otherwise.
func IsOK(spdxID string) int {
	if Classify(spdxID) == "ok" {
		return 1
	}
	return 0
}
