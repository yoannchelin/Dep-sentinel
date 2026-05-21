package vulns

import "testing"

func TestSemverGTE(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v1.2.3", "v1.2.3", true},
		{"v1.2.4", "v1.2.3", true},
		{"v2.0.0", "v1.9.9", true},
		{"v1.2.2", "v1.2.3", false},
		{"v0.9.0", "v1.0.0", false},
		{"v5.11.0", "v5.11.0", true},
		{"v5.12.0", "v5.11.0", true},
		{"v5.10.0", "v5.11.0", false},
		// pseudo-version
		{"v0.0.0-20230101000000-abcdef", "v0.0.0", true},
	}
	for _, tc := range cases {
		got := semverGTE(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("semverGTE(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestIsAffected(t *testing.T) {
	ranges := []OSVRange{{
		Type: "SEMVER",
		Events: []OSVEvent{
			{Introduced: "0"},
			{Fixed: "v5.11.0"},
		},
	}}
	if isAffected(ranges, "v5.11.0") {
		t.Error("v5.11.0 should NOT be affected (>= fixed)")
	}
	if isAffected(ranges, "v5.12.0") {
		t.Error("v5.12.0 should NOT be affected (> fixed)")
	}
	if !isAffected(ranges, "v5.10.0") {
		t.Error("v5.10.0 should be affected (< fixed)")
	}
}

func TestLookupModule_VersionFilter(t *testing.T) {
	db := []OSVEntry{
		{
			ID:      "GO-2024-1",
			Summary: "old vuln fixed in v1.1.0",
			Affected: []OSVAffected{{
				Package: "github.com/foo/bar",
				Ranges: []OSVRange{{
					Type:   "SEMVER",
					Events: []OSVEvent{{Introduced: "0"}, {Fixed: "v1.1.0"}},
				}},
			}},
		},
		{
			ID:      "GO-2024-2",
			Summary: "newer vuln fixed in v2.0.0",
			Affected: []OSVAffected{{
				Package: "github.com/foo/bar",
				Ranges: []OSVRange{{
					Type:   "SEMVER",
					Events: []OSVEvent{{Introduced: "v1.5.0"}, {Fixed: "v2.0.0"}},
				}},
			}},
		},
	}

	// At v0.9.0: GO-2024-1 active (< v1.1.0), GO-2024-2 not yet introduced (< v1.5.0).
	results := LookupModule(db, "github.com/foo/bar", "v0.9.0")
	if len(results) != 1 || results[0].ID != "GO-2024-1" {
		t.Errorf("v0.9.0: expected [GO-2024-1], got %v", results)
	}

	// At v1.2.0: GO-2024-1 fixed (>= v1.1.0), GO-2024-2 not yet introduced (< v1.5.0).
	results = LookupModule(db, "github.com/foo/bar", "v1.2.0")
	if len(results) != 0 {
		t.Errorf("v1.2.0: expected no vulns, got %v", results)
	}

	// At v1.6.0: GO-2024-1 fixed, GO-2024-2 active (>= v1.5.0 and < v2.0.0).
	results = LookupModule(db, "github.com/foo/bar", "v1.6.0")
	if len(results) != 1 || results[0].ID != "GO-2024-2" {
		t.Errorf("v1.6.0: expected [GO-2024-2], got %v", results)
	}

	// At v2.0.0: both fixed.
	results = LookupModule(db, "github.com/foo/bar", "v2.0.0")
	if len(results) != 0 {
		t.Errorf("v2.0.0: expected no vulns, got %v", results)
	}
}
