package licenses

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct{ spdx, want string }{
		{"MIT", "ok"},
		{"Apache-2.0", "ok"},
		{"BSD-3-Clause", "ok"},
		{"ISC", "ok"},
		{"MPL-2.0", "ok"},
		{"AGPL-3.0", "problematic"},
		{"GPL-2.0", "problematic"},
		{"GPL-3.0", "problematic"},
		{"SSPL-1.0", "problematic"},
		{"Commons-Clause", "problematic"},
		{"", "unknown"},
		{"Proprietary", "unknown"},
	}
	for _, tc := range cases {
		got := Classify(tc.spdx)
		if got != tc.want {
			t.Errorf("Classify(%q) = %q, want %q", tc.spdx, got, tc.want)
		}
	}
}

func TestIsOK(t *testing.T) {
	if IsOK("MIT") != 1 {
		t.Error("MIT should be OK")
	}
	if IsOK("AGPL-3.0") != 0 {
		t.Error("AGPL-3.0 should not be OK")
	}
	if IsOK("") != 0 {
		t.Error("empty should not be OK")
	}
}
