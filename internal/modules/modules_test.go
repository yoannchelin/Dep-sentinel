package modules

import "testing"

func TestDetectLicense(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"MIT License\nPermission is hereby granted", "MIT"},
		{"Apache License\nVersion 2.0", "Apache-2.0"},
		{"GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL-3.0"},
		{"GNU General Public License\nversion 3", "GPL-3.0"},
		{"GNU General Public License\nversion 2", "GPL-2.0"},
		{"BSD 3-Clause\nRedistributions of source code must retain\nnor the names", "BSD-3-Clause"},
		{"Mozilla Public License, version 2.0", "MPL-2.0"},
		{"this is some random text with no license", ""},
	}
	for _, tc := range cases {
		got := DetectLicense(tc.text)
		if got != tc.want {
			t.Errorf("DetectLicense(%q...) = %q, want %q", tc.text[:min(30, len(tc.text))], got, tc.want)
		}
	}
}

func TestPathEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"github.com/foo/bar", "github.com/foo/bar"},
		{"github.com/BurntSushi/toml", "github.com/!burnt!sushi/toml"},
	}
	for _, tc := range cases {
		got := pathEscape(tc.in)
		if got != tc.want {
			t.Errorf("pathEscape(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPathEscape_Capital(t *testing.T) {
	// Verify capital letters encode correctly per Go module proxy protocol.
	got := pathEscape("github.com/Azure/azure-sdk")
	want := "github.com/!azure/azure-sdk"
	if got != want {
		t.Errorf("pathEscape = %q, want %q", got, want)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
