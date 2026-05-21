package npm

import "testing"

func TestStripRange(t *testing.T) {
	cases := []struct{ in, want string }{
		{"^4.17.21", "4.17.21"},
		{"~1.2.3", "1.2.3"},
		{">=1.0.0 <2.0.0", "1.0.0"},
		{"1.0.0", "1.0.0"},
		{"  ^0.5.0", "0.5.0"},
	}
	for _, tc := range cases {
		got := StripRange(tc.in)
		if got != tc.want {
			t.Errorf("StripRange(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExtractName(t *testing.T) {
	cases := []struct{ key, want string }{
		{"node_modules/lodash", "lodash"},
		{"node_modules/@types/node", "@types/node"},
		{"node_modules/foo/node_modules/bar", "bar"},
	}
	for _, tc := range cases {
		got := extractName(tc.key)
		if got != tc.want {
			t.Errorf("extractName(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestParseLockfileV2(t *testing.T) {
	data := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "my-app",
				"dependencies": { "lodash": "^4.17.21" },
				"devDependencies": { "jest": "^29.0.0" }
			},
			"node_modules/lodash": {
				"version": "4.17.21",
				"license": "MIT",
				"dev": false
			},
			"node_modules/jest": {
				"version": "29.5.0",
				"license": "MIT",
				"dev": true
			},
			"node_modules/lodash/node_modules/nested": {
				"version": "1.0.0",
				"license": "ISC",
				"dev": false
			}
		}
	}`)

	pkgs, err := parseLockfileV2(data)
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	lodash, ok := byName["lodash"]
	if !ok {
		t.Fatal("lodash missing")
	}
	if lodash.Version != "4.17.21" {
		t.Errorf("lodash version = %q", lodash.Version)
	}
	if lodash.License != "MIT" {
		t.Errorf("lodash license = %q", lodash.License)
	}
	if !lodash.Direct {
		t.Error("lodash should be direct")
	}
	if lodash.Dev {
		t.Error("lodash should not be dev")
	}

	jest, ok := byName["jest"]
	if !ok {
		t.Fatal("jest missing")
	}
	if !jest.Dev {
		t.Error("jest should be dev")
	}
	if !jest.Direct {
		t.Error("jest should be direct")
	}

	nested, ok := byName["nested"]
	if !ok {
		t.Fatal("nested missing")
	}
	if nested.Direct {
		t.Error("nested (deduped) should not be direct")
	}
}

func TestParseLockfileV1(t *testing.T) {
	data := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"express": { "version": "4.18.2", "dev": false },
			"mocha":   { "version": "10.0.0", "dev": true }
		}
	}`)

	pkgs, err := parseLockfileV1(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if byName["express"].Version != "4.18.2" {
		t.Errorf("express version = %q", byName["express"].Version)
	}
	if !byName["mocha"].Dev {
		t.Error("mocha should be dev")
	}
}

func TestParsePackageJSON(t *testing.T) {
	data := []byte(`{
		"license": "Apache-2.0",
		"dependencies": { "axios": "^1.4.0" },
		"devDependencies": { "typescript": "~5.0.0" }
	}`)

	pkgs, err := parsePackageJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if byName["axios"].Version != "1.4.0" {
		t.Errorf("axios version = %q, want 1.4.0", byName["axios"].Version)
	}
	if byName["axios"].License != "Apache-2.0" {
		t.Errorf("axios license = %q", byName["axios"].License)
	}
	if byName["typescript"].Version != "5.0.0" {
		t.Errorf("typescript version = %q, want 5.0.0", byName["typescript"].Version)
	}
	if !byName["typescript"].Dev {
		t.Error("typescript should be dev")
	}
}

func TestParseAuditV7(t *testing.T) {
	data := []byte(`{
		"auditReportVersion": 2,
		"vulnerabilities": {
			"lodash": {
				"name": "lodash",
				"severity": "high",
				"via": [
					{
						"title": "Prototype Pollution",
						"url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
						"cvss": { "score": 7.4 }
					}
				],
				"fixAvailable": { "name": "lodash", "version": "4.17.21" }
			}
		}
	}`)

	findings, err := parseAuditV7(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.PackageName != "lodash" {
		t.Errorf("PackageName = %q", f.PackageName)
	}
	if f.VulnID != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("VulnID = %q", f.VulnID)
	}
	if f.CVSSScore != 7.4 {
		t.Errorf("CVSSScore = %v", f.CVSSScore)
	}
	if f.FixedIn != "4.17.21" {
		t.Errorf("FixedIn = %q", f.FixedIn)
	}
}

func TestParseAuditV6(t *testing.T) {
	data := []byte(`{
		"advisories": {
			"1234": {
				"module_name": "lodash",
				"severity": "high",
				"cves": ["CVE-2020-8203"],
				"overview": "Prototype pollution",
				"patched_versions": ">=4.17.19"
			}
		}
	}`)

	findings, err := parseAuditV6(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.VulnID != "CVE-2020-8203" {
		t.Errorf("VulnID = %q", f.VulnID)
	}
	if f.FixedIn != "4.17.19" {
		t.Errorf("FixedIn = %q", f.FixedIn)
	}
}
