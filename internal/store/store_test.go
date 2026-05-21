package store

import (
	"testing"
)

func openMem(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUpsertModule(t *testing.T) {
	s := openMem(t)
	id, err := s.UpsertModule(Module{Path: "github.com/foo/bar", Version: "v1.2.3", LicenseOK: 1, Direct: 1})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Error("expected non-zero id")
	}

	// Upsert again — should update, not duplicate.
	id2, err := s.UpsertModule(Module{Path: "github.com/foo/bar", Version: "v1.2.4", LicenseOK: 1, Direct: 1})
	if err != nil {
		t.Fatal(err)
	}

	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM dep_modules WHERE path='github.com/foo/bar'`).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 row after upsert, got %d", count)
	}
	_ = id2
}

func TestInsertAndQueryVulns(t *testing.T) {
	s := openMem(t)
	mid, _ := s.UpsertModule(Module{Path: "github.com/vuln/pkg", Version: "v1.0.0", LicenseOK: 1, Direct: 1})

	if err := s.InsertVuln(Vuln{ModuleID: mid, VulnID: "CVE-2024-1234", Severity: "high", CVSSScore: 8.1, Summary: "Remote code execution"}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertVuln(Vuln{ModuleID: mid, VulnID: "GO-2024-5678", Severity: "low", CVSSScore: 2.0, Summary: "Minor info leak"}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.QueryVulns("high")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("QueryVulns(high) = %d rows, want 1", len(rows))
	}
	if rows[0].VulnID != "CVE-2024-1234" {
		t.Errorf("wrong vuln: %s", rows[0].VulnID)
	}

	all, _ := s.QueryVulns("low")
	if len(all) != 2 {
		t.Errorf("QueryVulns(low) = %d rows, want 2", len(all))
	}
}

func TestQueryBadLicenses(t *testing.T) {
	s := openMem(t)
	s.UpsertModule(Module{Path: "a/ok", Version: "v1.0.0", License: "MIT", LicenseOK: 1, Direct: 1})
	s.UpsertModule(Module{Path: "b/agpl", Version: "v1.0.0", License: "AGPL-3.0", LicenseOK: 0, Direct: 1})
	s.UpsertModule(Module{Path: "c/unknown", Version: "v1.0.0", License: "", LicenseOK: 0, Direct: 0})

	mods, err := s.QueryBadLicenses()
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 {
		t.Errorf("bad licenses = %d, want 2", len(mods))
	}
}

func TestQueryOutdated(t *testing.T) {
	s := openMem(t)
	s.UpsertModule(Module{Path: "a/old", Version: "v1.0.0", LatestVersion: "v1.2.0", LicenseOK: 1, Direct: 1})
	s.UpsertModule(Module{Path: "b/current", Version: "v2.0.0", LatestVersion: "v2.0.0", LicenseOK: 1, Direct: 1})
	s.UpsertModule(Module{Path: "c/major", Version: "v1.0.0", LatestVersion: "v2.0.0", LicenseOK: 1, Direct: 1})

	all, _ := s.QueryOutdated(false)
	if len(all) != 2 {
		t.Errorf("outdated all = %d, want 2", len(all))
	}

	majors, _ := s.QueryOutdated(true)
	if len(majors) != 1 {
		t.Errorf("outdated major-only = %d, want 1", len(majors))
	}
	if majors[0].Path != "c/major" {
		t.Errorf("wrong module: %s", majors[0].Path)
	}
}

func TestMeta(t *testing.T) {
	s := openMem(t)
	if err := s.SetMeta("last_scan", "2026-05-21"); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetMeta("last_scan")
	if err != nil {
		t.Fatal(err)
	}
	if v != "2026-05-21" {
		t.Errorf("meta = %q, want 2026-05-21", v)
	}
	empty, _ := s.GetMeta("nonexistent")
	if empty != "" {
		t.Errorf("missing key should return empty, got %q", empty)
	}
}
