package scanner

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/leazelaya/dep-sentinel/internal/licenses"
	"github.com/leazelaya/dep-sentinel/internal/npm"
	"github.com/leazelaya/dep-sentinel/internal/store"
	"github.com/leazelaya/dep-sentinel/internal/vulns"
)

// runNPMScan audits npm dependencies in opts.Dir and writes results into s.
// Called by Run when a package.json is detected.
func runNPMScan(s *store.Store, opts Options) error {
	opts.log("listing npm packages…")
	pkgs, err := npm.ListAll(opts.Dir)
	if err != nil {
		return err
	}
	opts.log("%d npm packages found", len(pkgs))

	// Fetch latest versions concurrently (same 10-worker pattern as Go scan).
	type latestResult struct {
		name   string
		latest string
	}
	latestMap := make(map[string]string, len(pkgs))
	if !opts.NoNetwork {
		opts.log("fetching latest npm versions from registry.npmjs.org…")
		sem := make(chan struct{}, 10)
		results := make(chan latestResult, len(pkgs))
		var wg sync.WaitGroup
		for _, p := range pkgs {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				sem <- struct{}{}
				latest := npm.LatestVersion(name)
				<-sem
				results <- latestResult{name, latest}
			}(p.Name)
		}
		wg.Wait()
		close(results)
		for r := range results {
			if r.latest != "" {
				latestMap[r.name] = r.latest
			}
		}
	}

	// Upsert npm packages. Store path as "npm:<name>" to distinguish from Go modules.
	pkgIDs := make(map[string]int64, len(pkgs))
	for _, p := range pkgs {
		storePath := "npm:" + p.Name
		licOK := licenses.IsOK(p.License)
		direct := 0
		if p.Direct {
			direct = 1
		}
		id, err := s.UpsertModule(store.Module{
			Path:          storePath,
			Version:       p.Version,
			LatestVersion: latestMap[p.Name],
			License:       p.License,
			LicenseOK:     licOK,
			Direct:        direct,
			Ecosystem:     "npm",
		})
		if err != nil {
			opts.log("upsert npm %s: %v", p.Name, err)
			continue
		}
		pkgIDs[p.Name] = id
	}

	// Vulnerability scan: npm audit primary, OSV fallback.
	if npm.AuditAvailable() {
		opts.log("running npm audit…")
		findings, err := npm.RunAudit(opts.Dir)
		if err != nil {
			opts.log("npm audit warning: %v — falling back to OSV", err)
		} else {
			opts.log("%d npm audit findings", len(findings))
			for _, f := range findings {
				mid, ok := pkgIDs[f.PackageName]
				if !ok {
					continue
				}
				_ = s.InsertVuln(store.Vuln{
					ModuleID:  mid,
					VulnID:    f.VulnID,
					Severity:  f.Severity,
					CVSSScore: f.CVSSScore,
					Summary:   f.Summary,
					FixedIn:   f.FixedIn,
				})
			}
			return nil
		}
	}

	// OSV fallback.
	opts.log("npm audit not available — falling back to OSV database (npm ecosystem)")
	return runNPMOSVFallback(s, pkgs, pkgIDs, opts)
}

func runNPMOSVFallback(s *store.Store, pkgs []npm.Package, pkgIDs map[string]int64, opts Options) error {
	cachePath := opts.OSVCachePath
	if cachePath == "" {
		cachePath = filepath.Join(os.TempDir(), "dep-sentinel-osv-npm.zip")
	}
	opts.log("loading OSV npm database (cache: %s)…", cachePath)
	osvDB, err := vulns.LoadOSVDBFromURL(vulns.OSVNpmURL, cachePath, opts.OSVMaxAge)
	if err != nil {
		return err
	}
	opts.log("%d OSV npm entries loaded", len(osvDB))

	count := 0
	for _, p := range pkgs {
		mid, ok := pkgIDs[p.Name]
		if !ok {
			continue
		}
		entries := vulns.LookupModule(osvDB, p.Name, p.Version)
		for _, e := range entries {
			fixedIn := vulns.FixedVersion(e, p.Name)
			if err := s.InsertVuln(store.Vuln{
				ModuleID:  mid,
				VulnID:    e.ID,
				Severity:  e.Severity,
				CVSSScore: e.CVSS,
				Summary:   e.Summary,
				FixedIn:   fixedIn,
			}); err != nil {
				opts.log("insert npm osv vuln: %v", err)
			}
			count++
		}
	}
	opts.log("%d OSV npm vulnerabilities matched", count)
	return nil
}
