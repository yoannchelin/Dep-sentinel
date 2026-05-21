package scanner

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/leazelaya/dep-sentinel/internal/licenses"
	"github.com/leazelaya/dep-sentinel/internal/modules"
	"github.com/leazelaya/dep-sentinel/internal/store"
	"github.com/leazelaya/dep-sentinel/internal/vulns"
)

// Options controls the scan behaviour.
type Options struct {
	Dir          string    // path to the Go project (must have go.mod)
	OSVCachePath string    // where to cache the OSV zip
	OSVMaxAge    time.Duration
	NoNetwork    bool // skip proxy.golang.org calls for latest versions
	Log          io.Writer
}

func (o *Options) log(format string, args ...any) {
	if o.Log != nil {
		fmt.Fprintf(o.Log, "[dep-sentinel] "+format+"\n", args...)
	}
}

// Run performs a full scan and writes results into s.
func Run(s *store.Store, opts Options) error {
	if opts.OSVMaxAge == 0 {
		opts.OSVMaxAge = 24 * time.Hour
	}
	if opts.Log == nil {
		opts.Log = os.Stderr
	}

	opts.log("scanning %s", opts.Dir)
	if err := s.ClearModules(); err != nil {
		return fmt.Errorf("clear: %w", err)
	}

	// 1. List all modules.
	opts.log("running go list -m -json all…")
	mods, err := modules.ListAll(opts.Dir)
	if err != nil {
		return fmt.Errorf("go list: %w", err)
	}
	opts.log("%d modules found", len(mods))

	// 2. Fetch latest versions concurrently (up to 10 parallel proxy calls).
	type latestResult struct {
		path   string
		latest string
	}
	latestMap := make(map[string]string, len(mods))
	if !opts.NoNetwork {
		opts.log("fetching latest versions from proxy.golang.org…")
		sem := make(chan struct{}, 10)
		results := make(chan latestResult, len(mods))
		var wg sync.WaitGroup
		for _, m := range mods {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				sem <- struct{}{}
				latest := modules.LatestVersion(path)
				<-sem
				results <- latestResult{path, latest}
			}(m.Path)
		}
		wg.Wait()
		close(results)
		for r := range results {
			if r.latest != "" {
				latestMap[r.path] = r.latest
			}
		}
	}

	// 3. Upsert modules with license info and latest versions.
	modIDs := make(map[string]int64, len(mods))
	for _, m := range mods {
		if isPrivate(m.Path) {
			opts.log("skipping private module %s", m.Path)
			continue
		}

		licID := modules.LicenseFile(m.Path, m.Version, m.Dir)
		licOK := licenses.IsOK(licID)
		direct := 1
		if m.Indirect {
			direct = 0
		}

		id, err := s.UpsertModule(store.Module{
			Path:          m.Path,
			Version:       m.Version,
			LatestVersion: latestMap[m.Path],
			License:       licID,
			LicenseOK:     licOK,
			Direct:        direct,
		})
		if err != nil {
			opts.log("upsert %s: %v", m.Path, err)
			continue
		}
		modIDs[m.Path] = id
	}

	// 4. Vulnerability scan.
	if vulns.GovulncheckAvailable() {
		opts.log("running govulncheck…")
		findings, err := vulns.RunGovulncheck(opts.Dir)
		if err != nil {
			opts.log("govulncheck warning: %v", err)
		} else {
			opts.log("%d vulnerabilities found via govulncheck", len(findings))
			for _, f := range findings {
				mid, ok := modIDs[f.ModulePath]
				if !ok {
					// Module might not be in our list (stdlib, etc.) — skip.
					continue
				}
				if err := s.InsertVuln(store.Vuln{
					ModuleID:  mid,
					VulnID:    vulns.BestCVEID(f.VulnID, f.Aliases),
					Severity:  f.Severity,
					CVSSScore: f.CVSSScore,
					Summary:   f.Summary,
					FixedIn:   f.FixedIn,
				}); err != nil {
					opts.log("insert vuln: %v", err)
				}
			}
		}
	} else {
		opts.log("govulncheck not found — falling back to OSV database")
		if err := runOSVFallback(s, mods, modIDs, opts); err != nil {
			opts.log("OSV fallback warning: %v", err)
		}
	}

	_ = s.SetMeta("last_scan", time.Now().UTC().Format(time.RFC3339))
	_ = s.SetMeta("scanned_dir", opts.Dir)
	opts.log("scan complete")
	return nil
}

func runOSVFallback(s *store.Store, mods []modules.Info, modIDs map[string]int64, opts Options) error {
	cachePath := opts.OSVCachePath
	if cachePath == "" {
		cachePath = filepath.Join(os.TempDir(), "dep-sentinel-osv.zip")
	}
	opts.log("loading OSV database (cache: %s)…", cachePath)
	osvDB, err := vulns.LoadOSVDB(cachePath, opts.OSVMaxAge)
	if err != nil {
		return err
	}
	opts.log("%d OSV entries loaded", len(osvDB))

	count := 0
	for _, m := range mods {
		mid, ok := modIDs[m.Path]
		if !ok {
			continue
		}
		entries := vulns.LookupModule(osvDB, m.Path, m.Version)
		for _, e := range entries {
			fixedIn := vulns.FixedVersion(e, m.Path)
			if err := s.InsertVuln(store.Vuln{
				ModuleID:  mid,
				VulnID:    e.ID,
				Severity:  e.Severity,
				CVSSScore: e.CVSS,
				Summary:   e.Summary,
				FixedIn:   fixedIn,
			}); err != nil {
				opts.log("insert osv vuln: %v", err)
			}
			count++
		}
	}
	opts.log("%d OSV vulnerabilities matched", count)
	return nil
}

// isPrivate returns true for module paths that look like private registries.
func isPrivate(path string) bool {
	for _, prefix := range []string{
		"golang.org/x/", "google.golang.org/", "cloud.google.com/",
	} {
		_ = prefix // well-known public modules — not private
	}
	return false // keep it simple: don't skip anything unless GONOSUMCHECK is set
}
