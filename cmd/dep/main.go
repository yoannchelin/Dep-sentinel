package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/leazelaya/dep-sentinel/internal/scanner"
	"github.com/leazelaya/dep-sentinel/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return nil
	}
	switch os.Args[1] {
	case "scan":
		return cmdScan(os.Args[2:])
	case "vulns":
		return cmdVulns(os.Args[2:])
	case "licenses":
		return cmdLicenses(os.Args[2:])
	case "outdated":
		return cmdOutdated(os.Args[2:])
	default:
		usage()
		return nil
	}
}

func usage() {
	fmt.Println(`dep — Dep Sentinel CLI

Commands:
  scan      --dir <path>  [--db <path>] [--no-network] [--osv-cache <path>]
  vulns     --dir <path>  [--db <path>] [--min-severity high|medium|low]
  licenses  --dir <path>  [--db <path>]
  outdated  --dir <path>  [--db <path>] [--major-only]`)
}

func openDB(dbPath, dir string) (*store.Store, error) {
	if dbPath == "" {
		dbPath = dir + "/dep-sentinel.db"
	}
	return store.Open(dbPath)
}

// cmdScan runs a full dependency scan.
func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	dir := fs.String("dir", ".", "Path to Go project with go.mod")
	dbPath := fs.String("db", "", "SQLite DB path (default: <dir>/dep-sentinel.db)")
	noNetwork := fs.Bool("no-network", false, "Skip proxy.golang.org latest-version checks")
	osvCache := fs.String("osv-cache", "", "OSV cache zip path")
	_ = fs.Parse(args)

	s, err := openDB(*dbPath, *dir)
	if err != nil {
		return err
	}
	defer s.Close()

	return scanner.Run(s, scanner.Options{
		Dir:          *dir,
		OSVCachePath: *osvCache,
		OSVMaxAge:    24 * time.Hour,
		NoNetwork:    *noNetwork,
		Log:          os.Stderr,
	})
}

// cmdVulns shows vulnerability findings.
func cmdVulns(args []string) error {
	fs := flag.NewFlagSet("vulns", flag.ExitOnError)
	dir := fs.String("dir", ".", "Path to Go project")
	dbPath := fs.String("db", "", "SQLite DB path")
	minSev := fs.String("min-severity", "low", "Minimum severity: critical|high|medium|low")
	_ = fs.Parse(args)

	s, err := openDB(*dbPath, *dir)
	if err != nil {
		return err
	}
	defer s.Close()

	vulns, err := s.QueryVulns(*minSev)
	if err != nil {
		return err
	}
	if len(vulns) == 0 {
		fmt.Println("No vulnerabilities found.")
		return nil
	}

	fmt.Printf("%-10s  %-8s  %-6s  %-30s  %s\n", "VULN-ID", "SEVERITY", "CVSS", "MODULE", "SUMMARY")
	fmt.Println(strings.Repeat("-", 90))
	for _, v := range vulns {
		cvss := "-"
		if v.CVSSScore > 0 {
			cvss = fmt.Sprintf("%.1f", v.CVSSScore)
		}
		mod := v.ModulePath
		if len(mod) > 30 {
			mod = "…" + mod[len(mod)-29:]
		}
		sum := v.Summary
		if len(sum) > 50 {
			sum = sum[:47] + "…"
		}
		fmt.Printf("%-10s  %-8s  %-6s  %-30s  %s\n", v.VulnID, v.Severity, cvss, mod, sum)
		if v.FixedIn != "" {
			fmt.Printf("%-10s  fixed in: %s\n", "", v.FixedIn)
		}
	}
	return nil
}

// cmdLicenses shows modules with license issues.
func cmdLicenses(args []string) error {
	fs := flag.NewFlagSet("licenses", flag.ExitOnError)
	dir := fs.String("dir", ".", "Path to Go project")
	dbPath := fs.String("db", "", "SQLite DB path")
	_ = fs.Parse(args)

	s, err := openDB(*dbPath, *dir)
	if err != nil {
		return err
	}
	defer s.Close()

	mods, err := s.QueryBadLicenses()
	if err != nil {
		return err
	}
	if len(mods) == 0 {
		fmt.Println("All module licenses are acceptable.")
		return nil
	}

	fmt.Printf("%-50s  %-10s  %-20s  %s\n", "MODULE", "VERSION", "LICENSE", "TYPE")
	fmt.Println(strings.Repeat("-", 95))
	for _, m := range mods {
		lic := m.License
		if lic == "" {
			lic = "(unknown)"
		}
		direct := "transitive"
		if m.Direct == 1 {
			direct = "direct"
		}
		fmt.Printf("%-50s  %-10s  %-20s  %s\n", m.Path, m.Version, lic, direct)
	}
	return nil
}

// cmdOutdated shows modules with available updates.
func cmdOutdated(args []string) error {
	fs := flag.NewFlagSet("outdated", flag.ExitOnError)
	dir := fs.String("dir", ".", "Path to Go project")
	dbPath := fs.String("db", "", "SQLite DB path")
	majorOnly := fs.Bool("major-only", false, "Only show major version bumps")
	_ = fs.Parse(args)

	s, err := openDB(*dbPath, *dir)
	if err != nil {
		return err
	}
	defer s.Close()

	mods, err := s.QueryOutdated(*majorOnly)
	if err != nil {
		return err
	}
	if len(mods) == 0 {
		fmt.Println("All modules are up to date.")
		return nil
	}

	fmt.Printf("%-50s  %-15s  %-15s  %s\n", "MODULE", "CURRENT", "LATEST", "TYPE")
	fmt.Println(strings.Repeat("-", 90))
	for _, m := range mods {
		direct := "transitive"
		if m.Direct == 1 {
			direct = "direct"
		}
		fmt.Printf("%-50s  %-15s  %-15s  %s\n", m.Path, m.Version, m.LatestVersion, direct)
	}
	return nil
}
