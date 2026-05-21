package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite DB and exposes dep_* operations.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite DB at path and runs migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) DB() *sql.DB  { return s.db }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS dep_modules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    path           TEXT NOT NULL UNIQUE,
    version        TEXT NOT NULL,
    latest_version TEXT,
    license        TEXT,
    license_ok     INTEGER NOT NULL DEFAULT 1,
    last_commit_ts INTEGER,
    is_abandoned   INTEGER NOT NULL DEFAULT 0,
    direct         INTEGER NOT NULL DEFAULT 1,
    ecosystem      TEXT NOT NULL DEFAULT 'go'
);

CREATE TABLE IF NOT EXISTS dep_vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id   INTEGER NOT NULL REFERENCES dep_modules(id),
    vuln_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    cvss_score  REAL,
    summary     TEXT NOT NULL,
    fixed_in    TEXT,
    blast_risk  REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dep_vuln_sev ON dep_vulnerabilities(severity, cvss_score DESC);

CREATE TABLE IF NOT EXISTS dep_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`)
	if err != nil {
		return err
	}
	// For DBs created before the ecosystem column was added.
	_, _ = s.db.Exec(`ALTER TABLE dep_modules ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'go'`)
	return nil
}

// SetMeta stores a key-value pair.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO dep_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// GetMeta retrieves a value or returns "".
func (s *Store) GetMeta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM dep_meta WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// ClearModules removes all dep_* data (for re-scan).
func (s *Store) ClearModules() error {
	_, err := s.db.Exec(`DELETE FROM dep_vulnerabilities; DELETE FROM dep_modules`)
	return err
}

// UpsertModule inserts or updates a module row, returning its id.
func (s *Store) UpsertModule(m Module) (int64, error) {
	if m.Ecosystem == "" {
		m.Ecosystem = "go"
	}
	res, err := s.db.Exec(`
INSERT INTO dep_modules(path,version,latest_version,license,license_ok,last_commit_ts,is_abandoned,direct,ecosystem)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(path) DO UPDATE SET
  version=excluded.version,
  latest_version=excluded.latest_version,
  license=excluded.license,
  license_ok=excluded.license_ok,
  last_commit_ts=excluded.last_commit_ts,
  is_abandoned=excluded.is_abandoned,
  direct=excluded.direct,
  ecosystem=excluded.ecosystem`,
		m.Path, m.Version, m.LatestVersion, m.License, m.LicenseOK,
		m.LastCommitTS, m.IsAbandoned, m.Direct, m.Ecosystem)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if id == 0 {
		s.db.QueryRow(`SELECT id FROM dep_modules WHERE path=?`, m.Path).Scan(&id)
	}
	return id, nil
}

// InsertVuln inserts a vulnerability finding.
func (s *Store) InsertVuln(v Vuln) error {
	_, err := s.db.Exec(`
INSERT INTO dep_vulnerabilities(module_id,vuln_id,severity,cvss_score,summary,fixed_in,blast_risk)
VALUES(?,?,?,?,?,?,?)`,
		v.ModuleID, v.VulnID, v.Severity, v.CVSSScore, v.Summary, v.FixedIn, v.BlastRisk)
	return err
}

// QueryVulns returns vulnerabilities at or above minSeverity.
func (s *Store) QueryVulns(minSeverity string) ([]VulnRow, error) {
	severityRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	minRank, ok := severityRank[minSeverity]
	if !ok {
		minRank = 3
	}

	rows, err := s.db.Query(`
SELECT v.vuln_id, v.severity, v.cvss_score, v.summary, v.fixed_in, v.blast_risk,
       m.path, m.version, m.latest_version
FROM dep_vulnerabilities v
JOIN dep_modules m ON m.id = v.module_id
ORDER BY
  CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
  v.cvss_score DESC, v.blast_risk DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []VulnRow
	for rows.Next() {
		var r VulnRow
		var cvss sql.NullFloat64
		var fixedIn, latest sql.NullString
		if err := rows.Scan(&r.VulnID, &r.Severity, &cvss, &r.Summary, &fixedIn,
			&r.BlastRisk, &r.ModulePath, &r.ModuleVersion, &latest); err != nil {
			return nil, err
		}
		if cvss.Valid {
			r.CVSSScore = cvss.Float64
		}
		r.FixedIn = fixedIn.String
		r.LatestVersion = latest.String
		if severityRank[r.Severity] <= minRank {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// QueryBadLicenses returns modules with non-OK or unknown licenses.
func (s *Store) QueryBadLicenses() ([]Module, error) {
	rows, err := s.db.Query(`
SELECT id,path,version,latest_version,license,license_ok,last_commit_ts,is_abandoned,direct,ecosystem
FROM dep_modules WHERE license_ok=0 OR license IS NULL OR license=''
ORDER BY path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanModules(rows)
}

// QueryOutdated returns modules where latest_version != version.
func (s *Store) QueryOutdated(majorOnly bool) ([]Module, error) {
	q := `
SELECT id,path,version,latest_version,license,license_ok,last_commit_ts,is_abandoned,direct,ecosystem
FROM dep_modules WHERE latest_version IS NOT NULL AND latest_version!='' AND latest_version!=version
ORDER BY path`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	all, err := scanModules(rows)
	if err != nil || !majorOnly {
		return all, err
	}
	var out []Module
	for _, m := range all {
		if isMajorBump(m.Version, m.LatestVersion) {
			out = append(out, m)
		}
	}
	return out, nil
}

func scanModules(rows *sql.Rows) ([]Module, error) {
	var out []Module
	for rows.Next() {
		var m Module
		var latest, license, ecosystem sql.NullString
		var lastTS sql.NullInt64
		if err := rows.Scan(&m.ID, &m.Path, &m.Version, &latest, &license,
			&m.LicenseOK, &lastTS, &m.IsAbandoned, &m.Direct, &ecosystem); err != nil {
			return nil, err
		}
		m.LatestVersion = latest.String
		m.License = license.String
		m.LastCommitTS = lastTS.Int64
		m.Ecosystem = ecosystem.String
		if m.Ecosystem == "" {
			m.Ecosystem = "go"
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
