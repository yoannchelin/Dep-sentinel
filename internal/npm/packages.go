package npm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Package is an npm dependency with resolved version and license.
type Package struct {
	Name    string
	Version string
	License string
	Dev     bool // true if devDependency
	Direct  bool // true if in root dependencies/devDependencies
}

// ListAll reads package-lock.json (v2/v3 preferred, v1 fallback) or package.json from dir.
func ListAll(dir string) ([]Package, error) {
	if data, err := os.ReadFile(dir + "/package-lock.json"); err == nil {
		pkgs, err := parseLockfile(data)
		if err == nil {
			return pkgs, nil
		}
	}
	data, err := os.ReadFile(dir + "/package.json")
	if err != nil {
		return nil, fmt.Errorf("no package-lock.json or package.json in %s", dir)
	}
	return parsePackageJSON(data)
}

func parseLockfile(data []byte) ([]Package, error) {
	var meta struct {
		LockfileVersion int `json:"lockfileVersion"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	if meta.LockfileVersion >= 2 {
		return parseLockfileV2(data)
	}
	return parseLockfileV1(data)
}

func parseLockfileV2(data []byte) ([]Package, error) {
	var lf struct {
		Packages map[string]struct {
			Version string `json:"version"`
			License string `json:"license"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, err
	}

	// Collect direct dep names from root entry "".
	directDeps := map[string]bool{}
	var rootPackages struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(data, &rootPackages); err == nil {
		if rawRoot, ok := rootPackages.Packages[""]; ok {
			var root struct {
				Dependencies    map[string]string `json:"dependencies"`
				DevDependencies map[string]string `json:"devDependencies"`
			}
			json.Unmarshal(rawRoot, &root)
			for name := range root.Dependencies {
				directDeps[name] = true
			}
			for name := range root.DevDependencies {
				directDeps[name] = true
			}
		}
	}

	var out []Package
	for key, pkg := range lf.Packages {
		if key == "" || !strings.HasPrefix(key, "node_modules/") {
			continue
		}
		if pkg.Version == "" {
			continue
		}
		name := extractName(key)
		out = append(out, Package{
			Name:    name,
			Version: pkg.Version,
			License: pkg.License,
			Dev:     pkg.Dev,
			Direct:  directDeps[name],
		})
	}
	return out, nil
}

func parseLockfileV1(data []byte) ([]Package, error) {
	var lf struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	var out []Package
	for name, dep := range lf.Dependencies {
		out = append(out, Package{
			Name:    name,
			Version: dep.Version,
			Dev:     dep.Dev,
			Direct:  true,
		})
	}
	return out, nil
}

// extractName strips "node_modules/" prefix and handles nested deduplicated paths
// like "node_modules/foo/node_modules/bar" → "bar".
func extractName(key string) string {
	key = strings.TrimPrefix(key, "node_modules/")
	if idx := strings.LastIndex(key, "node_modules/"); idx >= 0 {
		key = key[idx+len("node_modules/"):]
	}
	return key
}

func parsePackageJSON(data []byte) ([]Package, error) {
	var pj struct {
		License         interface{}       `json:"license"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, err
	}
	lic := extractLicense(pj.License)
	var out []Package
	for name, ver := range pj.Dependencies {
		out = append(out, Package{Name: name, Version: StripRange(ver), License: lic, Direct: true})
	}
	for name, ver := range pj.DevDependencies {
		out = append(out, Package{Name: name, Version: StripRange(ver), License: lic, Dev: true, Direct: true})
	}
	return out, nil
}

func extractLicense(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case map[string]interface{}:
		if t, ok := s["type"].(string); ok {
			return t
		}
	}
	return ""
}

// StripRange removes semver range operators (^, ~, >=, etc.) to get a bare version.
func StripRange(v string) string {
	v = strings.TrimSpace(v)
	i := 0
	for i < len(v) && (v[i] == '^' || v[i] == '~' || v[i] == '>' || v[i] == '=' || v[i] == '<' || v[i] == ' ') {
		i++
	}
	v = v[i:]
	if f := strings.Fields(v); len(f) > 0 {
		return f[0]
	}
	return v
}

// LatestVersion queries registry.npmjs.org for the latest stable version.
// Returns "" on error (degrade gracefully).
func LatestVersion(name string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://registry.npmjs.org/" + name + "/latest")
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Version string `json:"version"`
	}
	json.Unmarshal(body, &result)
	return result.Version
}
