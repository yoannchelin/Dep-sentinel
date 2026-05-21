package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Info holds parsed information about a Go module from `go list -m -json all`.
type Info struct {
	Path    string
	Version string
	Dir     string // local cache dir, empty if not downloaded
	Indirect bool   // true if not a direct dependency
	Replace  *Replace
}

type Replace struct {
	Path    string
	Version string
}

// ListAll runs `go list -m -json all` in dir and returns all modules.
func ListAll(dir string) ([]Info, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = dir
	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list: %w — %s", err, strings.TrimSpace(errBuf.String()))
	}

	return parseGoListJSON(out.Bytes())
}

type goListEntry struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Dir      string `json:"Dir"`
	Indirect bool   `json:"Indirect"`
	Replace  *struct {
		Path    string `json:"Path"`
		Version string `json:"Version"`
	} `json:"Replace"`
}

func parseGoListJSON(data []byte) ([]Info, error) {
	var out []Info
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var e goListEntry
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("parse go list: %w", err)
		}
		if e.Version == "" {
			continue // main module itself
		}
		info := Info{
			Path:     e.Path,
			Version:  e.Version,
			Dir:      e.Dir,
			Indirect: e.Indirect,
		}
		if e.Replace != nil {
			info.Replace = &Replace{Path: e.Replace.Path, Version: e.Replace.Version}
		}
		out = append(out, info)
	}
	return out, nil
}

// LatestVersion queries proxy.golang.org for the latest stable version of a module.
// Returns "" on error (degrade gracefully).
func LatestVersion(modulePath string) string {
	url := fmt.Sprintf("https://proxy.golang.org/%s/@latest", pathEscape(modulePath))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	return result.Version
}

// pathEscape escapes a module path for use in proxy.golang.org URLs.
// Capital letters are encoded as !lowercase per the module proxy protocol.
func pathEscape(p string) string {
	var sb strings.Builder
	for _, r := range p {
		if r >= 'A' && r <= 'Z' {
			sb.WriteByte('!')
			sb.WriteRune(r + 32)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// LicenseFile finds a LICENSE file for a module. Checks dir first (from go list),
// then falls back to the Go module cache at $GOPATH/pkg/mod.
func LicenseFile(modulePath, version, dir string) string {
	dirs := []string{dir}
	if gopath := os.Getenv("GOPATH"); gopath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dirs = append(dirs, modCachePath(home+"/go/pkg/mod", modulePath, version))
		}
	} else {
		dirs = append(dirs, modCachePath(gopath+"/pkg/mod", modulePath, version))
	}

	for _, d := range dirs {
		if d == "" {
			continue
		}
		for _, name := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"} {
			data, err := os.ReadFile(d + "/" + name)
			if err == nil {
				return DetectLicense(string(data))
			}
		}
	}
	return ""
}

// modCachePath returns the local cache path for a module in $GOPATH/pkg/mod.
// Capital letters are escaped as !lowercase per the module proxy protocol.
func modCachePath(modRoot, modulePath, version string) string {
	escaped := pathEscape(modulePath)
	return modRoot + "/" + escaped + "@" + version
}

// DetectLicense returns an SPDX identifier by matching known license text snippets.
func DetectLicense(text string) string {
	text = strings.ToLower(text)
	switch {
	case strings.Contains(text, "apache license") && strings.Contains(text, "version 2"):
		return "Apache-2.0"
	case strings.Contains(text, "mit license") || (strings.Contains(text, "permission is hereby granted") && strings.Contains(text, "mit")):
		return "MIT"
	case strings.Contains(text, "bsd 3-clause") || strings.Contains(text, "redistributions of source code must retain") && strings.Contains(text, "nor the names"):
		return "BSD-3-Clause"
	case strings.Contains(text, "bsd 2-clause") || strings.Contains(text, "redistributions of source code must retain") && !strings.Contains(text, "nor the names"):
		return "BSD-2-Clause"
	case strings.Contains(text, "isc license") || strings.Contains(text, "isc"):
		return "ISC"
	case strings.Contains(text, "mozilla public license") && strings.Contains(text, "2.0"):
		return "MPL-2.0"
	case strings.Contains(text, "gnu lesser general public license"):
		if strings.Contains(text, "version 3") || strings.Contains(text, "v3") {
			return "LGPL-3.0"
		}
		return "LGPL-2.1"
	case strings.Contains(text, "gnu affero general public license") || strings.Contains(text, "agpl"):
		return "AGPL-3.0"
	case strings.Contains(text, "gnu general public license"):
		if strings.Contains(text, "version 3") || strings.Contains(text, "v3") {
			return "GPL-3.0"
		}
		return "GPL-2.0"
	case strings.Contains(text, "server side public license") || strings.Contains(text, "sspl"):
		return "SSPL-1.0"
	case strings.Contains(text, "commons clause"):
		return "Commons-Clause"
	case strings.Contains(text, "unlicense"):
		return "Unlicense"
	case strings.Contains(text, "creative commons"):
		return "CC0-1.0"
	default:
		return ""
	}
}
