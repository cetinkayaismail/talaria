package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LDNSSResult represents a Dynamic Linker or NSS configuration security finding.
type LDNSSResult struct {
	Path          string `json:"path"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

// ScanLDNSSConfiguration audits dynamic linker search paths and NSS configuration.
func ScanLDNSSConfiguration() ([]LDNSSResult, error) {
	var results []LDNSSResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	// 1. Check /etc/ld.so.conf.d/ directory itself
	if info, err := os.Stat("/etc/ld.so.conf.d"); err == nil {
		if isStatWritable(info, userCtx) {
			results = append(results, LDNSSResult{
				Path:          "/etc/ld.so.conf.d",
				RiskLevel:     "CRITICAL",
				Reason:        "/etc/ld.so.conf.d directory is writable by current user — dropping a custom .conf file hijacks shared library loading for all system binaries",
				ExploitHint:   "echo '/tmp/evil_libs' > /etc/ld.so.conf.d/00_evil.conf && ldconfig",
				Remediation:   "chown root:root /etc/ld.so.conf.d && chmod 0755 /etc/ld.so.conf.d",
				ComplianceTag: "CIS-Linux-5.4.2 / NIST-SI-7",
				IsDangerous:   true,
			})
		}
	}

	// 2. Check /etc/ld.so.conf file itself
	if info, err := os.Stat("/etc/ld.so.conf"); err == nil {
		if isStatWritable(info, userCtx) {
			results = append(results, LDNSSResult{
				Path:          "/etc/ld.so.conf",
				RiskLevel:     "CRITICAL",
				Reason:        "/etc/ld.so.conf is writable by current user — appending a writable library directory allows global shared library injection",
				ExploitHint:   "echo '/tmp/evil_libs' >> /etc/ld.so.conf && ldconfig",
				Remediation:   "chown root:root /etc/ld.so.conf && chmod 0644 /etc/ld.so.conf",
				ComplianceTag: "CIS-Linux-5.4.2 / NIST-SI-7",
				IsDangerous:   true,
			})
		}
	}

	// 3. Parse /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf for referenced library directories
	libDirs := collectLdDirs("/etc/ld.so.conf")
	for _, dir := range libDirs {
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if isStatWritable(info, userCtx) {
			results = append(results, LDNSSResult{
				Path:          dir,
				RiskLevel:     "CRITICAL",
				Reason:        fmt.Sprintf("Dynamic linker search directory '%s' is writable by current user — planting a malicious shared library (.so) hijacks privileged binaries", dir),
				ExploitHint:   fmt.Sprintf("Place a malicious compiled shared object (e.g. libc.so.6 or libssl.so) in %s", dir),
				Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s && ldconfig", dir, dir),
				ComplianceTag: "CIS-Linux-5.4.2 / NIST-SI-7",
				IsDangerous:   true,
			})
		}
	}

	// 4. Audit /etc/nsswitch.conf
	if info, err := os.Stat("/etc/nsswitch.conf"); err == nil {
		if isStatWritable(info, userCtx) {
			results = append(results, LDNSSResult{
				Path:          "/etc/nsswitch.conf",
				RiskLevel:     "CRITICAL",
				Reason:        "/etc/nsswitch.conf is writable by current user — modifying NSS service mappings allows redirecting password/group lookups to custom libraries",
				ExploitHint:   "Add 'passwd: files evil_nss' in /etc/nsswitch.conf to load custom libnss_evil_nss.so.2",
				Remediation:   "chown root:root /etc/nsswitch.conf && chmod 0644 /etc/nsswitch.conf",
				ComplianceTag: "CIS-Linux-5.4.2 / NIST-SI-7",
				IsDangerous:   true,
			})
		}
	}

	return results, nil
}

func collectLdDirs(confPath string) []string {
	var dirs []string
	visited := make(map[string]bool)

	var parseFile func(path string)
	parseFile = func(path string) {
		if visited[path] {
			return
		}
		visited[path] = true

		file, err := os.Open(path)
		if err != nil {
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if strings.HasPrefix(line, "include ") {
				pattern := strings.TrimSpace(strings.TrimPrefix(line, "include "))
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(path), pattern)
				}
				matches, err := filepath.Glob(pattern)
				if err == nil {
					for _, m := range matches {
						parseFile(m)
					}
				}
				continue
			}

			// It's a directory path
			cleanDir := strings.TrimSpace(line)
			if filepath.IsAbs(cleanDir) {
				dirs = append(dirs, cleanDir)
			}
		}
	}

	parseFile(confPath)
	return dirs
}
