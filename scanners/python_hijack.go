package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// PythonHijackResult represents a detected Python library or path hijacking vulnerability.
type PythonHijackResult struct {
	Type          string `json:"type"`                     // "Writable Search Path", "Writable Script Directory", "Shadowable Standard Library"
	Path          string `json:"path"`                     // Directory or file path that is writable
	ScriptName    string `json:"script_name,omitempty"`    // Root script affected (if applicable)
	RiskLevel     string `json:"risk_level"`               // CRITICAL, HIGH, MEDIUM
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var commonHijackModules = []string{"os", "sys", "requests", "yaml", "json", "subprocess", "shutil", "urllib", "logging"}

// ScanPythonHijack audits system Python search paths and root-owned Python scripts for library hijacking vectors.
func ScanPythonHijack() ([]PythonHijackResult, error) {
	var results []PythonHijackResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	seen := make(map[string]bool)

	// 1. Audit standard system-wide Python site-packages and dist-packages directories
	systemPythonDirs := discoverPythonSearchPaths()
	for _, dirPath := range systemPythonDirs {
		info, err := os.Stat(dirPath)
		if err != nil || !info.IsDir() {
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		if userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
			if seen[dirPath] {
				continue
			}
			seen[dirPath] = true

			results = append(results, PythonHijackResult{
				Type:          "Writable Search Path",
				Path:          dirPath,
				RiskLevel:     "HIGH",
				Reason:        fmt.Sprintf("System-wide Python module path '%s' is writable by unprivileged user", dirPath),
				ExploitHint:   fmt.Sprintf("Plant a malicious '%s.py' in %s: echo 'import os; os.setuid(0); os.system(\"/bin/bash\")' > %s/requests.py", commonHijackModules[2], dirPath, dirPath),
				Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", dirPath, dirPath),
				ComplianceTag: "CIS-Linux-6.2.8 / NIST-AC-6",
				IsDangerous:   true,
			})
		}
	}

	// 2. Audit root-owned Python scripts in crontabs and systemd services
	rootPythonScripts := discoverRootPythonScripts()
	for _, scriptPath := range rootPythonScripts {
		info, err := os.Stat(scriptPath)
		if err != nil || info.IsDir() {
			continue
		}

		scriptDir := filepath.Dir(scriptPath)
		dirInfo, err := os.Stat(scriptDir)
		if err != nil || !dirInfo.IsDir() {
			continue
		}

		dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		// If the directory containing the root-owned Python script is user-writable,
		// Python automatically places the script's directory as sys.path[0], granting instant hijacking!
		if userCtx.CanWrite(int(dirStat.Uid), int(dirStat.Gid), dirStat.Mode) {
			key := "scriptdir:" + scriptDir
			if seen[key] {
				continue
			}
			seen[key] = true

			// Find imported modules in the script to suggest exact payload names
			importedModule := extractFirstImport(scriptPath)
			if importedModule == "" {
				importedModule = "os"
			}

			results = append(results, PythonHijackResult{
				Type:          "Writable Script Directory",
				Path:          scriptDir,
				ScriptName:    scriptPath,
				RiskLevel:     "CRITICAL",
				Reason:        fmt.Sprintf("Root-owned Python script '%s' resides in a user-writable directory '%s' (sys.path[0] library hijacking)", filepath.Base(scriptPath), scriptDir),
				ExploitHint:   fmt.Sprintf("Plant '%s.py' in %s: echo 'import os; os.setuid(0); os.system(\"/bin/bash\")' > %s/%s.py", importedModule, scriptDir, scriptDir, importedModule),
				Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", scriptDir, scriptDir),
				ComplianceTag: "CIS-Linux-5.1.2 / NIST-AC-6",
				IsDangerous:   true,
			})
		}
	}

	return results, nil
}

// discoverPythonSearchPaths collects common system Python library and package directories.
func discoverPythonSearchPaths() []string {
	var paths []string

	// Standard base directories
	prefixes := []string{"/usr/local/lib", "/usr/lib"}
	versions := []string{"python3", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python2.7"}

	for _, prefix := range prefixes {
		for _, ver := range versions {
			paths = append(paths, filepath.Join(prefix, ver, "dist-packages"))
			paths = append(paths, filepath.Join(prefix, ver, "site-packages"))
		}
	}

	// Environment / shared paths
	paths = append(paths, "/var/lib/python", "/opt/python", "/usr/share/python")
	return paths
}

// discoverRootPythonScripts inspects common automation locations for Python scripts.
func discoverRootPythonScripts() []string {
	var scripts []string
	seen := make(map[string]bool)

	// Check crontabs
	cronFiles := []string{"/etc/crontab"}
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				cronFiles = append(cronFiles, filepath.Join("/etc/cron.d", e.Name()))
			}
		}
	}

	for _, cFile := range cronFiles {
		file, err := os.Open(cFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.Contains(line, ".py") {
				for _, part := range strings.Fields(line) {
					if strings.HasSuffix(part, ".py") && strings.HasPrefix(part, "/") {
						if !seen[part] {
							seen[part] = true
							scripts = append(scripts, part)
						}
					}
				}
			}
		}
		file.Close()
	}

	// Check systemd services
	serviceDirs := []string{"/etc/systemd/system", "/lib/systemd/system"}
	for _, sDir := range serviceDirs {
		entries, err := os.ReadDir(sDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			sFile := filepath.Join(sDir, e.Name())
			file, err := os.Open(sFile)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "ExecStart=") && strings.Contains(line, ".py") {
					for _, part := range strings.Fields(strings.TrimPrefix(line, "ExecStart=")) {
						if strings.HasSuffix(part, ".py") && strings.HasPrefix(part, "/") {
							if !seen[part] {
								seen[part] = true
								scripts = append(scripts, part)
							}
						}
					}
				}
			}
			file.Close()
		}
	}

	return scripts
}

var reImport = regexp.MustCompile(`(?m)^\s*(?:import|from)\s+([a-zA-Z0-9_]+)`)

func extractFirstImport(scriptPath string) string {
	file, err := os.Open(scriptPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if match := reImport.FindStringSubmatch(line); len(match) > 1 {
			mod := match[1]
			if mod != "__future__" && mod != "sys" {
				return mod
			}
		}
	}
	return ""
}
