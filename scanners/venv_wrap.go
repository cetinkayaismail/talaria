package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VenvWrapResult represents a vulnerable virtualenv or wrapper script finding.
type VenvWrapResult struct {
	Path        string `json:"path"`
	TargetType  string `json:"target_type"`
	RiskLevel   string `json:"risk_level"`
	Reason      string `json:"reason"`
	ExploitHint string `json:"exploit_hint"`
	IsDangerous bool   `json:"is_dangerous"`
}

var venvSearchDirs = []string{
	"/opt",
	"/var/www",
	"/usr/local",
	"/srv",
}

// ScanVirtualEnvsAndWrappers audits Python/Node virtual environments and executable wrapper scripts.
func ScanVirtualEnvsAndWrappers() ([]VenvWrapResult, error) {
	var results []VenvWrapResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	// 1. Audit /usr/local/bin and /usr/local/sbin wrapper scripts
	wrapperDirs := []string{"/usr/local/bin", "/usr/local/sbin"}
	for _, dir := range wrapperDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			scriptPath := filepath.Join(dir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if isStatWritable(info, userCtx) {
				results = append(results, VenvWrapResult{
					Path:        scriptPath,
					TargetType:  "WrapperScript",
					RiskLevel:   "CRITICAL",
					Reason:      fmt.Sprintf("Wrapper executable '%s' is writable by current user — if executed by root or admin users, grants code execution", scriptPath),
					ExploitHint: fmt.Sprintf("echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> %s", scriptPath),
					IsDangerous: true,
				})
			}
		}
	}

	// 2. Scan virtual environments in common application paths
	for _, baseDir := range venvSearchDirs {
		entries, err := os.ReadDir(baseDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			subPath := filepath.Join(baseDir, entry.Name())

			// Check for Python venv marker (bin/activate)
			activatePath := filepath.Join(subPath, "bin", "activate")
			if actInfo, err := os.Stat(activatePath); err == nil {
				if isStatWritable(actInfo, userCtx) {
					results = append(results, VenvWrapResult{
						Path:        activatePath,
						TargetType:  "VirtualEnv",
						RiskLevel:   "CRITICAL",
						Reason:      fmt.Sprintf("Virtualenv activation script '%s' is writable by current user", activatePath),
						ExploitHint: fmt.Sprintf("echo '/tmp/payload.sh' >> %s", activatePath),
						IsDangerous: true,
					})
				}

				// Check site-packages inside this venv
				libDir := filepath.Join(subPath, "lib")
				if pyDirs, err := os.ReadDir(libDir); err == nil {
					for _, pyDir := range pyDirs {
						if strings.HasPrefix(pyDir.Name(), "python") {
							spPath := filepath.Join(libDir, pyDir.Name(), "site-packages")
							if spInfo, err := os.Stat(spPath); err == nil && isStatWritable(spInfo, userCtx) {
								results = append(results, VenvWrapResult{
									Path:        spPath,
									TargetType:  "SitePackages",
									RiskLevel:   "CRITICAL",
									Reason:      fmt.Sprintf("Python site-packages directory '%s' is writable — poisoning packages executed by root services yields root execution", spPath),
									ExploitHint: fmt.Sprintf("Inject malicious payload into any module under %s", spPath),
									IsDangerous: true,
								})
							}
						}
					}
				}
			}
		}
	}

	return results, nil
}
