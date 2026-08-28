package scanners

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// PAMResult represents a vulnerability or misconfiguration found in PAM policies.
type PAMResult struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	RiskLevel   string `json:"risk_level"`
	Reason      string `json:"reason"`
	ExploitHint string `json:"exploit_hint"`
	IsDangerous bool   `json:"is_dangerous"`
}

// Security module search directories on Linux
var pamSecurityDirs = []string{
	"/lib/security",
	"/lib64/security",
	"/lib/x86_64-linux-gnu/security",
	"/usr/lib/security",
	"/usr/lib64/security",
	"/usr/lib/x86_64-linux-gnu/security",
}

// ScanPAM audits /etc/pam.d/ for writable PAM configuration files,
// writable pam_exec scripts, writable pam_env files, and writable custom PAM modules (.so).
func ScanPAM() ([]PAMResult, error) {
	var results []PAMResult
	userCtx := GetUserContext()

	pamDir := "/etc/pam.d"
	entries, err := os.ReadDir(pamDir)
	if err != nil {
		return results, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(pamDir, entry.Name())

		// 1. Check if the PAM policy file itself is writable
		fileInfo, statErr := os.Stat(filePath)
		if statErr == nil && userCtx != nil {
			mode := uint32(fileInfo.Mode().Perm())
			fileUID, fileGID := getFileOwnership(fileInfo)
			if userCtx.CanWrite(fileUID, fileGID, mode) {
				results = append(results, PAMResult{
					Path:        filePath,
					Type:        "pam_config_writable",
					RiskLevel:   "CRITICAL",
					Reason:      "PAM configuration file is writable by current user (authentication bypass vector)",
					ExploitHint: "echo 'auth sufficient pam_permit.so' >> " + filePath,
					IsDangerous: true,
				})
			}
		}

		// 2. Parse file content for directives (pam_exec.so, pam_env.so, custom modules)
		file, err := os.Open(filePath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Audit pam_exec.so script execution targets
			if strings.Contains(line, "pam_exec.so") {
				fields := strings.Fields(line)
				for _, f := range fields {
					if strings.HasPrefix(f, "/") {
						scriptPath := f
						if info, err := os.Stat(scriptPath); err == nil {
							uid, gid := getFileOwnership(info)
							mode := uint32(info.Mode().Perm())
							if userCtx != nil && userCtx.CanWrite(uid, gid, mode) {
								results = append(results, PAMResult{
									Path:        scriptPath,
									Type:        "pam_exec_writable",
									RiskLevel:   "CRITICAL",
									Reason:      "Script executed by pam_exec in " + entry.Name() + " is writable",
									ExploitHint: "echo 'chmod +s /bin/bash' >> " + scriptPath,
									IsDangerous: true,
								})
							}
						}
					}
				}
			}

			// Audit pam_env.so environment file targets
			if strings.Contains(line, "pam_env.so") {
				fields := strings.Fields(line)
				for _, f := range fields {
					if strings.HasPrefix(f, "envfile=") || strings.HasPrefix(f, "user_envfile=") {
						parts := strings.SplitN(f, "=", 2)
						if len(parts) == 2 && strings.HasPrefix(parts[1], "/") {
							envPath := parts[1]
							if info, err := os.Stat(envPath); err == nil {
								uid, gid := getFileOwnership(info)
								mode := uint32(info.Mode().Perm())
								if userCtx != nil && userCtx.CanWrite(uid, gid, mode) {
									results = append(results, PAMResult{
										Path:        envPath,
										Type:        "pam_env_writable",
										RiskLevel:   "HIGH",
										Reason:      "Environment file referenced by pam_env in " + entry.Name() + " is writable",
										ExploitHint: "echo 'LD_PRELOAD=/tmp/evil.so' >> " + envPath,
										IsDangerous: true,
									})
								}
							}
						}
					}
				}
			}

			// Audit custom PAM module .so files
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasSuffix(f, ".so") {
					modulePath := f
					if !strings.HasPrefix(modulePath, "/") {
						// Search in standard security directories
						for _, secDir := range pamSecurityDirs {
							fullPath := filepath.Join(secDir, modulePath)
							if info, err := os.Stat(fullPath); err == nil {
								uid, gid := getFileOwnership(info)
								mode := uint32(info.Mode().Perm())
								if userCtx != nil && userCtx.CanWrite(uid, gid, mode) {
									results = append(results, PAMResult{
										Path:        fullPath,
										Type:        "pam_module_writable",
										RiskLevel:   "CRITICAL",
										Reason:      "PAM module " + modulePath + " referenced in " + entry.Name() + " is writable",
										ExploitHint: "Overwrite " + fullPath + " with a custom malicious shared library",
										IsDangerous: true,
									})
								}
								break
							}
						}
					} else {
						if info, err := os.Stat(modulePath); err == nil {
							uid, gid := getFileOwnership(info)
							mode := uint32(info.Mode().Perm())
							if userCtx != nil && userCtx.CanWrite(uid, gid, mode) {
								results = append(results, PAMResult{
									Path:        modulePath,
									Type:        "pam_module_writable",
									RiskLevel:   "CRITICAL",
									Reason:      "PAM module " + modulePath + " is writable by current user",
									ExploitHint: "Overwrite " + modulePath + " with a malicious shared library",
									IsDangerous: true,
								})
							}
						}
					}
				}
			}
		}
		file.Close()
	}

	return results, nil
}

// Helper function to extract file UID/GID via syscall.Stat_t
func getFileOwnership(info os.FileInfo) (int, int) {
	if sys := info.Sys(); sys != nil {
		if stat, ok := sys.(*syscall.Stat_t); ok {
			return int(stat.Uid), int(stat.Gid)
		}
	}
	// Fallback stats reflect root ownership
	return 0, 0
}
