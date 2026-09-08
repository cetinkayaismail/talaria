package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ShellRCResult represents an audit finding for a writable shell initialization or environment file.
type ShellRCResult struct {
	Path          string `json:"path"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

// resolveRootHome parses /etc/passwd to find UID 0 user's home directory, defaulting to /root.
func resolveRootHome(passwdPath string) string {
	f, err := os.Open(passwdPath)
	if err != nil {
		return "/root"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		// username:password:uid:gid:gecos:home:shell
		if len(parts) >= 6 && parts[2] == "0" {
			if parts[5] != "" {
				return filepath.Clean(parts[5])
			}
		}
	}
	return "/root"
}

// ScanShellRC audits root shell startup scripts and system-wide environment files for unauthorized writability.
func ScanShellRC() ([]ShellRCResult, error) {
	return scanShellRCInternal("/etc/passwd", "")
}

func scanShellRCInternal(passwdPath string, customRootHome string) ([]ShellRCResult, error) {
	var results []ShellRCResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	rootHome := customRootHome
	if rootHome == "" {
		rootHome = resolveRootHome(passwdPath)
	}

	type targetSpec struct {
		path      string
		isRoot    bool
		isCreatableCheck bool
	}

	targets := []targetSpec{
		// Root personal shell startup files
		{path: filepath.Join(rootHome, ".bashrc"), isRoot: true, isCreatableCheck: true},
		{path: filepath.Join(rootHome, ".bash_profile"), isRoot: true, isCreatableCheck: false},
		{path: filepath.Join(rootHome, ".profile"), isRoot: true, isCreatableCheck: false},
		{path: filepath.Join(rootHome, ".bash_login"), isRoot: true, isCreatableCheck: false},
		{path: filepath.Join(rootHome, ".zshrc"), isRoot: true, isCreatableCheck: false},

		// System-wide shell startup and environment files
		{path: "/etc/bash.bashrc", isRoot: false, isCreatableCheck: false},
		{path: "/etc/profile", isRoot: false, isCreatableCheck: false},
		{path: "/etc/environment", isRoot: false, isCreatableCheck: false},
	}

	checkedDirs := make(map[string]bool)

	for _, target := range targets {
		lstat, err := os.Lstat(target.path)
		if err != nil {
			// Target file does not exist. If it is creatableCheck and parent directory is writable:
			if target.isCreatableCheck {
				parentDir := filepath.Dir(target.path)
				if !checkedDirs[parentDir] {
					checkedDirs[parentDir] = true
					if pInfo, pErr := os.Stat(parentDir); pErr == nil {
						if sys := pInfo.Sys(); sys != nil {
							if stat, ok := sys.(*syscall.Stat_t); ok {
								uid := int(stat.Uid)
								gid := int(stat.Gid)
								mode := uint32(pInfo.Mode().Perm())

								canCreate := false
								if userCtx.UID != 0 {
									canCreate = userCtx.CanWrite(uid, gid, mode)
								} else {
									canCreate = (mode&syscall.S_IWOTH != 0) || (gid != 0 && (mode&syscall.S_IWGRP != 0))
								}

								if canCreate {
									results = append(results, ShellRCResult{
										Path:          target.path,
										RiskLevel:     "CRITICAL",
										Reason:        fmt.Sprintf("Root initialization file '%s' does not exist but directory '%s' is writable — attacker can create malicious startup script", target.path, parentDir),
										ExploitHint:   fmt.Sprintf("echo 'chmod +s /bin/bash' > %s", target.path),
										Remediation:   fmt.Sprintf("chmod 0700 %s", parentDir),
										ComplianceTag: "CIS-Linux-5.4.4",
										IsDangerous:   true,
									})
								}
							}
						}
					}
				}
			}
			continue
		}

		resolvedPath := target.path
		// Handle symlinks
		if lstat.Mode()&os.ModeSymlink != 0 {
			targetLink, evalErr := filepath.EvalSymlinks(target.path)
			if evalErr != nil {
				continue
			}
			// Skip /dev/null or non-regular files
			if targetLink == "/dev/null" || strings.HasPrefix(targetLink, "/dev/") {
				continue
			}
			resolvedPath = targetLink
		}

		info, err := os.Stat(resolvedPath)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}

		if sys := info.Sys(); sys != nil {
			if stat, ok := sys.(*syscall.Stat_t); ok {
				uid := int(stat.Uid)
				gid := int(stat.Gid)
				mode := uint32(info.Mode().Perm())

				isWritable := false
				if userCtx.UID != 0 {
					isWritable = userCtx.CanWrite(uid, gid, mode)
				} else {
					isWritable = (mode&syscall.S_IWOTH != 0) || (gid != 0 && (mode&syscall.S_IWGRP != 0))
				}

				if isWritable {
					risk := "HIGH"
					reason := fmt.Sprintf("System startup file '%s' is writable by current user — executes commands on user or administrator interactive shell sessions", resolvedPath)
					exploit := fmt.Sprintf("echo 'echo \"hacked\"' >> %s", resolvedPath)

					if target.isRoot {
						risk = "CRITICAL"
						reason = fmt.Sprintf("Root shell startup script '%s' is writable by current user — payload executes as root on next root interactive shell or su/sudo session", resolvedPath)
						exploit = fmt.Sprintf("echo 'chmod +s /bin/bash' >> %s", resolvedPath)
					} else if target.path == "/etc/environment" {
						risk = "HIGH"
						reason = "System-wide /etc/environment file is writable — can inject malicious environment variables (e.g., PATH manipulation or LD_PRELOAD) during login"
						exploit = fmt.Sprintf("echo 'PATH=/tmp/evil:$PATH' >> %s", resolvedPath)
					}

					results = append(results, ShellRCResult{
						Path:          resolvedPath,
						RiskLevel:     risk,
						Reason:        reason,
						ExploitHint:   exploit,
						Remediation:   fmt.Sprintf("chown root:root %s && chmod 0644 %s", resolvedPath, resolvedPath),
						ComplianceTag: "CIS-Linux-5.4.4 / DISA-STIG-V-230356",
						IsDangerous:   true,
					})
				}
			}
		}
	}

	return results, nil
}
