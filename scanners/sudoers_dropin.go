package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// SudoersDropinResult represents an audit finding for a writable /etc/sudoers.d directory or drop-in file.
type SudoersDropinResult struct {
	Path          string `json:"path"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

// hasSudoersInclude checks if /etc/sudoers includes /etc/sudoers.d.
// Returns true if the directive is present or if /etc/sudoers is unreadable (err on side of reporting).
func hasSudoersInclude(sudoersFile, dropinDir string) bool {
	f, err := os.Open(sudoersFile)
	if err != nil {
		return true // Default safe assumption: include is present
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineCount := 0
	cleanDropin := filepath.Clean(dropinDir)

	for scanner.Scan() && lineCount < 5000 {
		lineCount++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#includedir") && !strings.HasPrefix(line, "#include") {
			continue
		}
		// Match #includedir /etc/sudoers.d or @includedir /etc/sudoers.d
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			directive := fields[0]
			target := filepath.Clean(fields[1])
			if directive == "#includedir" || directive == "@includedir" || directive == "#include" || directive == "@include" {
				if target == cleanDropin || strings.HasPrefix(cleanDropin, target) || strings.HasPrefix(target, cleanDropin) {
					return true
				}
			}
		}
	}
	return false
}

// ScanSudoersDropin audits /etc/sudoers.d and drop-in files for unauthorized write permissions.
func ScanSudoersDropin() ([]SudoersDropinResult, error) {
	return scanSudoersDropinInternal("/etc/sudoers.d", "/etc/sudoers")
}

// scanSudoersDropinInternal allows testing against mock directories.
func scanSudoersDropinInternal(dirPath, sudoersPath string) ([]SudoersDropinResult, error) {
	var results []SudoersDropinResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	dirInfo, err := os.Stat(dirPath)
	if err != nil {
		return results, nil // Sudoers.d does not exist on this system
	}

	included := hasSudoersInclude(sudoersPath, dirPath)

	// 1. Audit directory itself
	if sys := dirInfo.Sys(); sys != nil {
		if stat, ok := sys.(*syscall.Stat_t); ok {
			uid := int(stat.Uid)
			gid := int(stat.Gid)
			mode := uint32(dirInfo.Mode().Perm())

			isWritable := false
			if userCtx.UID != 0 {
				isWritable = userCtx.CanWrite(uid, gid, mode)
			} else {
				isWritable = (mode&syscall.S_IWOTH != 0) || (gid != 0 && (mode&syscall.S_IWGRP != 0))
			}

			if isWritable {
				risk := "CRITICAL"
				reason := fmt.Sprintf("Directory '%s' is writable by current user — unprivileged user can drop custom sudoers rules granting passwordless root access", dirPath)
				if !included {
					risk = "LOW"
					reason = fmt.Sprintf("Directory '%s' is writable by current user, but '%s' does not include it (not currently exploitable)", dirPath, sudoersPath)
				}

				results = append(results, SudoersDropinResult{
					Path:          dirPath,
					RiskLevel:     risk,
					Reason:        reason,
					ExploitHint:   fmt.Sprintf("echo \"%s ALL=(ALL) NOPASSWD: ALL\" > %s/99-pwned && sudo -i", userCtx.Username, dirPath),
					Remediation:   fmt.Sprintf("chown root:root %s && chmod 0750 %s", dirPath, dirPath),
					ComplianceTag: "CIS-Linux-5.3.4 / DISA-STIG-V-230355",
					IsDangerous:   included,
				})
			}
		}
	}

	// 2. Audit files inside directory
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return results, nil
	}

	for _, entry := range entries {
		name := entry.Name()
		// Sudo ignores any file that contains a dot '.' or ends with a tilde '~'
		if strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
			continue
		}

		filePath := filepath.Join(dirPath, name)
		fileInfo, err := entry.Info()
		if err != nil {
			continue
		}

		// Only check regular files
		if !fileInfo.Mode().IsRegular() {
			continue
		}

		if sys := fileInfo.Sys(); sys != nil {
			if stat, ok := sys.(*syscall.Stat_t); ok {
				uid := int(stat.Uid)
				gid := int(stat.Gid)
				mode := uint32(fileInfo.Mode().Perm())

				isWritable := false
				if userCtx.UID != 0 {
					isWritable = userCtx.CanWrite(uid, gid, mode)
				} else {
					isWritable = (mode&syscall.S_IWOTH != 0) || (gid != 0 && (mode&syscall.S_IWGRP != 0))
				}

				if isWritable {
					risk := "CRITICAL"
					reason := fmt.Sprintf("Sudoers drop-in file '%s' is writable by current user — rules can be appended/modified to grant passwordless root", filePath)
					if !included {
						risk = "LOW"
						reason = fmt.Sprintf("Sudoers drop-in file '%s' is writable, but '%s' does not include '%s'", filePath, sudoersPath, dirPath)
					}

					results = append(results, SudoersDropinResult{
						Path:          filePath,
						RiskLevel:     risk,
						Reason:        reason,
						ExploitHint:   fmt.Sprintf("echo \"%s ALL=(ALL) NOPASSWD: ALL\" >> %s && sudo -i", userCtx.Username, filePath),
						Remediation:   fmt.Sprintf("chown root:root %s && chmod 0440 %s", filePath, filePath),
						ComplianceTag: "CIS-Linux-5.3.4 / DISA-STIG-V-230355",
						IsDangerous:   included,
					})
				}
			}
		}
	}

	return results, nil
}
