package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// AtJobResult represents an audit finding for at daemon access, spool writability, or job tampering.
type AtJobResult struct {
	Path          string `json:"path"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var defaultAtSpoolDirs = []string{
	"/var/spool/cron/atjobs",
	"/var/spool/at",
	"/var/spool/at/spool",
}

var atJobPrivilegedThreshold = 1000

// isAtdRunning checks if atd process is currently active.
func isAtdRunning() bool {
	snap, err := GetProcSnapshot()
	if err != nil {
		// Fallback: check /proc directly for atd
		entries, rErr := os.ReadDir("/proc")
		if rErr != nil {
			return false
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			commBytes, cErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if cErr == nil && strings.TrimSpace(string(commBytes)) == "atd" {
				return true
			}
		}
		return false
	}

	for _, proc := range snap.Processes {
		if proc.Comm == "atd" {
			return true
		}
		fields := strings.Fields(proc.Cmdline)
		if len(fields) > 0 && (fields[0] == "atd" || filepath.Base(fields[0]) == "atd") {
			return true
		}
	}
	return false
}

// ScanAtJobInjection audits the at daemon spool directories, access lists, and scheduled job files.
func ScanAtJobInjection() ([]AtJobResult, error) {
	return scanAtJobsInternal(isAtdRunning(), defaultAtSpoolDirs, "/etc/at.allow", "/etc/at.deny")
}

func scanAtJobsInternal(atdActive bool, spoolDirs []string, atAllowPath, atDenyPath string) ([]AtJobResult, error) {
	var results []AtJobResult

	// Critical safeguard: If atd is not running, scheduled jobs never execute -> exit early
	if !atdActive {
		return results, nil
	}

	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	// 1. Audit Spool Directories & Existing Jobs
	for _, spoolDir := range spoolDirs {
		dirInfo, err := os.Stat(spoolDir)
		if err != nil {
			continue
		}

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
					results = append(results, AtJobResult{
						Path:          spoolDir,
						RiskLevel:     "CRITICAL",
						Reason:        fmt.Sprintf("at daemon spool directory '%s' is writable by current user — attacker can schedule arbitrary jobs executing as root", spoolDir),
						ExploitHint:   fmt.Sprintf("echo 'chmod +s /bin/bash' | at now + 1 minute"),
						Remediation:   fmt.Sprintf("chown daemon:daemon %s && chmod 0770 %s", spoolDir, spoolDir),
						ComplianceTag: "CIS-Linux-5.1.8",
						IsDangerous:   true,
					})
				}
			}
		}

		// Inspect existing job files inside spool
		entries, err := os.ReadDir(spoolDir)
		if err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, ".") || name == "spool" {
					continue
				}
				jobPath := filepath.Join(spoolDir, name)
				info, iErr := entry.Info()
				if iErr != nil || !info.Mode().IsRegular() {
					continue
				}

				if sys := info.Sys(); sys != nil {
					if stat, ok := sys.(*syscall.Stat_t); ok {
						jobUID := int(stat.Uid)
						jobGID := int(stat.Gid)
						mode := uint32(info.Mode().Perm())

						// Check if job is owned by root/privileged and writable by current user
						if (jobUID == 0 || jobUID < atJobPrivilegedThreshold) && userCtx.CanWrite(jobUID, jobGID, mode) && jobUID != userCtx.UID {
							results = append(results, AtJobResult{
								Path:          jobPath,
								RiskLevel:     "CRITICAL",
								Reason:        fmt.Sprintf("Scheduled at job file '%s' is owned by UID %d and writable by current user — arbitrary command injection into scheduled task", jobPath, jobUID),
								ExploitHint:   fmt.Sprintf("echo 'chmod +s /bin/bash' >> %s", jobPath),
								Remediation:   fmt.Sprintf("chown root:root %s && chmod 0600 %s", jobPath, jobPath),
								ComplianceTag: "CIS-Linux-5.1.8",
								IsDangerous:   true,
							})
						}
					}
				}
			}
		}
	}

	// 2. Audit Access Control: at.allow and at.deny
	canSchedule := false
	allowExists := false

	if allowBytes, err := os.ReadFile(atAllowPath); err == nil {
		allowExists = true
		scanner := bufio.NewScanner(strings.NewReader(string(allowBytes)))
		for scanner.Scan() {
			user := strings.TrimSpace(scanner.Text())
			if user == userCtx.Username {
				canSchedule = true
				break
			}
		}
	}

	if !allowExists {
		if denyBytes, err := os.ReadFile(atDenyPath); err == nil {
			inDeny := false
			scanner := bufio.NewScanner(strings.NewReader(string(denyBytes)))
			for scanner.Scan() {
				user := strings.TrimSpace(scanner.Text())
				if user == userCtx.Username {
					inDeny = true
					break
				}
			}
			if !inDeny {
				canSchedule = true
			}
		}
	}

	if canSchedule && len(results) == 0 && userCtx.UID != 0 {
		reportPath := atAllowPath
		if !allowExists {
			reportPath = atDenyPath
		}
		results = append(results, AtJobResult{
			Path:          reportPath,
			RiskLevel:     "MEDIUM",
			Reason:        fmt.Sprintf("User '%s' is permitted to schedule jobs via 'at' daemon. While jobs execute under user privileges, this enables deferred scheduled execution", userCtx.Username),
			ExploitHint:   "echo '/path/to/script.sh' | at now + 1 minute",
			Remediation:   fmt.Sprintf("Restrict access via %s or %s", atAllowPath, atDenyPath),
			ComplianceTag: "CIS-Linux-5.1.8",
			IsDangerous:   false,
		})
	}

	return results, nil
}
