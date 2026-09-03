package scanners

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SudoTokenResult represents a finding related to active sudo tokens, timestamp tickets, or TTY injection.
type SudoTokenResult struct {
	Vector        string `json:"vector"`
	Path          string `json:"path,omitempty"`
	RiskLevel     string `json:"risk_level"` // CRITICAL, HIGH, MEDIUM
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// ScanSudoTokensAndTTY audits for active sudo ticket reuse, writable sudo directories,
// and TIOCSTI terminal command injection into peer terminals.
func ScanSudoTokensAndTTY() ([]SudoTokenResult, error) {
	var results []SudoTokenResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	// 1. Check for Active Passwordless Sudo Session (Live Sudo Token)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "-n", "true")
	if err := cmd.Run(); err == nil {
		results = append(results, SudoTokenResult{
			Vector:        "Active Sudo Session Token",
			RiskLevel:     "CRITICAL",
			IsDangerous:   true,
			Reason:        "Current user has an active, valid sudo timestamp token. Commands can be run with root privileges without entering a password!",
			ExploitHint:   "sudo /bin/bash (or 'sudo su -') immediately spawns a root shell without authentication",
			Remediation:   "Configure 'Defaults timestamp_timeout=0' in /etc/sudoers to disable ticket caching, or run 'sudo -k' after privileged tasks",
			ComplianceTag: "CIS-Linux-5.3.4 / NIST-AC-2",
		})
	}

	// 2. Audit Sudo Timestamp Directories (/var/run/sudo/ts, /run/sudo/ts)
	tsDirs := []string{"/var/run/sudo/ts", "/run/sudo/ts"}
	for _, tsDir := range tsDirs {
		info, err := os.Stat(tsDir)
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		// Check if directory is writable by us
		if userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
			results = append(results, SudoTokenResult{
				Vector:        "Writable Sudo Timestamp Directory",
				Path:          tsDir,
				RiskLevel:     "CRITICAL",
				IsDangerous:   true,
				Reason:        fmt.Sprintf("Sudo timestamp directory '%s' is writable — forging or modifying ticket timestamps can grant passwordless sudo", tsDir),
				ExploitHint:   fmt.Sprintf("touch -t $(date +%%Y%%m%%d%%H%%M.%%S) %s/%s", tsDir, userCtx.Username),
				Remediation:   fmt.Sprintf("chown root:root %s && chmod 0700 %s", tsDir, tsDir),
				ComplianceTag: "CIS-Linux-5.3.4 / NIST-AC-6",
			})
		}

		// Inspect tickets inside
		entries, err := os.ReadDir(tsDir)
		if err == nil {
			for _, e := range entries {
				ticketPath := filepath.Join(tsDir, e.Name())
				tInfo, tErr := os.Stat(ticketPath)
				if tErr != nil {
					continue
				}
				tStat, tOk := tInfo.Sys().(*syscall.Stat_t)
				if !tOk {
					continue
				}
				if userCtx.CanWrite(int(tStat.Uid), int(tStat.Gid), tStat.Mode) && int(tStat.Uid) != userCtx.UID {
					results = append(results, SudoTokenResult{
						Vector:        "Writable Peer Sudo Ticket",
						Path:          ticketPath,
						RiskLevel:     "CRITICAL",
						IsDangerous:   true,
						Reason:        fmt.Sprintf("Sudo timestamp ticket '%s' belonging to another user is writable", ticketPath),
						Remediation:   fmt.Sprintf("chmod 0600 %s", ticketPath),
						ComplianceTag: "CIS-Linux-5.3.4 / NIST-AC-6",
					})
				}
			}
		}
	}

	// 3. Writable /etc/sudoers.d/ Check
	if info, err := os.Stat("/etc/sudoers.d"); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
				results = append(results, SudoTokenResult{
					Vector:        "Writable /etc/sudoers.d Directory",
					Path:          "/etc/sudoers.d",
					RiskLevel:     "CRITICAL",
					IsDangerous:   true,
					Reason:        "The /etc/sudoers.d directory is writable — dropping a new sudoers file grants instant passwordless root",
					ExploitHint:   fmt.Sprintf("echo '%s ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-pwn && sudo -l", userCtx.Username),
					Remediation:   "chown root:root /etc/sudoers.d && chmod 0750 /etc/sudoers.d",
					ComplianceTag: "CIS-Linux-5.3.1 / NIST-AC-6",
				})
			}
		}
	}

	// 4. TIOCSTI Terminal Command Injection via /dev/pts/
	tiocstiAllowed := true
	if data, err := os.ReadFile("/proc/sys/dev/tiocsti_restrict"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			tiocstiAllowed = false
		}
	}

	if tiocstiAllowed {
		ptsEntries, err := os.ReadDir("/dev/pts")
		if err == nil {
			for _, p := range ptsEntries {
				// We care about numeric TTY nodes (e.g. /dev/pts/0, /dev/pts/1)
				if _, err := strconv.Atoi(p.Name()); err != nil {
					continue
				}

				ptsPath := filepath.Join("/dev/pts", p.Name())
				info, err := os.Stat(ptsPath)
				if err != nil {
					continue
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					continue
				}

				// Check if another user owns this terminal and we can write to it
				if int(stat.Uid) != userCtx.UID && userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
					ownerName := CachedUserName(int(stat.Uid))
					results = append(results, SudoTokenResult{
						Vector:        "Writable Peer Terminal (TIOCSTI Injection)",
						Path:          ptsPath,
						RiskLevel:     "HIGH",
						IsDangerous:   true,
						Reason:        fmt.Sprintf("Peer pseudo-terminal '%s' (owned by %s) is writable and kernel permits TIOCSTI — arbitrary commands can be injected into their active shell session", ptsPath, ownerName),
						ExploitHint:   fmt.Sprintf("perl -e 'require \"sys/ioctl.ph\"; ioctl(STDIN, &TIOCSTI, $_) for split \"\", \"sudo id\\n\";' < %s", ptsPath),
						Remediation:   "sysctl -w dev.tiocsti_restrict=1 && chmod 0620 " + ptsPath,
						ComplianceTag: "CIS-Linux-5.4.1 / NIST-AC-3",
					})
				}
			}
		}
	}

	return results, nil
}
