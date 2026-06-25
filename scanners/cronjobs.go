package scanners

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// CronJobResult matches your main.go expectations
type CronJobResult struct {
	Owner           string
	Schedule        string
	Command         string
	IsRootJob       bool
	IsPrivilegedJob bool // Added back to fix main.go errors
	IsDangerous     bool
	Reason          string
	CronFile        string
}

// ScanCronJobs analyzes time-based execution for vulnerabilities
func ScanCronJobs() ([]CronJobResult, error) {
	var results []CronJobResult
	currUser, _ := user.Current()
	uid, _ := strconv.Atoi(currUser.Uid)

	cronPaths := []string{"/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"}

	for _, path := range cronPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
			entries, _ := os.ReadDir(path)
			for _, entry := range entries {
				if !entry.IsDir() {
					results = append(results, parseFile(filepath.Join(path, entry.Name()), uid)...)
				}
			}
		} else {
			results = append(results, parseFile(path, uid)...)
		}
	}
	return results, nil
}

func parseFile(filePath string, currentUID int) []CronJobResult {
	var results []CronJobResult
	file, err := os.Open(filePath)
	if err != nil {
		return results
	}
	defer file.Close()

	// System maintenance cron jobs to skip (low priority)
	skipPatterns := []string{
		"run-parts", "anacron", "popularity-contest", "checkarray",
		"ua-reboot", "ubuntu-advantage", "apt", "dpkg", "update-notifier",
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// A1: Detect dangerous environment variable definitions in crontab files
		// instead of silently skipping them. LD_PRELOAD, LD_LIBRARY_PATH, PATH, SHELL
		// in a writable crontab can be abused to hijack root cron job execution.
		if strings.Contains(line, "=") {
			dangerousEnvVars := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "SHELL"}
			parts := strings.SplitN(line, "=", 2)
			envKey := strings.TrimSpace(parts[0])
			envVal := ""
			if len(parts) > 1 {
				envVal = strings.TrimSpace(parts[1])
			}
			for _, dangerous := range dangerousEnvVars {
				if strings.EqualFold(envKey, dangerous) {
					// Check if the crontab file itself is writable by the current user
					if info, statErr := os.Stat(filePath); statErr == nil {
						if stat, ok := info.Sys().(*syscall.Stat_t); ok {
							isWritable := (info.Mode()&0002 != 0) ||
								(int(stat.Uid) == currentUID && info.Mode()&0200 != 0)
							if isWritable {
								results = append(results, CronJobResult{
									Owner:       "root",
									Schedule:    "env",
									Command:     line,
									IsRootJob:   true,
									IsDangerous: true,
									Reason:      fmt.Sprintf("Writable crontab sets dangerous env var %s=%s — can hijack root job execution", envKey, envVal),
									CronFile:    filePath,
								})
							}
						}
					}
					break
				}
			}
			continue
		}

		// Skip system maintenance cron jobs
		shouldSkip := false
		for _, pattern := range skipPatterns {
			if strings.Contains(line, pattern) {
				shouldSkip = true
				break
			}
		}
		if shouldSkip {
			continue
		}

		res := analyzeCronLine(line, filePath, currentUID)
		if res != nil {
			results = append(results, *res)
		}
	}
	return results
}

func analyzeCronLine(line string, filePath string, currentUID int) *CronJobResult {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return nil
	}

	var jobOwner, command string
	if _, err := user.Lookup(fields[5]); err == nil {
		jobOwner = fields[5]
		command = strings.Join(fields[6:], " ")
	} else {
		jobOwner = "root"
		command = strings.Join(fields[5:], " ")
	}

	isRoot := (jobOwner == "root" || jobOwner == "0")
	isDangerous := false
	reason := ""

	// Check for writable command (Critical finding)
	cmdParts := strings.Fields(command)
	if len(cmdParts) > 0 {
		execPath := cmdParts[0]
		if info, err := os.Stat(execPath); err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && ((info.Mode()&0002 != 0) || (int(stat.Uid) == currentUID && info.Mode()&0200 != 0)) {
				isDangerous = true
				reason = "Cron executes a WRITABLE binary"
			}
		}
	}

	// Check for Wildcard Injection vectors (Critical finding)
	vulnerableCmds := []string{"tar", "chown", "chmod", "rsync", "7z", "zip", "rar", "7zip"}
	for _, vulnerableCmd := range vulnerableCmds {
		// Look for command followed by space and a wildcard
		pattern := vulnerableCmd + " "
		if strings.Contains(command, pattern) && strings.Contains(command, "*") {
			isDangerous = true
			reason = "Cron executes '" + vulnerableCmd + "' with wildcard (*) - vulnerable to Wildcard Injection"
			break
		}
	}

	if isRoot || isDangerous {
		return &CronJobResult{
			Owner:           jobOwner,
			Schedule:        strings.Join(fields[0:5], " "),
			Command:         command,
			IsRootJob:       isRoot,
			IsPrivilegedJob: isRoot, // Mapping for main.go compatibility
			IsDangerous:     isDangerous,
			Reason:          reason,
			CronFile:        filePath,
		}
	}
	return nil
}

// ScanAtJobs scans the at job spool for writable job files (A5).
// Writable at jobs can be modified to execute arbitrary commands as the job owner.
func ScanAtJobs() ([]WriteableResult, error) {
	var results []WriteableResult
	ctx := GetUserContext()

	atPaths := []string{"/var/spool/at", "/var/spool/cron/atjobs", "/var/spool/at/spool"}
	for _, dir := range atPaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			if ctx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) && int(stat.Uid) != ctx.UID {
				results = append(results, WriteableResult{
					Path:            path,
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: false,
					IsExecutable:    info.Mode()&0111 != 0,
					IsDangerous:     true,
					Type:            "Writable at Job",
					RiskLevel:       "CRITICAL",
					Reason:          "Scheduled at job file is writable. Modify to execute arbitrary commands as the job owner.",
				})
			}
		}
	}
	return results, nil
}

// ScanAnacronWritability checks if /etc/anacrontab is writable (B4).
// Anacrontab defines delayed root jobs — writable file allows code execution as root.
func ScanAnacronWritability() ([]WriteableResult, error) {
	var results []WriteableResult
	ctx := GetUserContext()

	info, err := os.Stat("/etc/anacrontab")
	if err != nil {
		return results, nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return results, nil
	}
	if ctx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
		results = append(results, WriteableResult{
			Path:            "/etc/anacrontab",
			OwnerUID:        int(stat.Uid),
			CurrentUserOwns: ctx.UID == int(stat.Uid),
			IsExecutable:    false,
			IsDangerous:     true,
			Type:            "Writable Anacrontab",
			RiskLevel:       "CRITICAL",
			Reason:          "Anacrontab is writable. Inject or modify delayed root jobs for privilege escalation.",
		})
	}
	return results, nil
}

// SystemdTimerResult holds findings for systemd unit files
type SystemdTimerResult struct {
	Path        string
	IsDangerous bool
	Reason      string
}

// ScanSystemdTimers checks for writeable systemd timer or service files this might lead direct root
func ScanSystemdTimers() ([]SystemdTimerResult, error) {
	var results []SystemdTimerResult
	currUser, _ := user.Current()
	uid, _ := strconv.Atoi(currUser.Uid)

	// Get user groups for accurate permission checking for lateral movement
	gidStrings, _ := currUser.GroupIds()
	userGids := make(map[int]bool)
	for _, g := range gidStrings {
		id, _ := strconv.Atoi(g)
		userGids[id] = true
	}

	systemdPaths := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}

	for _, path := range systemdPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}

		filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			// We care about .timer and .service files
			if !d.IsDir() && (strings.HasSuffix(d.Name(), ".timer") || strings.HasSuffix(d.Name(), ".service")) {

				// Helper to check if a REAL file (not symlink) is writable by us
				checkWriteable := func(fpath string) (bool, string) {
					info, err := os.Stat(fpath) // Stat follows symlinks — gives us target perms
					if err != nil {
						return false, ""
					}
					stat, ok := info.Sys().(*syscall.Stat_t)
					if !ok {
						return false, ""
					}
					if info.Mode()&0002 != 0 {
						return true, "world-writeable"
					}
					if int(stat.Uid) == uid && info.Mode()&0200 != 0 {
						return true, "owner-writeable"
					}
					if userGids[int(stat.Gid)] && info.Mode()&0020 != 0 {
						return true, "group-writeable"
					}
					return false, ""
				}

				info, err := d.Info()
				if err != nil {
					return nil
				}

				isSymlink := (info.Mode() & os.ModeSymlink) != 0

				if isSymlink {
					// IMPORTANT: Linux symlink permission bits are ALWAYS 0777 (lrwxrwxrwx).
					// Checking Lstat on a symlink will ALWAYS report world-writable — this is a
					// kernel invariant and a classic false positive source.
					// Instead: check if the symlink TARGET is writable (that's the real risk).
					targetPath, err := filepath.EvalSymlinks(p)
					if err == nil && targetPath != p && targetPath != "/dev/null" {
						if writable, reason := checkWriteable(targetPath); writable {
							results = append(results, SystemdTimerResult{
								Path:        p,
								IsDangerous: true,
								Reason:      fmt.Sprintf("Systemd symlink target is writable: %s (%s)", targetPath, reason),
							})
						}
					}
				} else {
					// Real file — check directly
					if writable, reason := checkWriteable(p); writable {
						results = append(results, SystemdTimerResult{
							Path:        p,
							IsDangerous: true,
							Reason:      fmt.Sprintf("Writable systemd unit file (%s)", reason),
						})
					}
				}

				// Deep Service Analysis (Service Writeability Tracking)
				// Even if the unit file is read-only, the script it executes might be writable!
				if file, err := os.Open(p); err == nil {
					defer file.Close()
					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if strings.HasPrefix(line, "ExecStart=") || strings.HasPrefix(line, "ExecStartPre=") || strings.HasPrefix(line, "ExecStartPost=") {
							// Extract the command
							cmdLine := strings.TrimPrefix(line, "ExecStart=")
							cmdLine = strings.TrimPrefix(cmdLine, "ExecStartPre=")
							cmdLine = strings.TrimPrefix(cmdLine, "ExecStartPost=")
							
							// Strip systemd modifiers (- ignore error, @ change argv0, + full privs, ! capabilities)
							cmdLine = strings.TrimLeft(cmdLine, "-@+!")
							fields := strings.Fields(cmdLine)
							if len(fields) > 0 {
								execPath := fields[0]
								// Fast check if it's an absolute path
								if strings.HasPrefix(execPath, "/") {
									if writable, reason := checkWriteable(execPath); writable {
										results = append(results, SystemdTimerResult{
											Path:        p,
											IsDangerous: true,
											Reason:      fmt.Sprintf("Service executes a writable script/binary: %s (%s)", execPath, reason),
										})
									}
								}
							}
						}
					}
				}
			}
			return nil
		})
	}

	return results, nil
}
