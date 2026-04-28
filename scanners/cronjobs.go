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
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "=") {
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
	for _, vulnerableCmd := range []string{"tar", "chown", "chmod", "rsync"} {
		if strings.Contains(command, vulnerableCmd) && strings.Contains(command, "*") {
			isDangerous = true
			reason = "Cron executes command with wildcard (*) - vulnerable to Wildcard Injection"
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

// ScanAtJobs for backward compatibility with your main.go
func ScanAtJobs() ([]string, error) {
	return []string{}, nil
}

// SystemdTimerResult holds findings for systemd unit files
type SystemdTimerResult struct {
	Path        string
	IsDangerous bool
	Reason      string
}

// ScanSystemdTimers checks for writeable systemd timer or service files
func ScanSystemdTimers() ([]SystemdTimerResult, error) {
	var results []SystemdTimerResult
	currUser, _ := user.Current()
	uid, _ := strconv.Atoi(currUser.Uid)

	// Get user groups for accurate permission checking
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
				
				// Helper to check if a file/link is writeable
				checkWriteable := func(fpath string, isLink bool) (bool, string) {
					var info os.FileInfo
					var err error
					if isLink {
						info, err = os.Lstat(fpath)
					} else {
						info, err = os.Stat(fpath)
					}
					
					if err != nil {
						return false, ""
					}

					stat, ok := info.Sys().(*syscall.Stat_t)
					if !ok {
						return false, ""
					}

					// 1. World Writeable
					if info.Mode()&0002 != 0 {
						return true, "world-writeable"
					}
					// 2. Owner Writeable
					if int(stat.Uid) == uid && info.Mode()&0200 != 0 {
						return true, "owner-writeable"
					}
					// 3. Group Writeable
					if userGids[int(stat.Gid)] && info.Mode()&0020 != 0 {
						return true, "group-writeable"
					}

					return false, ""
				}

				// Check the link/file itself
				info, err := d.Info()
				if err != nil {
					return nil
				}

				isSymlink := (info.Mode()&os.ModeSymlink != 0)
				writeable, reason := checkWriteable(p, isSymlink)

				if writeable {
					msg := "Writeable systemd unit file"
					if isSymlink {
						msg = "Writeable systemd symlink"
					}
					results = append(results, SystemdTimerResult{
						Path:        p,
						IsDangerous: true,
						Reason:      fmt.Sprintf("%s (%s)", msg, reason),
					})
				} else if isSymlink {
					// If the link itself isn't writeable, check the target
					targetPath, err := filepath.EvalSymlinks(p)
					if err == nil && targetPath != p {
						writeableTarget, reasonTarget := checkWriteable(targetPath, false)
						if writeableTarget {
							results = append(results, SystemdTimerResult{
								Path:        p,
								IsDangerous: true,
								Reason:      fmt.Sprintf("Systemd unit points to a writeable target: %s (%s)", targetPath, reasonTarget),
							})
						}
					}
				}
			}
			return nil
		})
	}

	return results, nil
}
