package scanners

import (
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type WriteableResult struct {
	Path            string
	Owner           string
	OwnerUID        int
	CurrentUserOwns bool
	IsExecutable    bool
	IsDangerous     bool
	Type            string // Writable (Own), Writable (Root), Writable (Other User), SUID Writable
	RiskLevel       string // CRITICAL, HIGH, MEDIUM, LOW
}

func ScanWriteable(root string) ([]WriteableResult, error) {
	var results []WriteableResult

	// 1. Setup User Context (Once)
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}
	uid, _ := strconv.Atoi(currentUser.Uid)
	gidStrings, _ := currentUser.GroupIds()
	userGids := make(map[int]bool)
	for _, g := range gidStrings {
		id, _ := strconv.Atoi(g)
		userGids[id] = true
	}

	// 2. Define Dangerous Targets
	dangerousBinaries := []string{"bash", "python", "perl", "vim", "find", "cp", "mv"}
	skipDirs := []string{
		"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/snap",
		"/usr/lib/python", "/usr/share", "/var/lib/apt", "/usr/src", "/lib/modules",
		"/home/web/.nvm",
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Noise Reduction
		if d.IsDir() {
			for _, skip := range skipDirs {
				if path == skip {
					return filepath.SkipDir
				}
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}

		// 3. Check Write Permission (Native syscall constants)
		mode := stat.Mode
		canWrite := false

		if uid == int(stat.Uid) && (mode&syscall.S_IWUSR != 0) {
			canWrite = true
		} else if userGids[int(stat.Gid)] && (mode&syscall.S_IWGRP != 0) {
			canWrite = true
		} else if mode&syscall.S_IWOTH != 0 {
			canWrite = true
		}

		if canWrite {
			fileName := filepath.Base(path)
			isSUID := (info.Mode()&os.ModeSetuid != 0)
			isExecutable := (info.Mode()&0111 != 0)
			isRootOwned := (stat.Uid == 0)
			currentUserOwns := (uid == int(stat.Uid))
			isOtherUserOwned := !currentUserOwns && !isRootOwned && stat.Uid != 0

			// --- Case 1: Writable SUID (Always dangerous) ---
			if isSUID {
				results = append(results, WriteableResult{
					Path:            path,
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: currentUserOwns,
					IsExecutable:    isExecutable,
					IsDangerous:     true,
					Type:            "SUID Writable",
					RiskLevel:       "CRITICAL",
				})
			}

			// --- Case 2: Writable file owned by OTHER USER (high risk!) ---
			if isOtherUserOwned {
				isDangerous := false
				riskLevel := "MEDIUM"

				// Executable writable by non-owner = HIGH RISK
				if isExecutable {
					isDangerous = true
					riskLevel = "HIGH"
				}

				// Check if it's a known dangerous binary
				lowerFileName := strings.ToLower(fileName)
				for _, bin := range dangerousBinaries {
					if strings.Contains(lowerFileName, bin) {
						isDangerous = true
						riskLevel = "HIGH"
						break
					}
				}

				results = append(results, WriteableResult{
					Path:            path,
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: false,
					IsExecutable:    isExecutable,
					IsDangerous:     isDangerous,
					Type:            "Writable (Other User)",
					RiskLevel:       riskLevel,
				})
			}

			// --- Case 3: Writable file owned by ROOT (privilege escalation vector) ---
			if isRootOwned && !isSUID && !currentUserOwns {
				isDangerous := false
				riskLevel := "MEDIUM"

				// Root-owned executable writable by user = CRITICAL
				if isExecutable {
					isDangerous = true
					riskLevel = "CRITICAL"
				}

				// Check for sensitive root files
				sensitiveFiles := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab"}
				for _, sf := range sensitiveFiles {
					if path == sf {
						isDangerous = true
						riskLevel = "CRITICAL"
					}
				}

				// Check for dangerous binaries owned by root
				lowerFileName := strings.ToLower(fileName)
				for _, bin := range dangerousBinaries {
					if strings.Contains(lowerFileName, bin) && isExecutable {
						isDangerous = true
						riskLevel = "HIGH"
						break
					}
				}

				if isDangerous {
					results = append(results, WriteableResult{
						Path:            path,
						OwnerUID:        0,
						CurrentUserOwns: false,
						IsExecutable:    isExecutable,
						IsDangerous:     true,
						Type:            "Writable (Root)",
						RiskLevel:       riskLevel,
					})
				}
			}
		}
		return nil
	})
	return results, err
}
