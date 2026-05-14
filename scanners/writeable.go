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
	Reason          string
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

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Noise Reduction using global exclusion list
		if d.IsDir() {
			if ShouldIgnore(path) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip Symlinks
		if d.Type()&os.ModeSymlink != 0 {
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

		// 3. Check Write Permission
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

			// --- Case 1: Writable SUID ---
			if isSUID {
				results = append(results, WriteableResult{
					Path:            path,
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: currentUserOwns,
					IsExecutable:    isExecutable,
					IsDangerous:     true,
					Type:            "SUID Writable",
					RiskLevel:       "CRITICAL",
					Reason:          "SUID binary is writable. Attackers can overwrite it to gain immediate root access.",
				})
			}

			// --- Case 2: Writable file owned by OTHER USER ---
			if isOtherUserOwned {
				isDangerous := false
				riskLevel := "MEDIUM"

				if isExecutable {
					isDangerous = true
					riskLevel = "HIGH"
				}

				lowerFileName := strings.ToLower(fileName)
				for _, bin := range dangerousBinaries {
					if strings.Contains(lowerFileName, bin) {
						isDangerous = true
						riskLevel = "HIGH"
						break
					}
				}

				reason := "Writable file owned by another user. Can be modified for lateral movement."
				if isExecutable {
					reason = "Writable executable owned by another user. High risk of lateral movement."
				}

				results = append(results, WriteableResult{
					Path:            path,
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: false,
					IsExecutable:    isExecutable,
					IsDangerous:     isDangerous,
					Type:            "Writable (Other User)",
					RiskLevel:       riskLevel,
					Reason:          reason,
				})
			}

			// --- Case 3: Writable file owned by ROOT ---
			if isRootOwned && !isSUID && !currentUserOwns {
				isDangerous := false
				riskLevel := "MEDIUM"

				if isExecutable {
					isDangerous = true
					riskLevel = "CRITICAL"
				}

				sensitiveFiles := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab", "/etc/hosts"}
				for _, sf := range sensitiveFiles {
					if path == sf {
						isDangerous = true
						riskLevel = "CRITICAL"
					}
				}
				if strings.HasPrefix(path, "/etc/sudoers.d/") {
					isDangerous = true
					riskLevel = "CRITICAL"
				}

				lowerFileName := strings.ToLower(fileName)
				for _, bin := range dangerousBinaries {
					if strings.Contains(lowerFileName, bin) && isExecutable {
						isDangerous = true
						riskLevel = "HIGH"
						break
					}
				}

				if isDangerous {
					reason := "Root-owned file is writable. Can be abused for privilege escalation."
					if isExecutable {
						reason = "Root-owned executable is writable. Critical privilege escalation vector."
					} else if riskLevel == "CRITICAL" {
						reason = "Critical system file is world-writable. High risk of system compromise."
					}

					results = append(results, WriteableResult{
						Path:            path,
						OwnerUID:        0,
						CurrentUserOwns: false,
						IsExecutable:    isExecutable,
						IsDangerous:     true,
						Type:            "Writable (Root)",
						RiskLevel:       riskLevel,
						Reason:          reason,
					})
				}
			}
		}
		return nil
	})
	return results, err
}

// ScanSystemdGenerators checks for writeable directories in systemd generator paths.
func ScanSystemdGenerators() ([]WriteableResult, error) {
	var results []WriteableResult
	generatorPaths := []string{
		"/lib/systemd/system-generators",
		"/usr/lib/systemd/system-generators",
		"/etc/systemd/system-generators",
		"/run/systemd/system-generators",
		"/lib/systemd/user-generators",
		"/usr/lib/systemd/user-generators",
		"/etc/systemd/user-generators",
		"/run/systemd/user-generators",
	}

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

	for _, path := range generatorPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue // Path doesn't exist or not accessible
		}

		if !info.IsDir() {
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		// Check Write Permission
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
			results = append(results, WriteableResult{
				Path:            path,
				OwnerUID:        int(stat.Uid),
				CurrentUserOwns: (uid == int(stat.Uid)),
				IsExecutable:    true,
				IsDangerous:     true,
				Type:            "Systemd Generator Writable",
				RiskLevel:       "CRITICAL",
				Reason:          "Systemd generator directory is writable. Attackers can plant a script to be executed as root.",
			})
		}
	}

	return results, nil
}
