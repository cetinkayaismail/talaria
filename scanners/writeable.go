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
			// C1: Skip current-user-owned files in temp directories (noise reduction).
			// Root-owned or other-user-owned writable files in /tmp are kept — they can be
			// real vectors (race conditions, symlink attacks).
			if uid == int(stat.Uid) {
				for _, tempDir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
					if strings.HasPrefix(path, tempDir+"/") {
						return nil
					}
				}
			}

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

// ScanWritableServices checks for writable systemd service unit files in /etc/systemd/system
func ScanWritableServices() ([]WriteableResult, error) {
	var results []WriteableResult

	currentUser, err := user.Current()
	if err != nil {
		return results, err
	}
	uid, _ := strconv.Atoi(currentUser.Uid)

	gidStrings, _ := currentUser.GroupIds()
	userGids := make(map[int]bool)
	for _, g := range gidStrings {
		id, _ := strconv.Atoi(g)
		userGids[id] = true
	}

	checkDir := func(root string) {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			// Only check .service files
			if !strings.HasSuffix(path, ".service") {
				return nil
			}
			// Skip symlinks — most entries in /etc/systemd/system/ are symlinks
			// to /usr/lib/systemd/system/ created by 'systemctl enable'.
			// Symlinks always show as lrwxrwxrwx which causes false positives.
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
			canWrite := false
			if uid == int(stat.Uid) && (stat.Mode&syscall.S_IWUSR != 0) {
				canWrite = true
			} else if userGids[int(stat.Gid)] && (stat.Mode&syscall.S_IWGRP != 0) {
				canWrite = true
			} else if stat.Mode&syscall.S_IWOTH != 0 {
				canWrite = true
			}
			if canWrite {
				results = append(results, WriteableResult{
					Path:            path,
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: (uid == int(stat.Uid)),
					IsExecutable:    false,
					IsDangerous:     true,
					Type:            "Writable Systemd Service",
					RiskLevel:       "CRITICAL",
					Reason:          "Systemd service unit file is writable. Modify ExecStart to execute code as root on restart.",
				})
			}
			return nil
		})
	}

	// Check /etc/systemd/system for writable service files
	if _, err := os.Stat("/etc/systemd/system"); err == nil {
		checkDir("/etc/systemd/system")
	}

	// Check /etc/systemd/system/*.d/ override directories
	sysdDirs, _ := filepath.Glob("/etc/systemd/system/*.d")
	for _, d := range sysdDirs {
		checkDir(d)
	}

	return results, nil
}

// ScanUdevRules checks for writable files/directories in udev rules paths.
func ScanUdevRules() ([]WriteableResult, error) {
	var results []WriteableResult
	udevPaths := []string{
		"/etc/udev/rules.d",
		"/lib/udev/rules.d",
		"/usr/lib/udev/rules.d",
		"/run/udev/rules.d",
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

	for _, rootPath := range udevPaths {
		if _, err := os.Stat(rootPath); err != nil {
			continue
		}

		filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
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
				typeName := "Udev Rule Writable"
				reason := "Udev rule file is writable. Attackers can inject a RUN command to execute code as root when a device is plugged in."
				if d.IsDir() {
					typeName = "Udev Rules Directory Writable"
					reason = "Udev rules directory is writable. Attackers can create a new rule file to execute code as root."
				}

				results = append(results, WriteableResult{
					Path:            path,
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: (uid == int(stat.Uid)),
					IsExecutable:    false,
					IsDangerous:     true,
					Type:            typeName,
					RiskLevel:       "CRITICAL",
					Reason:          reason,
				})
			}
			return nil
		})
	}

	return results, nil
}

// ScanMotdProfiledHijack checks for writable files/directories in profile.d and update-motd.d paths, and /etc/profile itself.
func ScanMotdProfiledHijack() ([]WriteableResult, error) {
	var results []WriteableResult
	targets := []struct {
		path        string
		dirType     string
		fileType    string
		dirReason   string
		fileReason  string
	}{
		{
			path:       "/etc/profile.d",
			dirType:    "Writable profile.d Directory",
			fileType:   "Writable profile.d Script",
			dirReason:  "The profile.d directory is writable. Attackers can plant a new script to execute automatically when any user logs in.",
			fileReason: "A profile.d script is writable. Attackers can modify it to execute malicious commands when any user logs in.",
		},
		{
			path:       "/etc/update-motd.d",
			dirType:    "Writable update-motd.d Directory",
			fileType:   "Writable update-motd.d Script",
			dirReason:  "The update-motd.d directory is writable. Attackers can plant a new script to execute automatically as root on login.",
			fileReason: "An update-motd.d script is writable. Attackers can modify it to execute malicious commands as root on login.",
		},
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

	for _, target := range targets {
		if _, err := os.Stat(target.path); err != nil {
			continue
		}

		filepath.WalkDir(target.path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			// Skip Symlinks to prevent false positives
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
				typeName := target.fileType
				reason := target.fileReason
				if d.IsDir() {
					typeName = target.dirType
					reason = target.dirReason
				}

				results = append(results, WriteableResult{
					Path:            path,
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: (uid == int(stat.Uid)),
					IsExecutable:    !d.IsDir() && (info.Mode()&0111 != 0),
					IsDangerous:     true,
					Type:            typeName,
					RiskLevel:       "CRITICAL",
					Reason:          reason,
				})
			}
			return nil
		})
	}

	// Also check /etc/profile itself
	if info, err := os.Stat("/etc/profile"); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
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
					Path:            "/etc/profile",
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: (uid == int(stat.Uid)),
					IsExecutable:    false,
					IsDangerous:     true,
					Type:            "Writable /etc/profile",
					RiskLevel:       "CRITICAL",
					Reason:          "The /etc/profile file is writable. Attackers can append malicious commands to execute when any user logs in.",
				})
			}
		}
	}

	return results, nil
}
