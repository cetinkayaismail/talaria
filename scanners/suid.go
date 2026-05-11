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

type SUIDResult struct {
	Path                 string
	IsDangerous          bool
	Reason               string
	WritableLibraryPaths []string
}

// SGIDResult holds findings for SGID binaries
type SGIDResult struct {
	Path        string
	OwnerGroup  string
	IsDangerous bool
	Reason      string
}

// PrivilegedGroupsForSGID: owning group of an SGID binary makes it dangerous
var privilegedSGIDGroups = map[string]bool{
	"shadow": true, "disk": true, "kmem": true, "tty": true,
	"audio": true, "video": true, "staff": true,
}

func ScanSUID(root string) ([]SUIDResult, error) {
	var results []SUIDResult

	// Only binaries that can be DIRECTLY used for PrivEsc or File Read
	// This list reduces the noise from standard binaries like ping or mount. but i want to add more binaries
	// to this list to make it more effective for ctf engagements as well as red team exercises.
	trueDangerousBinaries := map[string]bool{
		"find": true, "nmap": true, "vim": true, "vi": true, "bash": true, "sh": true, "dash": true,
		"python": true, "python3": true, "perl": true, "ruby": true,
		"cp": true, "mv": true, "wget": true, "curl": true,
		"docker": true, "git": true, "less": true, "more": true, "node": true,
		"npm": true, "tee": true, "tar": true, "awk": true, "sed": true,
		"env": true, "ftp": true, "php": true, "lua": true, "socat": true,
		"strace": true, "man": true, "time": true, "watch": true, "expect": true,
	}

	// Standard system SUID binaries that are safe/necessary to prevent noice in reports but we can add more if needed
	systemSUIDBinaries := map[string]bool{
		"chfn": true, "chsh": true, "gpasswd": true, "newgidmap": true,
		"newuidmap": true, "passwd": true, "su": true, "sudo": true,
		"pkexec": true, "mount": true, "umount": true, "ping": true, "ping6": true,
		"traceroute": true, "traceroute6": true, "at": true, "newgrp": true,
		"doas": true, "ssh-keysign": true, "fusermount": true,
	}

	skipDirs := []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/snap", "/usr/share", "/usr/lib"}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

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

		// Check for SUID bit
		if info.Mode()&os.ModeSetuid != 0 {
			fileName := filepath.Base(path)

			// Skip standard system SUID binaries to prevent noice
			if _, isSystemBinary := systemSUIDBinaries[strings.ToLower(fileName)]; isSystemBinary {
				return nil
			}

			// Logic: Is it in our GTFOBins-like high-risk list?
			isDangerous := false
			reason := ""
			var writableLibs []string

			if _, ok := trueDangerousBinaries[strings.ToLower(fileName)]; ok {
				isDangerous = true
				reason = "Matches known GTFOBins executable. Can be abused for privilege escalation."
				
				// SUID Library Path Tracking (Potential Library Hijacking)
				// We check common paths. Safest approach to avoid false positives is only checking common ones.
				switch strings.ToLower(fileName) {
				case "python", "python2", "python3":
					writableLibs = checkWritableDirs([]string{
						"/usr/local/lib/python3.8/dist-packages", "/usr/local/lib/python3.9/dist-packages",
						"/usr/local/lib/python3.10/dist-packages", "/usr/local/lib/python3.11/dist-packages",
						"/usr/local/lib/python3.12/dist-packages",
						"/usr/lib/python3/dist-packages", "/usr/lib/python3.8/site-packages",
						"/usr/lib/python3.9/site-packages", "/usr/lib/python3.10/site-packages",
					})
				case "perl":
					writableLibs = checkWritableDirs([]string{
						"/usr/local/lib/site_perl", "/usr/lib/x86_64-linux-gnu/perl5/5.30",
						"/usr/lib/x86_64-linux-gnu/perl5/5.34", "/usr/share/perl5",
					})
				case "ruby":
					writableLibs = checkWritableDirs([]string{
						"/usr/local/lib/site_ruby", "/var/lib/gems",
					})
				}
				
				if len(writableLibs) > 0 {
					reason += " | POTENTIAL HIJACKING: Writable library paths found."
				}
			}

			results = append(results, SUIDResult{
				Path:                 path,
				IsDangerous:          isDangerous,
				Reason:               reason,
				WritableLibraryPaths: writableLibs,
			})
		}
		return nil
	})

	return results, err
}

// ScanSGID finds binaries with the SGID bit set. If owned by a privileged group,
// it can be abused to gain group-level access (e.g., shadow group -> /etc/shadow read).
func ScanSGID(root string) ([]SGIDResult, error) {
	var results []SGIDResult

	skipDirs := []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/snap", "/usr/share", "/usr/lib"}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
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

		// Check for SGID bit
		if info.Mode()&os.ModeSetgid != 0 {
			ownerGroup := "unknown"
			isDangerous := false

			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				if g, err := user.LookupGroupId(strconv.Itoa(int(stat.Gid))); err == nil {
					ownerGroup = g.Name
					if privilegedSGIDGroups[strings.ToLower(g.Name)] {
						isDangerous = true
					}
				}
			}

			fileName := strings.ToLower(filepath.Base(path))

			// Safe privileged SGID binaries that are NOT exploitable for privilege escalation
			safePrivilegedSGID := map[string]bool{
				"chage": true, "expiry": true, "unix_chkpwd": true, "pam_extrausers_chkpwd": true, "bsd-write": true,
				"wall": true, "write": true,
			}

			if isDangerous && safePrivilegedSGID[fileName] {
				isDangerous = false
			}

			reason := ""
			if isDangerous {
				reason = "SGID binary owned by privileged group '" + ownerGroup + "'. Can be abused to gain group privileges."
			}

			// Standard system SGID binaries (skip to reduce noise)
			skipSystemSGID := map[string]bool{
				"write": true, "wall": true, "crontab": true, "ssh-agent": true,
				"dotlock.mailutils": true, "mail": true, "mailx": true,
			}
			if skipSystemSGID[fileName] && !isDangerous {
				return nil
			}

			results = append(results, SGIDResult{
				Path:        path,
				OwnerGroup:  ownerGroup,
				IsDangerous: isDangerous,
				Reason:      reason,
			})
		}
		return nil
	})

	return results, err
}

// checkWritableDirs checks if any of the provided directories exist and are writable by the current user
func checkWritableDirs(dirs []string) []string {
	var writable []string
	currUser, err := user.Current()
	if err != nil {
		return writable
	}
	uid, _ := strconv.Atoi(currUser.Uid)

	gidStrings, _ := currUser.GroupIds()
	userGids := make(map[int]bool)
	for _, g := range gidStrings {
		id, _ := strconv.Atoi(g)
		userGids[id] = true
	}

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

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
			writable = append(writable, dir)
		}
	}
	return writable
}
