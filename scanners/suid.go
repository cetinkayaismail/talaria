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
	Path        string
	IsDangerous bool
}

// SGIDResult holds findings for SGID binaries
type SGIDResult struct {
	Path        string
	OwnerGroup  string
	IsDangerous bool
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
			if _, ok := trueDangerousBinaries[strings.ToLower(fileName)]; ok {
				isDangerous = true
			}

			results = append(results, SUIDResult{
				Path:        path,
				IsDangerous: isDangerous,
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

			// Standard system SGID binaries (skip to reduce noise)
			fileName := strings.ToLower(filepath.Base(path))
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
			})
		}
		return nil
	})

	return results, err
}
