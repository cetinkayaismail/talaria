package scanners

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type SUIDResult struct {
	Path        string
	IsDangerous bool
}

func ScanSUID(root string) ([]SUIDResult, error) {
	var results []SUIDResult

	// English: Only binaries that can be DIRECTLY used for PrivEsc or File Read
	// This list reduces the noise from standard binaries like ping or mount.
	trueDangerousBinaries := map[string]bool{
		"find": true, "nmap": true, "vim": true, "vi": true, "bash": true,
		"python": true, "python3": true, "perl": true, "ruby": true,
		"cp": true, "mv": true, "wget": true, "curl": true,
		"docker": true, "git": true, "less": true, "more": true, "node": true,
		"npm": true,
	}

	// Standard system SUID binaries that are safe/necessary
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

			// Skip standard system SUID binaries
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
