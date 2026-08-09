package scanners

import (
	"context"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"talaria/internal/walkpool"
)

type SUIDResult struct {
	Path                 string
	IsDangerous          bool
	Reason               string
	WritableLibraryPaths []string
	ExploitHint          string
}

// SGIDResult holds findings for SGID binaries
type SGIDResult struct {
	Path        string
	OwnerGroup  string
	IsDangerous bool
	Reason      string
	ExploitHint string
}

// PrivilegedGroupsForSGID: owning group of an SGID binary makes it dangerous
var privilegedSGIDGroups = map[string]bool{
	"shadow": true, "disk": true, "kmem": true, "tty": true,
	"audio": true, "video": true, "staff": true,
}

// hasAppArmorProfile checks if a specific profile name pattern is loaded in AppArmor.
func hasAppArmorProfile(name string) bool {
	data, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), name)
}

func ScanSUID(root string) ([]SUIDResult, error) {
	var results []SUIDResult

	// Standard system SUID binaries that are safe/necessary — skip these to
	// avoid noise. They are legitimate and well-audited.
	systemSUIDBinaries := map[string]bool{
		"chfn": true, "chsh": true, "gpasswd": true, "newgidmap": true,
		"newuidmap": true, "passwd": true, "su": true, "sudo": true,
		"pkexec": true, "mount": true, "umount": true, "ping": true, "ping6": true,
		"traceroute": true, "traceroute6": true, "at": true, "newgrp": true,
		"doas": true, "ssh-keysign": true, "fusermount": true, "fusermount3": true,
	}

	// walkpool.Walk handles ShouldIgnore at the dispatcher level (SkipDir semantics).
	// Entries are delivered one at a time; appends to results are single-threaded.
	for entry := range walkpool.Walk(context.Background(), root, poolWorkers(), ShouldIgnore) {
		path := entry.Path
		d := entry.Entry

		info, err := d.Info()
		if err != nil {
			continue
		}

		// Check for SUID bit
		if info.Mode()&os.ModeSetuid != 0 {
			// --- FP Reduction for SUID Sandbox and Ownership ---
			// 1. Skip sandboxed apps (Snap/Flatpak) ONLY if their AppArmor profiles are active/loaded
			if strings.HasPrefix(path, "/snap/") {
				if hasAppArmorProfile("snap.") {
					continue
				}
			} else if strings.Contains(path, "/flatpak/") || strings.HasPrefix(path, "/var/lib/flatpak/") {
				if hasAppArmorProfile("flatpak") {
					continue
				}
			}

			// 2. Extract stat and check ownership
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			isRootOwned := (stat.Uid == 0)

			fileName := filepath.Base(path)
			fileNameLower := strings.ToLower(fileName)

			// Skip standard system SUID binaries to prevent noise
			if _, isSystemBinary := systemSUIDBinaries[fileNameLower]; isSystemBinary {
				continue
			}

			// GTFOBins JSON lookup — covers 380+ binaries vs the old 30-entry map.
			gtfoEntry, inGTFOBins := LookupGTFOBin(fileNameLower)

			isDangerous := false
			reason := ""
			var writableLibs []string

			if inGTFOBins && gtfoEntry.SUID {
				isDangerous = true

				// Build a concise capability tag string for the reason
				var caps []string
				if gtfoEntry.Shell     { caps = append(caps, "shell") }
				if gtfoEntry.FileRead  { caps = append(caps, "file-read") }
				if gtfoEntry.FileWrite { caps = append(caps, "file-write") }
				capStr := strings.Join(caps, ", ")
				if capStr == "" { capStr = "privilege-escalation" }

				if isRootOwned {
					reason = fmt.Sprintf(
						"GTFOBins match — SUID capabilities: [%s]. Can be abused for privilege escalation to root.",
						capStr,
					)
				} else {
					reason = fmt.Sprintf(
						"GTFOBins match — SUID capabilities: [%s]. Owned by UID %d — lateral movement / user pivoting risk.",
						capStr, stat.Uid,
					)
				}

				// Check interpreter-specific writable library paths
				switch fileNameLower {
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

			// ELF RPATH/RUNPATH Analysis (SO Hijacking)
			rpathDirs := checkRPATH(path)
			if len(rpathDirs) > 0 {
				isDangerous = true
				reason += " | SO HIJACKING: Writable RPATH/RUNPATH found: " + strings.Join(rpathDirs, ", ")
				writableLibs = append(writableLibs, rpathDirs...)
			}

			exploitHint := ""
			if isDangerous {
				// Use exploit hint from GTFOBins JSON if available
				if inGTFOBins && gtfoEntry.ExploitHint != "" {
					exploitHint = gtfoEntry.ExploitHint
				} else {
					exploitHint = GetExploitHint(path, "suid")
				}
				if exploitHint == "" {
					exploitHint = "Create a malicious .so in one of the writable paths and run the binary."
				}
			}

			results = append(results, SUIDResult{
				Path:                 path,
				IsDangerous:          isDangerous,
				Reason:               reason,
				WritableLibraryPaths: writableLibs,
				ExploitHint:          exploitHint,
			})
		}
	}

	return results, nil
}

// checkRPATH extracts RPATH and RUNPATH from ELF and checks if they are writable.
func checkRPATH(path string) []string {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var paths []string
	if tags, err := f.DynString(elf.DT_RPATH); err == nil {
		paths = append(paths, tags...)
	}
	if tags, err := f.DynString(elf.DT_RUNPATH); err == nil {
		paths = append(paths, tags...)
	}

	if len(paths) == 0 {
		return nil
	}
	return checkWritableDirs(paths)
}

// ScanSGID finds binaries with the SGID bit set.
func ScanSGID(root string) ([]SGIDResult, error) {
	var results []SGIDResult

	// walkpool.Walk handles ShouldIgnore at the dispatcher level (SkipDir semantics).
	// Entries are delivered one at a time; appends to results are single-threaded.
	for entry := range walkpool.Walk(context.Background(), root, poolWorkers(), ShouldIgnore) {
		path := entry.Path
		d := entry.Entry

		info, err := d.Info()
		if err != nil {
			continue
		}

		// Check for SGID bit
		if info.Mode()&os.ModeSetgid != 0 {
			ownerGroup := "unknown"
			isDangerous := false

			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				ownerGroup = CachedGroupName(int(stat.Gid))
				if privilegedSGIDGroups[strings.ToLower(ownerGroup)] {
					isDangerous = true
				}
			}

			fileName := strings.ToLower(filepath.Base(path))

			// Safe privileged SGID binaries
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

			// Standard system SGID binaries
			skipSystemSGID := map[string]bool{
				"write": true, "wall": true, "crontab": true, "ssh-agent": true,
				"dotlock.mailutils": true, "mail": true, "mailx": true,
			}
			if skipSystemSGID[fileName] && !isDangerous {
				continue
			}

			exploitHint := ""
			if isDangerous {
				exploitHint = "Binary is owned by privileged group '" + ownerGroup + "'. Exploit to gain group access."
			}

			results = append(results, SGIDResult{
				Path:        path,
				OwnerGroup:  ownerGroup,
				IsDangerous: isDangerous,
				Reason:      reason,
				ExploitHint: exploitHint,
			})
		}
	}

	return results, nil
}

// checkWritableDirs checks if any of the provided directories exist and are
// writable by the current user. Uses the cached UserContext (D2) to avoid
// redundant user.Current() / GroupIds() syscalls.
func checkWritableDirs(dirs []string) []string {
	var writable []string
	ctx := GetUserContext()

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if ctx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
			writable = append(writable, dir)
		}
	}
	return writable
}
