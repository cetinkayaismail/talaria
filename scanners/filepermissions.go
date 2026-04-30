package scanners

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// FilePermissionResult must be a match for report headers this important for json reports
type FilePermissionResult struct {
	Path            string
	Permissions     string
	Owner           string
	OwnerUID        int
	IsWorldWritable bool
	IsGroupWritable bool
	IsWorldReadable bool
	IsDangerous     bool
	Issue           string
}

// CriticalFiles defines standard system files and their safe permission configuratiosn 
// This list is not exhaustive, but it covers the most common and critical system files that should be protected
var CriticalFiles = []struct {
	Path          string
	ExpectedPerms os.FileMode
	Description   string
}{
	{"/etc/passwd", 0644, "User account info"},
	{"/etc/shadow", 0600, "Password hashes"},
	{"/etc/sudoers", 0440, "Sudo config"},
	{"/etc/ssh/sshd_config", 0600, "SSH config"},
	{"/etc/crontab", 0644, "System crontab"},
	{"/etc/ld.so.conf", 0644, "Shared library config"},
	{"/etc/logrotate.conf", 0644, "Logrotate config"},
}

// ScanFilePermissions checks for misconfigurations in system files and common writable areas 
// This is a very important step in Privilege Escalation as it can lead to direct root access
func ScanFilePermissions() ([]FilePermissionResult, error) {
	var results []FilePermissionResult
	currUser, _ := user.Current()
	uid, _ := strconv.Atoi(currUser.Uid)

	// 1. Check Specific Critical System Files for standard permissions
	for _, cf := range CriticalFiles {
		res := checkSingleFile(cf.Path, cf.ExpectedPerms, uid)
		if res != nil {
			results = append(results, *res)
		}
	}

	// 2. Check World Writable Directories (useful for privescalation running scripts etc)
	wwPaths := []string{"/tmp", "/var/tmp", "/dev/shm", "/var/run", "/opt"}
	for _, p := range wwPaths {
		res := checkSingleFile(p, 0, uid)
		if res != nil && res.IsWorldWritable {
			res.Issue = "World-writable directory detected"
			results = append(results, *res)
		}
	}

	// 3. Direct /etc/shadow readability confirmation
	// Groups check infers access; this actually tries to open the file to ensure its readable.
	if f, err := os.Open("/etc/shadow"); err == nil {
		f.Close()
		results = append(results, FilePermissionResult{
			Path:            "/etc/shadow",
			Permissions:     "readable",
			IsWorldReadable: true,
			IsDangerous:     true,
			Issue:           "CONFIRMED: /etc/shadow is readable by current user — extract and crack hashes offline",
		})
	}

	// 4. /etc/ld.so.conf.d/ directory entries writable
	if entries, err := os.ReadDir("/etc/ld.so.conf.d"); err == nil {
		for _, e := range entries {
			p := "/etc/ld.so.conf.d/" + e.Name()
			if res := checkSingleFile(p, 0644, uid); res != nil && (res.IsWorldWritable || res.IsGroupWritable) {
				res.IsDangerous = true
				res.Issue = "Writable ld.so.conf.d entry: inject a malicious shared library path to hijack privileged binary loads"
				results = append(results, *res)
			}
		}
	}

	// 5. /etc/logrotate.d/ entries writable
	if entries, err := os.ReadDir("/etc/logrotate.d"); err == nil {
		for _, e := range entries {
			p := "/etc/logrotate.d/" + e.Name()
			if res := checkSingleFile(p, 0644, uid); res != nil && (res.IsWorldWritable || res.IsGroupWritable) {
				res.IsDangerous = true
				res.Issue = fmt.Sprintf("Writable logrotate config: %s — inject 'postrotate' commands to execute as root during log rotation", p)
				results = append(results, *res)
			}
		}
	}

	// 6. /etc/sudoers.d/ entries writable (catch drop-in files)
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			p := "/etc/sudoers.d/" + e.Name()
			if res := checkSingleFile(p, 0440, uid); res != nil && (res.IsWorldWritable || res.IsGroupWritable) {
				res.IsDangerous = true
				res.Issue = fmt.Sprintf("Writable sudoers drop-in: %s — add 'ALL=(ALL) NOPASSWD: ALL' to gain instant root", p)
				results = append(results, *res)
			}
		}
	}

	return results, nil
}

func checkSingleFile(path string, expected os.FileMode, currentUID int) *FilePermissionResult {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	mode := info.Mode()
	perms := mode.Perm()

	// Use bitwise and native way of perm checking . this will give more accurate and faster results than normal scanning
	isWorldWritable := (perms & 0o002) != 0
	isGroupWritable := (perms & 0o020) != 0
	isWorldReadable := (perms & 0o004) != 0

	isDangerous := false
	issue := ""

	// Logic: If it's a critical /etc file and it's world-writable, it's a critical finding
	if strings.HasPrefix(path, "/etc") && isWorldWritable {
		isDangerous = true
		issue = "Critical system file is world-writable!"
	}

	// Logic: If shadow or sudoers is world-readable
	if (strings.Contains(path, "shadow") || strings.Contains(path, "sudoers")) && isWorldReadable {
		isDangerous = true
		issue = "Sensitive file is world-readable!"
	}

	if isDangerous || isWorldWritable || isGroupWritable {
		ownerName := "unknown"
		if u, err := user.LookupId(strconv.Itoa(int(stat.Uid))); err == nil {
			ownerName = u.Username
		}

		return &FilePermissionResult{
			Path:            path,
			Permissions:     fmt.Sprintf("%04o", perms),
			Owner:           ownerName,
			OwnerUID:        int(stat.Uid),
			IsWorldWritable: isWorldWritable,
			IsGroupWritable: isGroupWritable,
			IsWorldReadable: isWorldReadable,
			IsDangerous:     isDangerous,
			Issue:           issue,
		}
	}

	return nil
}