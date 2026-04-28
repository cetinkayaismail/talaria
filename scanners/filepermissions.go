package scanners

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// FilePermissionResult must be a match for report headers
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
}

// ScanFilePermissions checks for misconfigurations in system files and common writable areas
func ScanFilePermissions() ([]FilePermissionResult, error) {
	var results []FilePermissionResult
	currUser, _ := user.Current()
	uid, _ := strconv.Atoi(currUser.Uid)

	// 1. Check Specific Critical System Files for standart permissions
	for _, cf := range CriticalFiles {
		res := checkSingleFile(cf.Path, cf.ExpectedPerms, uid)
		if res != nil {
			results = append(results, *res)
		}
	}

	// 2. Checking World Writable Directories (The most common PrivEsc vector)
	wwPaths := []string{"/tmp", "/var/tmp", "/dev/shm", "/var/run", "/opt"}
	for _, p := range wwPaths {
		res := checkSingleFile(p, 0, uid)
		if res != nil && res.IsWorldWritable {
			res.Issue = "World-writable directory detected"
			results = append(results, *res)
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

	// Use bitwise and native way of perm checking
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