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
	Path            string `json:"path"`
	Permissions     string `json:"permissions"`
	Owner           string `json:"owner,omitempty"`
	OwnerUID        int    `json:"owner_uid,omitempty"`
	IsWorldWritable bool   `json:"is_world_writable"`
	IsGroupWritable bool   `json:"is_group_writable"`
	IsWorldReadable bool   `json:"is_world_readable"`
	CanWrite        bool   `json:"can_write"`
	IsDangerous     bool   `json:"is_dangerous"`
	Issue           string `json:"issue"`
	Remediation     string `json:"remediation,omitempty"`
	ComplianceTag   string `json:"compliance_tag,omitempty"`
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
	{"/etc/fstab", 0644, "Filesystem mount table"},
}

// ScanFilePermissions checks for misconfigurations in system files and common writable areas
func ScanFilePermissions() ([]FilePermissionResult, error) {
	var results []FilePermissionResult
	ctx := GetUserContext()

	// 1. Check Specific Critical System Files for standard permissions
	for _, cf := range CriticalFiles {
		res := checkSingleFile(cf.Path, cf.ExpectedPerms, ctx)
		if res != nil {
			if res.Issue == "" {
				res.Issue = fmt.Sprintf("%s — permissions match expected (%04o), no immediate write access detected", cf.Description, cf.ExpectedPerms)
			}
			results = append(results, *res)
		}
	}

	// 2. Check World Writable Directories (useful for privescalation running scripts etc)
	wwPaths := []string{"/tmp", "/var/tmp", "/dev/shm", "/var/run", "/opt"}
	for _, p := range wwPaths {
		res := checkSingleFile(p, 0, ctx)
		if res != nil && res.IsWorldWritable {
			res.Issue = "World-writable directory detected"
			res.Remediation = "chmod 1777 " + p
			res.ComplianceTag = "CIS-Linux-1.1.2 / NIST-CM-6"
			results = append(results, *res)
		}
	}

	// 3. Direct /etc/shadow readability confirmation
	if f, err := os.Open("/etc/shadow"); err == nil {
		f.Close()
		results = append(results, FilePermissionResult{
			Path:            "/etc/shadow",
			Permissions:     "readable",
			IsWorldReadable: true,
			IsDangerous:     true,
			Issue:           "CONFIRMED: /etc/shadow is readable by current user — extract and crack hashes offline",
			Remediation:     "chmod 0640 /etc/shadow && chown root:shadow /etc/shadow",
			ComplianceTag:   "CIS-Linux-6.2.2 / DISA-STIG-V-230280",
		})
	}

	// 4. /etc/ld.so.conf.d/ directory entries writable
	if entries, err := os.ReadDir("/etc/ld.so.conf.d"); err == nil {
		for _, e := range entries {
			p := "/etc/ld.so.conf.d/" + e.Name()
			if res := checkSingleFile(p, 0644, ctx); res != nil && res.CanWrite {
				res.IsDangerous = true
				res.Issue = "Writable ld.so.conf.d entry: inject a malicious shared library path to hijack privileged binary loads"
				res.Remediation = "chown root:root " + p + " && chmod 0644 " + p
				res.ComplianceTag = "CIS-Linux-5.4.2 / NIST-SI-7"
				results = append(results, *res)
			}
		}
	}

	// 5. /etc/logrotate.d/ entries writable
	if entries, err := os.ReadDir("/etc/logrotate.d"); err == nil {
		for _, e := range entries {
			p := "/etc/logrotate.d/" + e.Name()
			if res := checkSingleFile(p, 0644, ctx); res != nil && res.CanWrite {
				res.IsDangerous = true
				res.Issue = fmt.Sprintf("Writable logrotate config: %s — inject 'postrotate' commands to execute as root during log rotation", p)
				res.Remediation = "chown root:root " + p + " && chmod 0644 " + p
				res.ComplianceTag = "CIS-Linux-4.2.1 / NIST-AU-9"
				results = append(results, *res)
			}
		}
	}

	// 6. /etc/sudoers.d/ entries writable (catch drop-in files)
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			p := "/etc/sudoers.d/" + e.Name()
			if res := checkSingleFile(p, 0440, ctx); res != nil && res.CanWrite {
				res.IsDangerous = true
				res.Issue = fmt.Sprintf("Writable sudoers drop-in: %s — add 'ALL=(ALL) NOPASSWD: ALL' to gain instant root", p)
				res.Remediation = "chown root:root " + p + " && chmod 0440 " + p
				res.ComplianceTag = "CIS-Linux-5.3.4 / DISA-STIG-V-230534"
				results = append(results, *res)
			}
		}
	}

	return results, nil
}

func checkSingleFile(path string, expected os.FileMode, ctx *UserContext) *FilePermissionResult {
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
	isSticky := (mode & os.ModeSticky) != 0

	isWorldWritable := (perms&0o002) != 0 && !isSticky
	isGroupWritable := (perms & 0o020) != 0
	isWorldReadable := (perms & 0o004) != 0

	canWrite := false
	if ctx != nil {
		canWrite = ctx.CanWrite(int(stat.Uid), int(stat.Gid), uint32(mode))
	}

	isDangerous := false
	issue := ""
	remediation := ""
	complianceTag := "CIS-Linux-6.2.1 / NIST-CM-6"

	// Logic: If it's a critical /etc file and it's world-writable, it's a critical finding
	if strings.HasPrefix(path, "/etc") && isWorldWritable {
		isDangerous = true
		issue = "Critical system file is world-writable!"
		remediation = fmt.Sprintf("chmod o-w %s && chown root:root %s", path, path)
	}

	// Logic: If shadow or sudoers is world-readable
	if (strings.Contains(path, "shadow") || strings.Contains(path, "sudoers")) && isWorldReadable {
		isDangerous = true
		issue = "Sensitive file is world-readable!"
		if strings.Contains(path, "shadow") {
			remediation = "chmod 0640 /etc/shadow && chown root:shadow /etc/shadow"
			complianceTag = "CIS-Linux-6.2.2 / DISA-STIG-V-230280"
		} else {
			remediation = "chmod 0440 /etc/sudoers && chown root:root /etc/sudoers"
			complianceTag = "CIS-Linux-5.3.4 / DISA-STIG-V-230534"
		}
	}

	if isDangerous || canWrite || isWorldWritable || isGroupWritable {
		ownerName := "unknown"
		if u, err := user.LookupId(strconv.Itoa(int(stat.Uid))); err == nil {
			ownerName = u.Username
		}

		if remediation == "" && expected > 0 {
			remediation = fmt.Sprintf("chmod %04o %s && chown root:root %s", expected, path, path)
		}

		return &FilePermissionResult{
			Path:            path,
			Permissions:     fmt.Sprintf("%04o", perms),
			Owner:           ownerName,
			OwnerUID:        int(stat.Uid),
			IsWorldWritable: isWorldWritable,
			IsGroupWritable: isGroupWritable,
			IsWorldReadable: isWorldReadable,
			CanWrite:        canWrite,
			IsDangerous:     isDangerous,
			Issue:           issue,
			Remediation:     remediation,
			ComplianceTag:   complianceTag,
		}
	}

	return nil
}
