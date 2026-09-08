package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// FstabResult represents a security misconfiguration finding within /etc/fstab persistent mount configuration.
type FstabResult struct {
	Device        string `json:"device"`
	MountPoint    string `json:"mount_point"`
	FSType        string `json:"fs_type"`
	Options       string `json:"options"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

// System partitions that legitimately require SUID and execution binaries
var systemFstabSkipMounts = map[string]bool{
	"/":     true,
	"/boot": true,
	"/usr":  true,
	"/var":  true,
	"none":  true,
	"swap":  true,
}

// ScanFstab parses /etc/fstab to detect insecure persistent mount options and user-mountable partitions.
func ScanFstab() ([]FstabResult, error) {
	return scanFstabInternal("/etc/fstab")
}

func scanFstabInternal(fstabPath string) ([]FstabResult, error) {
	var results []FstabResult
	userCtx := GetUserContext()

	f, err := os.Open(fstabPath)
	if err != nil {
		return results, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue // Malformed line
		}

		device := fields[0]
		mountPoint := filepath.Clean(fields[1])
		fsType := fields[2]
		rawOptions := fields[3]

		// Skip swap and non-filesystems
		if fsType == "swap" || mountPoint == "none" || mountPoint == "swap" {
			continue
		}

		// Skip system partitions for nosuid checks
		if systemFstabSkipMounts[mountPoint] {
			continue
		}

		opts := strings.Split(rawOptions, ",")
		optMap := make(map[string]bool)
		for _, o := range opts {
			optMap[strings.TrimSpace(o)] = true
		}

		// 1. "user" or "users" mount option check (allows unprivileged mounting)
		isUserMount := optMap["user"] || optMap["users"]
		hasNoSuid := optMap["nosuid"]
		hasNoExec := optMap["noexec"]

		if isUserMount {
			risk := "HIGH"
			reason := fmt.Sprintf("Partition '%s' has '%s' mount option — unprivileged users can mount/remount this filesystem", mountPoint, rawOptions)
			exploit := fmt.Sprintf("mount %s (or remount with attacker-crafted media containing SUID root binaries)", mountPoint)
			isDangerous := false

			if !hasNoSuid {
				risk = "CRITICAL"
				reason = fmt.Sprintf("Partition '%s' permits unprivileged user mounting WITHOUT 'nosuid' — attacker can mount custom image containing SUID root shell", mountPoint)
				exploit = fmt.Sprintf("Prepare disk image with SUID bash, mount to %s, execute root shell", mountPoint)
				isDangerous = true
			}

			results = append(results, FstabResult{
				Device:        device,
				MountPoint:    mountPoint,
				FSType:        fsType,
				Options:       rawOptions,
				RiskLevel:     risk,
				Reason:        reason,
				ExploitHint:   exploit,
				Remediation:   fmt.Sprintf("Add 'nosuid,nodev,noexec' to options in %s for %s", fstabPath, mountPoint),
				ComplianceTag: "CIS-Linux-1.1.2 - 1.1.8",
				IsDangerous:   isDangerous,
			})
		}

		// 2. Missing nosuid on non-system partitions like /home, /tmp, /var/tmp, /dev/shm, NFS
		if !hasNoSuid && !isUserMount {
			if mountPoint == "/home" || mountPoint == "/tmp" || mountPoint == "/var/tmp" || mountPoint == "/dev/shm" || fsType == "nfs" || fsType == "nfs4" {
				results = append(results, FstabResult{
					Device:        device,
					MountPoint:    mountPoint,
					FSType:        fsType,
					Options:       rawOptions,
					RiskLevel:     "HIGH",
					Reason:        fmt.Sprintf("Partition '%s' is missing 'nosuid' mount option — SUID binaries placed here can be executed with elevated privileges", mountPoint),
					ExploitHint:   fmt.Sprintf("Deploy SUID binary on %s to retain root execution", mountPoint),
					Remediation:   fmt.Sprintf("Add 'nosuid' option to %s entry in %s", mountPoint, fstabPath),
					ComplianceTag: "CIS-Linux-1.1.3",
					IsDangerous:   false,
				})
			}
		}

		// 3. Missing noexec on /home or /tmp
		if !hasNoExec && (mountPoint == "/home" || mountPoint == "/tmp" || mountPoint == "/var/tmp") && !isUserMount {
			// Informational/hardening suggestion
		}

		// 4. Bind mount source writability check
		if optMap["bind"] && userCtx != nil {
			sourcePath := device
			if sInfo, sErr := os.Stat(sourcePath); sErr == nil && sInfo.IsDir() {
				if sys := sInfo.Sys(); sys != nil {
					if stat, ok := sys.(*syscall.Stat_t); ok {
						uid := int(stat.Uid)
						gid := int(stat.Gid)
						mode := uint32(sInfo.Mode().Perm())
						if userCtx.CanWrite(uid, gid, mode) {
							results = append(results, FstabResult{
								Device:        device,
								MountPoint:    mountPoint,
								FSType:        fsType,
								Options:       rawOptions,
								RiskLevel:     "HIGH",
								Reason:        fmt.Sprintf("Bind mount source '%s' (mounted to '%s') is writable by current user — files placed in source immediately reflect in privileged target", sourcePath, mountPoint),
								ExploitHint:   fmt.Sprintf("cp /tmp/evil %s/ -> reflected in %s", sourcePath, mountPoint),
								Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", sourcePath, sourcePath),
								ComplianceTag: "CIS-Linux-1.1.1",
								IsDangerous:   true,
							})
						}
					}
				}
			}
		}
	}

	return results, nil
}
