package scanners

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// MountResult represents a temporary or shared memory mount flag auditing finding.
type MountResult struct {
	MountPoint    string `json:"mount_point"`
	FSType        string `json:"fs_type"`
	Options       string `json:"options"`
	MissingFlag   string `json:"missing_flag"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var tempMountTargets = map[string]bool{
	"/dev/shm": true,
	"/tmp":     true,
	"/var/tmp": true,
	"/run/shm": true,
}

// ScanMountAuditor parses /proc/mounts to audit mount options (noexec, nosuid) on temp partitions.
func ScanMountAuditor() ([]MountResult, error) {
	var results []MountResult

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return results, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			mountPoint := fields[1]
			fsType := fields[2]
			optsStr := fields[3]

			if tempMountTargets[mountPoint] {
				optsList := strings.Split(optsStr, ",")
				optsMap := make(map[string]bool)
				for _, o := range optsList {
					optsMap[o] = true
				}

				// Check for missing noexec flag
				if !optsMap["noexec"] {
					results = append(results, MountResult{
						MountPoint:    mountPoint,
						FSType:        fsType,
						Options:       optsStr,
						MissingFlag:   "noexec",
						RiskLevel:     "MEDIUM",
						Reason:        fmt.Sprintf("Temporary storage partition '%s' is missing 'noexec' flag — allows execution of compiled binaries out of RAM/tmp disk", mountPoint),
						ExploitHint:   fmt.Sprintf("mount -o remount,noexec %s", mountPoint),
						Remediation:   fmt.Sprintf("mount -o remount,nodev,nosuid,noexec %s", mountPoint),
						ComplianceTag: "CIS-Linux-1.1.4 / DISA-STIG-V-230230",
						IsDangerous:   true,
					})
				}

				// Check for missing nosuid flag
				if !optsMap["nosuid"] {
					results = append(results, MountResult{
						MountPoint:    mountPoint,
						FSType:        fsType,
						Options:       optsStr,
						MissingFlag:   "nosuid",
						RiskLevel:     "HIGH",
						Reason:        fmt.Sprintf("Temporary storage partition '%s' is missing 'nosuid' flag — SUID bit honored on binary payload execution", mountPoint),
						ExploitHint:   fmt.Sprintf("mount -o remount,nosuid %s", mountPoint),
						Remediation:   fmt.Sprintf("mount -o remount,nodev,nosuid,noexec %s", mountPoint),
						ComplianceTag: "CIS-Linux-1.1.3 / DISA-STIG-V-230230",
						IsDangerous:   true,
					})
				}
			}
		}
	}

	return results, nil
}
