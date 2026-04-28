package scanners

import (
	"os/user"
)

type GroupResult struct {
	GroupName   string
	IsDangerous bool
	Reason      string
}

// PrivilegedGroups lists groups that often lead to privilege escalation
var PrivilegedGroups = map[string]string{
	"docker": "Can spin up root containers and mount host filesystem.",
	"lxd":    "Can spin up root containers and mount host filesystem.",
	"lxc":    "Can spin up root containers and mount host filesystem.",
	"disk":   "Can directly read/write raw disk devices (e.g., /dev/sda).",
	"shadow": "Can read the /etc/shadow file to crack passwords.",
	"adm":    "Can read sensitive logs in /var/log.",
	"staff":  "Often has write permissions to /usr/local/bin.",
	"sudo":   "Can execute commands as root (check sudo -l).",
	"wheel":  "Can execute commands as root (check sudo -l).",
	"root":   "Is the root group.",
}

// ScanGroups checks if the current user belongs to any high-risk groups
func ScanGroups() ([]GroupResult, error) {
	var results []GroupResult

	currentUser, err := user.Current()
	if err != nil {
		return results, err
	}

	groupIds, err := currentUser.GroupIds()
	if err != nil {
		return results, err
	}

	for _, gid := range groupIds {
		group, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}

		isDangerous := false
		reason := ""

		if desc, exists := PrivilegedGroups[group.Name]; exists {
			isDangerous = true
			reason = desc
		}

		results = append(results, GroupResult{
			GroupName:   group.Name,
			IsDangerous: isDangerous,
			Reason:      reason,
		})
	}

	return results, nil
}
