package scanners

import (
	"os/user"
)

type GroupResult struct {
	GroupName     string `json:"group_name"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// PrivilegedGroups lists groups that often lead to privilege escalation usefull docker privescalation and lateral movement
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
	"video":  "Can access the framebuffer (/dev/fb*) for keylogging or screen capture.",
	"input":  "Can read raw input events from /dev/input/* for keylogging.",
}

var GroupExploits = map[string]string{
	"docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt",
	"lxd":    "lxc image import alpine.tar.gz --alias alpine; lxc init alpine privesc -c security.privileged=true; lxc config device add privesc hostroot disk source=/ path=/mnt/root; lxc start privesc; lxc exec privesc /bin/sh",
	"disk":   "debugfs /dev/sda1 (or relevant device) - find sensitive files or write to disk.",
	"shadow": "cat /etc/shadow | grep root",
	"video":  "cat /dev/fb0 > screenshot.raw; or use tools like fbtft to capture screen.",
	"input":  "cat /dev/input/event* (requires root or CAP_INPUT) or use showkey to log keys.",
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
		exploitHint := ""
		remediation := ""
		complianceTag := ""

		if desc, exists := PrivilegedGroups[group.Name]; exists {
			isDangerous = true
			reason = desc
			if hint, ok := GroupExploits[group.Name]; ok {
				exploitHint = hint
			}
			remediation = "gpasswd -d " + currentUser.Username + " " + group.Name
			complianceTag = "CIS-Linux-5.4.1 / NIST-AC-6(2)"
		}

		results = append(results, GroupResult{
			GroupName:     group.Name,
			IsDangerous:   isDangerous,
			Reason:        reason,
			ExploitHint:   exploitHint,
			Remediation:   remediation,
			ComplianceTag: complianceTag,
		})
	}

	return results, nil
}
