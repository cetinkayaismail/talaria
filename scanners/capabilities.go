package scanners

import (
	"os/exec"
	"strings"
)

// CapabilityResult is exported for main.go reporting
type CapabilityResult struct {
	Path          string `json:"path"`
	Capabilities  string `json:"capabilities"`
	IsDangerous   bool   `json:"is_dangerous"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// Critical capabilities that often lead to instant privilege escalation
var DangerousCapabilities = []string{
	"cap_setuid", "cap_setgid",
	"cap_sys_admin", "cap_sys_ptrace", "cap_dac_override",
	"cap_dac_read_search", "cap_fowner", "cap_fsetid",
	"cap_sys_module", "cap_sys_boot", "cap_sys_chroot",
}

// ScanCapabilities uses the native getcap binary to rapidly scan the filesystem.
func ScanCapabilities(root string) ([]CapabilityResult, error) {
	var results []CapabilityResult

	// Run getcap recursively.
	cmd := exec.Command("getcap", "-r", root)
	output, _ := cmd.Output()

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}

		path := strings.TrimSpace(parts[0])
		caps := strings.TrimSpace(parts[1])
		caps = strings.TrimPrefix(caps, "=")
		caps = strings.TrimSpace(caps)

		isDangerous := false
		capsLower := strings.ToLower(caps)
		for _, dc := range DangerousCapabilities {
			if strings.Contains(capsLower, dc) {
				isDangerous = true
				break
			}
		}

		hint := ""
		remediation := ""
		complianceTag := ""
		if isDangerous {
			hint = GetExploitHint(path, "capability")
			remediation = "setcap -r " + path
			complianceTag = "CIS-Linux-6.1.15 / NIST-AC-6(1)"
		}

		results = append(results, CapabilityResult{
			Path:          path,
			Capabilities:  caps,
			IsDangerous:   isDangerous,
			ExploitHint:   hint,
			Remediation:   remediation,
			ComplianceTag: complianceTag,
		})
	}

	return results, nil
}