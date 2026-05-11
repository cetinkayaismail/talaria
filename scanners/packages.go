package scanners

import (
	"os"
	"os/exec"
	"strings"
)

// PackageAuditResult holds findings for package manager misconfigurations
type PackageAuditResult struct {
	Name        string `json:"name"`
	IsDangerous bool   `json:"is_dangerous"`
	Reason      string `json:"reason"`
	ExploitHint string `json:"exploit_hint,omitempty"`
}

// ScanPackages audits package managers and privilege tools (doas, snap, flatpak)
func ScanPackages() ([]PackageAuditResult, error) {
	var results []PackageAuditResult

	// 1. Audit doas
	if res := auditDoas(); res != nil {
		results = append(results, *res)
	}

	// 2. Audit Snap
	if res := auditSnap(); res != nil {
		results = append(results, *res)
	}

	// 3. Audit Flatpak
	if res := auditFlatpak(); res != nil {
		results = append(results, *res)
	}

	return results, nil
}

func auditDoas() *PackageAuditResult {
	// Check if doas.conf exists
	info, err := os.Stat("/etc/doas.conf")
	if err != nil {
		return nil // doas not installed or config missing
	}

	// Check if it's world-readable (bad practice)
	if info.Mode()&0004 != 0 {
		return &PackageAuditResult{
			Name:        "doas",
			IsDangerous: true,
			Reason:      "/etc/doas.conf is world-readable. May leak privileged command aliases.",
			ExploitHint: "Read /etc/doas.conf to find commands that don't require a password.",
		}
	}

	// Try to read content to find 'nopass'
	data, err := os.ReadFile("/etc/doas.conf")
	if err == nil && strings.Contains(string(data), "nopass") {
		return &PackageAuditResult{
			Name:        "doas",
			IsDangerous: true,
			Reason:      "/etc/doas.conf contains 'nopass' entries.",
			ExploitHint: "Execute commands with 'doas' without a password.",
		}
	}

	return nil
}

func auditSnap() *PackageAuditResult {
	_, err := exec.LookPath("snap")
	if err != nil {
		return nil
	}

	// Check if snapd socket is writable (unlikely but critical)
	info, err := os.Stat("/run/snapd.socket")
	if err == nil && info.Mode()&0002 != 0 {
		return &PackageAuditResult{
			Name:        "snap",
			IsDangerous: true,
			Reason:      "snapd.socket is world-writable.",
			ExploitHint: "Potential for local root via snapd API injection.",
		}
	}

	return nil
}

func auditFlatpak() *PackageAuditResult {
	_, err := exec.LookPath("flatpak")
	if err != nil {
		return nil
	}

	// Check for writable flatpak installations
	info, err := os.Stat("/var/lib/flatpak")
	if err == nil && info.Mode()&0002 != 0 {
		return &PackageAuditResult{
			Name:        "flatpak",
			IsDangerous: true,
			Reason:      "/var/lib/flatpak is world-writable.",
			ExploitHint: "Inject malicious flatpak apps or override existing ones.",
		}
	}

	return nil
}
