package scanners

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SnapAuditResult represents an audit finding for a vulnerable or misconfigured snapd/flatpak component.
type SnapAuditResult struct {
	Path          string `json:"path"`
	Binary        string `json:"binary"`
	Version       string `json:"version"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	CVE           string `json:"cve,omitempty"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var snapConfineCandidatePaths = []string{
	"/usr/lib/snapd/snap-confine",
	"/usr/libexec/snapd/snap-confine",
}

// readSnapdVersion runs `snapd --version` or `snap --version` to extract the snapd version.
func readSnapdVersion() string {
	for _, cmdName := range []string{"snapd", "snap"} {
		path, err := exec.LookPath(cmdName)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, "--version")
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "snapd ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "snapd "))
			}
		}
	}
	return ""
}

// readFlatpakVersion runs `flatpak --version` to extract flatpak version.
func readFlatpakVersion() string {
	path, err := exec.LookPath("flatpak")
	if err != nil {
		return ""
	}
	cmd := exec.Command(path, "--version")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(out))
	if strings.HasPrefix(line, "Flatpak ") {
		return strings.TrimSpace(strings.TrimPrefix(line, "Flatpak "))
	}
	return ""
}

// ScanSnapAudit audits snap-confine, snapd, flatpak helpers, and snap package confinement modes.
func ScanSnapAudit() ([]SnapAuditResult, error) {
	snapdVer := readSnapdVersion()
	flatpakVer := readFlatpakVersion()
	return scanSnapAuditInternal(snapConfineCandidatePaths, snapdVer, flatpakVer, "/snap", true)
}

func scanSnapAuditInternal(confinePaths []string, snapdVer, flatpakVer, snapDir string, checkSUID bool) ([]SnapAuditResult, error) {
	var results []SnapAuditResult

	// 1. Audit snap-confine SUID helper
	for _, confinePath := range confinePaths {
		info, err := os.Stat(confinePath)
		if err != nil {
			continue
		}

		// Pre-condition: Is SUID bit set?
		if checkSUID && (info.Mode()&os.ModeSetuid == 0) {
			// SUID bit was removed/mitigated -> do not flag as critical SUID vulnerability
			continue
		}

		if snapdVer != "" {
			// CVE-2021-44731: snap-confine race condition sandbox escape (fixed in 2.54.3)
			if compareDistroVersions(snapdVer, "2.54.3") < 0 {
				results = append(results, SnapAuditResult{
					Path:          confinePath,
					Binary:        "snap-confine",
					Version:       snapdVer,
					RiskLevel:     "CRITICAL",
					Reason:        fmt.Sprintf("snap-confine has SUID bit set and snapd version '%s' is vulnerable to CVE-2021-44731 (race condition root escape)", snapdVer),
					CVE:           "CVE-2021-44731",
					ExploitHint:   "Public exploit available: local race condition in snap-confine grants root shell",
					Remediation:   "apt-get update && apt-get install --only-upgrade snapd",
					ComplianceTag: "CVE-2021-44731",
					IsDangerous:   true,
				})
			} else if compareDistroVersions(snapdVer, "2.57.6") < 0 {
				// CVE-2022-3328: multipathd symlink & snap-confine race
				results = append(results, SnapAuditResult{
					Path:          confinePath,
					Binary:        "snap-confine",
					Version:       snapdVer,
					RiskLevel:     "CRITICAL",
					Reason:        fmt.Sprintf("snap-confine has SUID bit set and snapd version '%s' is vulnerable to CVE-2022-3328 (snap-confine race condition)", snapdVer),
					CVE:           "CVE-2022-3328",
					ExploitHint:   "Public exploit available: Qualys Advisory CVE-2022-3328",
					Remediation:   "apt-get update && apt-get install --only-upgrade snapd",
					ComplianceTag: "CVE-2022-3328",
					IsDangerous:   true,
				})
			}
		}
	}

	// 2. Audit Flatpak helper versions
	if flatpakVer != "" {
		if compareDistroVersions(flatpakVer, "1.10.4") < 0 {
			flatpakPath := "/usr/bin/flatpak"
			if lp, err := exec.LookPath("flatpak"); err == nil {
				flatpakPath = lp
			}
			results = append(results, SnapAuditResult{
				Path:          flatpakPath,
				Binary:        "flatpak",
				Version:       flatpakVer,
				RiskLevel:     "HIGH",
				Reason:        fmt.Sprintf("Flatpak version '%s' is vulnerable to CVE-2021-41133 (unprivileged portal sandbox bypass)", flatpakVer),
				CVE:           "CVE-2021-41133",
				ExploitHint:   "Sandbox escape via portal interface allows arbitrary command execution outside container",
				Remediation:   "Upgrade flatpak to >= 1.10.4",
				ComplianceTag: "CVE-2021-41133",
				IsDangerous:   false,
			})
		}
	}

	// 3. Audit snap packages running in devmode (unconfined)
	if entries, err := os.ReadDir(snapDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == "bin" {
				continue
			}
			metaPath := filepath.Join(snapDir, entry.Name(), "current", "meta", "snap.yaml")
			metaBytes, mErr := os.ReadFile(metaPath)
			if mErr != nil {
				continue
			}
			scanner := bufio.NewScanner(strings.NewReader(string(metaBytes)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "confinement:") && strings.Contains(line, "devmode") {
					results = append(results, SnapAuditResult{
						Path:          metaPath,
						Binary:        entry.Name(),
						RiskLevel:     "MEDIUM",
						Reason:        fmt.Sprintf("Snap package '%s' is configured with 'confinement: devmode' — runs with full host system access and bypasses AppArmor sandboxing", entry.Name()),
						Remediation:   fmt.Sprintf("Reinstall snap '%s' in strict mode: snap refresh %s --jailmode", entry.Name(), entry.Name()),
						ComplianceTag: "AppArmor-Snap-Confinement",
						IsDangerous:   false,
					})
					break
				}
			}
		}
	}

	return results, nil
}
