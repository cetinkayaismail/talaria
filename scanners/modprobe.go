package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ModprobeResult represents a modprobe configuration or hook finding.
type ModprobeResult struct {
	Path          string `json:"path"`
	Directive     string `json:"directive,omitempty"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var modprobeDirs = []string{
	"/etc/modprobe.d",
	"/lib/modprobe.d",
	"/usr/lib/modprobe.d",
}

// ScanModprobeRules audits kernel module loading rules and custom install directives.
func ScanModprobeRules() ([]ModprobeResult, error) {
	var results []ModprobeResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	for _, dir := range modprobeDirs {
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}

		if isStatWritable(info, userCtx) {
			results = append(results, ModprobeResult{
				Path:          dir,
				RiskLevel:     "CRITICAL",
				Reason:        fmt.Sprintf("Modprobe directory '%s' is writable by current user — dropping a custom config with 'install <module> <cmd>' grants root code execution upon socket/module trigger", dir),
				ExploitHint:   fmt.Sprintf("echo 'install bluetooth /tmp/payload.sh' > %s/evil.conf", dir),
				Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", dir, dir),
				ComplianceTag: "CIS-Linux-1.1.1 / NIST-CM-7",
				IsDangerous:   true,
			})
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}

			confPath := filepath.Join(dir, entry.Name())
			fInfo, fErr := entry.Info()
			if fErr != nil {
				continue
			}

			if isStatWritable(fInfo, userCtx) {
				results = append(results, ModprobeResult{
					Path:          confPath,
					RiskLevel:     "CRITICAL",
					Reason:        fmt.Sprintf("Modprobe configuration file '%s' is writable by current user", confPath),
					ExploitHint:   fmt.Sprintf("echo 'install dccp /tmp/payload.sh' >> %s", confPath),
					Remediation:   fmt.Sprintf("chown root:root %s && chmod 0644 %s", confPath, confPath),
					ComplianceTag: "CIS-Linux-1.1.1 / NIST-CM-7",
					IsDangerous:   true,
				})
			}

			// Parse install directives inside the conf file
			file, err := os.Open(confPath)
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "install ") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						cmdTarget := fields[2]
						if strings.HasPrefix(cmdTarget, "/") {
							if targetInfo, err := os.Stat(cmdTarget); err == nil {
								if isStatWritable(targetInfo, userCtx) {
									results = append(results, ModprobeResult{
										Path:          cmdTarget,
										Directive:     line,
										RiskLevel:     "CRITICAL",
										Reason:        fmt.Sprintf("Modprobe install command target '%s' (referenced in %s) is writable by current user", cmdTarget, confPath),
										ExploitHint:   fmt.Sprintf("Modify '%s' to insert your root payload", cmdTarget),
										Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", cmdTarget, cmdTarget),
										ComplianceTag: "CIS-Linux-1.1.1 / NIST-SI-7",
										IsDangerous:   true,
									})
								}
							}
						}
					}
				}
			}
			file.Close()
		}
	}

	return results, nil
}
