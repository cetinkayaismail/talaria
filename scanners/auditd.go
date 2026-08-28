package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AuditdResult represents an audit daemon or logging system detection result.
type AuditdResult struct {
	DaemonName    string `json:"daemon_name"`
	Status        string `json:"status"`
	RuleCount     int    `json:"rule_count"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var auditDaemons = []string{
	"auditd", "rsyslogd", "syslog-ng", "systemd-journald", "auditbeat",
}

// ScanAuditdAuditor checks for active audit daemons and inspects audit rules in /etc/audit/.
func ScanAuditdAuditor(procResults []ProcessResult) ([]AuditdResult, error) {
	var results []AuditdResult

	activeDaemons := make(map[string]bool)
	for _, proc := range procResults {
		cmdLower := strings.ToLower(proc.Command)
		for _, d := range auditDaemons {
			if strings.Contains(cmdLower, d) {
				activeDaemons[d] = true
			}
		}
	}

	for d := range activeDaemons {
		ruleCount := 0
		if d == "auditd" {
			ruleCount = countAuditRules()
		}

		reason := fmt.Sprintf("Active audit daemon '%s' detected running on system", d)
		if ruleCount > 0 {
			reason += fmt.Sprintf(" (%d active audit rules configured in /etc/audit/rules.d/)", ruleCount)
		}

		results = append(results, AuditdResult{
			DaemonName:    d,
			Status:        "ACTIVE",
			RuleCount:     ruleCount,
			RiskLevel:     "INFO",
			Reason:        reason,
			ExploitHint:   "OPSEC Warning: Commands and process executions may be logged by system audit daemon",
			Remediation:   "Ensure auditd rules are enabled in /etc/audit/rules.d/ and auditd service is active",
			ComplianceTag: "CIS-Linux-4.1.1 / NIST-AU-2, AU-12",
			IsDangerous:   true,
		})
	}

	return results, nil
}

func countAuditRules() int {
	count := 0
	ruleDir := "/etc/audit/rules.d"
	entries, err := os.ReadDir(ruleDir)
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".rules") && entry.Name() != "audit.rules") {
			continue
		}
		path := filepath.Join(ruleDir, entry.Name())
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") && strings.HasPrefix(line, "-a") {
				count++
			}
		}
		file.Close()
	}

	return count
}
