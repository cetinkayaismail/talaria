package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcEnvResult represents a sensitive token or password discovered in process environment variables.
type ProcEnvResult struct {
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name"`
	Key           string `json:"key"`
	ValueSample   string `json:"value_sample"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var sensitiveEnvKeys = []string{
	"AWS_SECRET_ACCESS_KEY",
	"AWS_ACCESS_KEY_ID",
	"VAULT_TOKEN",
	"DB_PASSWORD",
	"DATABASE_URL",
	"MYSQL_PWD",
	"PGPASSWORD",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"SLACK_TOKEN",
	"BEARER_TOKEN",
	"API_KEY",
	"SECRET_KEY",
	"PRIVATE_KEY",
	"PASSPHRASE",
	"AUTH_TOKEN",
}

// ScanProcEnvAuditor inspects readable /proc/[pid]/environ files for exposed credentials.
func ScanProcEnvAuditor(procResults []ProcessResult) ([]ProcEnvResult, error) {
	var results []ProcEnvResult

	procMap := make(map[int]string)
	for _, p := range procResults {
		procMap[p.PID] = p.Command
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return results, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		envPath := filepath.Join("/proc", entry.Name(), "environ")
		data, err := os.ReadFile(envPath)
		if err != nil || len(data) == 0 {
			continue
		}

		procName := procMap[pid]
		if procName == "" {
			procName = fmt.Sprintf("PID %d", pid)
		}

		// Environment variables in /proc/[pid]/environ are null-byte (\x00) separated
		envVars := strings.Split(string(data), "\x00")
		for _, envVar := range envVars {
			if envVar == "" {
				continue
			}

			parts := strings.SplitN(envVar, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := parts[0]
			val := parts[1]
			keyUpper := strings.ToUpper(key)

			for _, sKey := range sensitiveEnvKeys {
				if keyUpper == sKey || strings.Contains(keyUpper, "PASSWORD") || strings.Contains(keyUpper, "SECRET") || strings.Contains(keyUpper, "AUTH_TOKEN") {
					if isFalsePositiveEnvValue(val) {
						continue
					}

					valPreview := val
					if len(valPreview) > 16 {
						valPreview = valPreview[:16] + "..."
					}

					results = append(results, ProcEnvResult{
						PID:           pid,
						ProcessName:   procName,
						Key:           key,
						ValueSample:   valPreview,
						RiskLevel:     "CRITICAL",
						Reason:        fmt.Sprintf("Process '%s' (PID %d) exposes sensitive environment variable '%s' in /proc/%d/environ", procName, pid, key, pid),
						ExploitHint:   fmt.Sprintf("cat /proc/%d/environ | tr '\\0' '\\n' | grep %s", pid, key),
						Remediation:   "mount -o remount,hidepid=2 /proc (and avoid passing credentials in env variables)",
						ComplianceTag: "NIST-SC-28 / DISA-STIG-V-230420",
						IsDangerous:   true,
					})
					break
				}
			}
		}
	}

	return results, nil
}

func isFalsePositiveEnvValue(val string) bool {
	vLower := strings.ToLower(val)
	if val == "" || len(val) < 3 {
		return true
	}
	noise := []string{
		"null", "none", "false", "true", "0", "1", "undefined", "dummy", "placeholder", "xxx", "your_secret",
	}
	for _, n := range noise {
		if vLower == n {
			return true
		}
	}
	return false
}
