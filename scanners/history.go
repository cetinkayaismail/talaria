package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// HistorySecretResult holds a matched sensitive shell command finding
type HistorySecretResult struct {
	User          string `json:"user"`
	HistoryFile   string `json:"history_file"`
	LineNumber    int    `json:"line_number"`
	Command       string `json:"command"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// ScanHistoryFiles audits all local user shell histories for leaked credentials
func ScanHistoryFiles() ([]HistorySecretResult, error) {
	var results []HistorySecretResult

	// Discover users and their home directories from /etc/passwd
	users, err := getSystemUsers()
	if err != nil {
		return nil, err
	}

	historyFiles := []string{
		".bash_history",
		".zsh_history",
		".sh_history",
		".nano_history",
	}

	for _, u := range users {
		for _, hFile := range historyFiles {
			path := filepath.Join(u.HomeDir, hFile)
			// Check if file exists and is regular
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}

			// Open and scan line-by-line (highly memory-safe)
			file, err := os.Open(path)
			if err != nil {
				continue // Gracefully skip unreadable history files
			}

			scanner := bufio.NewScanner(file)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				if line == "" {
					continue
				}

				if res := auditHistoryLine(line, u.Username, path, lineNum); res != nil {
					results = append(results, *res)
				}
			}
			file.Close()
		}
	}

	return results, nil
}

type userInfo struct {
	Username string
	HomeDir  string
}

// getSystemUsers parses /etc/passwd to extract users with active home directories
func getSystemUsers() ([]userInfo, error) {
	var users []userInfo

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 6 {
			continue
		}

		username := parts[0]
		homeDir := parts[5]

		// Focus strictly on real users (home directory under /home or root's home)
		if strings.HasPrefix(homeDir, "/home") || homeDir == "/root" {
			users = append(users, userInfo{
				Username: username,
				HomeDir:  homeDir,
			})
		}
	}

	return users, nil
}

// auditHistoryLine checks a single history line for hardcoded credentials and masks them
func auditHistoryLine(line string, username string, path string, lineNum int) *HistorySecretResult {
	trimmed := strings.TrimSpace(line)
	// Skip comments (often templates or examples in history)
	if strings.HasPrefix(trimmed, "#") {
		return nil
	}

	// Standard credential assignment patterns:
	reAssign := regexp.MustCompile(`(?i)(?:password|pass|secret|token|key|pwd)\s*(?:=|:)\s*['"]?([^'"\s&|;<>]+)['"]?`)
	reCliFlag := regexp.MustCompile(`(?i)(?:-p|--password|--pass)\s*['"]?([^'"\s&|;<>]+)['"]?`)
	reConnection := regexp.MustCompile(`(?i)(?:mysql|postgresql|postgres|redis|mongodb)(?:://[^:]+:([^@]+)@|(?:\s+[^-\s]+)*\s+-p\s*([^-\s]+))`)

	// New patterns for Cloud and API tokens (often exported in history)
	reAWS := regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)
	reBearer := regexp.MustCompile(`(?i)Authorization:\s+Bearer\s+([A-Za-z0-9\-._~+/]+=*)`)

	var secretVal string
	var matchType string
	var reason string

	if m := reAWS.FindStringSubmatch(line); len(m) > 1 {
		secretVal = m[1]
		matchType = "aws_key"
		reason = "Discovered AWS Access Key ID in shell history"
	} else if m := reBearer.FindStringSubmatch(line); len(m) > 1 {
		secretVal = m[1]
		matchType = "bearer_token"
		reason = "Discovered HTTP Bearer Token in shell history"
	} else if m := reAssign.FindStringSubmatch(line); len(m) > 1 {
		secretVal = m[1]
		matchType = "assignment"
		reason = "Discovered hardcoded password or credential assignment in shell history"
	} else if m := reCliFlag.FindStringSubmatch(line); len(m) > 1 {
		secretVal = m[1]
		matchType = "cli_flag"
		reason = "Discovered credentials passed as CLI argument in shell history"

		// --- FP Reduction for CLI -p option ---
		// Checks if the CLI flag is likely a port/numeric assignment, or if the command itself
		// is not a tool that natively expects passwords/keys via CLI flag.
		if strings.Contains(line, " -p ") || strings.Contains(line, " -p") {
			// 1. Skip numeric ports (e.g., -p 22, -p 8080) and port mappings (e.g., -p 80:80)
			isNumericOrPort := true
			for _, char := range secretVal {
				if (char < '0' || char > '9') && char != ':' {
					isNumericOrPort = false
					break
				}
			}
			if isNumericOrPort {
				return nil
			}

			// 2. Only allow -p flags for known tools that accept passwords (mysql, pg_dump, etc.)
			fields := strings.Fields(strings.ToLower(line))
			if len(fields) > 0 {
				binaryName := filepath.Base(fields[0])
				validPassTools := map[string]bool{
					"mysql": true, "mysqldump": true, "mysqladmin": true, "pg_dump": true,
					"psql": true, "redis-cli": true, "mongo": true, "mongodump": true,
					"sshpass": true, "7z": true, "7za": true, "unzip": true, "rar": true,
				}
				if !validPassTools[binaryName] {
					return nil
				}
			}
		}
	} else if m := reConnection.FindStringSubmatch(line); len(m) > 1 {
		if m[1] != "" {
			secretVal = m[1]
		} else if len(m) > 2 && m[2] != "" {
			secretVal = m[2]
		}
		matchType = "connection"
		reason = "Discovered database credentials in command execution history"
	}

	// Avoid false positive matches of placeholders or empty strings
	if secretVal == "" || isFalsePositive(secretVal) {
		return nil
	}

	// Extra FP protection for history: check if secret is just a variable evaluation
	if strings.HasPrefix(secretVal, "$") || strings.HasPrefix(secretVal, "\\$") {
		return nil
	}

	// Extra FP protection for assignments (e.g. export PASS=...)
	if matchType == "assignment" && calculateEntropy(secretVal) < 2.5 && !strings.Contains(line, "mysql") {
		return nil
	}

	// In professional/audit mode mask the value; in CTF mode keep cleartext for direct use
	displayCmd := line
	if AuditCfg.MaskSecrets {
		displayCmd = maskCredentials(line, secretVal)
	}

	return &HistorySecretResult{
		User:          username,
		HistoryFile:   path,
		LineNumber:    lineNum,
		Command:       displayCmd,
		RiskLevel:     "CRITICAL",
		Reason:        reason,
		Remediation:   fmt.Sprintf("history -d %d (or clear history via 'history -c && rm %s')", lineNum, path),
		ComplianceTag: "CIS-Linux-5.4.3 / NIST-IA-5",
	}
}

// maskCredentials replaces cleartext secrets with masked representations
func maskCredentials(line string, secret string) string {
	if len(secret) <= 3 {
		return strings.ReplaceAll(line, secret, "****")
	}
	// Keep first 3 chars, mask the rest
	masked := secret[:3] + "********"
	return strings.ReplaceAll(line, secret, masked)
}
