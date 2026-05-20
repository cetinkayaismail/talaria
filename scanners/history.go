package scanners

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// HistorySecretResult holds a matched sensitive shell command finding
type HistorySecretResult struct {
	User        string `json:"user"`
	HistoryFile string `json:"history_file"`
	LineNumber  int    `json:"line_number"`
	Command     string `json:"command"`
	RiskLevel   string `json:"risk_level"`
	Reason      string `json:"reason"`
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
	// Standard credential assignment patterns:
	// 1. assignment (e.g. password=secret, token: secret)
	// 2. cli flags (e.g. -p'secret', --password='secret')
	// 3. connections (e.g. mysql -u user -psecret)
	reAssign := regexp.MustCompile(`(?i)(?:password|pass|secret|token|key|pwd)\s*(?:=|:)\s*['"]?([^'"\s&|;<>]+)['"]?`)
	reCliFlag := regexp.MustCompile(`(?i)(?:-p|--password|--pass)\s*['"]?([^'"\s&|;<>]+)['"]?`)
	reConnection := regexp.MustCompile(`(?i)(?:mysql|postgresql|postgres|redis|mongodb)(?:://[^:]+:([^@]+)@|(?:\s+[^-\s]+)*\s+-p\s*([^-\s]+))`)

	var secretVal string
	var matchType string

	if m := reAssign.FindStringSubmatch(line); len(m) > 1 {
		secretVal = m[1]
		matchType = "assignment"
	} else if m := reCliFlag.FindStringSubmatch(line); len(m) > 1 {
		secretVal = m[1]
		matchType = "cli_flag"
	} else if m := reConnection.FindStringSubmatch(line); len(m) > 1 {
		// reConnection has multiple capture groups due to alternate formats
		if m[1] != "" {
			secretVal = m[1]
		} else if len(m) > 2 && m[2] != "" {
			secretVal = m[2]
		}
		matchType = "connection"
	}

	// Avoid false positive matches of placeholders or empty strings
	if secretVal == "" || isFalsePositive(secretVal) {
		return nil
	}

	// Mask the discovered credential inside the command line for secure output
	maskedCmd := maskCredentials(line, secretVal)

	reason := "Discovered hardcoded password or credential in shell history"
	if matchType == "connection" {
		reason = "Discovered database credentials in command execution history"
	}

	return &HistorySecretResult{
		User:        username,
		HistoryFile: path,
		LineNumber:  lineNum,
		Command:     maskedCmd,
		RiskLevel:   "CRITICAL",
		Reason:      reason,
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
