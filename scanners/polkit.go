package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PolkitRuleResult represents a parsed Polkit rule finding
type PolkitRuleResult struct {
	FilePath      string `json:"file_path"`
	Action        string `json:"action"`
	Authorized    string `json:"authorized"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// ScanPolkitRules audits custom rules in /etc/polkit-1/rules.d/
func ScanPolkitRules() ([]PolkitRuleResult, error) {
	var results []PolkitRuleResult

	rulesDir := "/etc/polkit-1/rules.d"
	// Check if directory exists
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		return nil, nil // Return empty, no error
	}

	files, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range files {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".rules") {
			continue
		}

		path := filepath.Join(rulesDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue // Gracefully skip unreadable files
		}

		res := parsePolkitContent(string(data), path)
		if len(res) > 0 {
			results = append(results, res...)
		}
	}

	return results, nil
}

// parsePolkitContent parses JavaScript rule contents into structural findings
func parsePolkitContent(content string, filePath string) []PolkitRuleResult {
	var results []PolkitRuleResult

	// 1. Strip comments to avoid matching commented-out rules
	content = stripComments(content)

	// 2. Loop and find polkit.addRule declarations
	idx := 0
	for {
		startIdx := strings.Index(content[idx:], "polkit.addRule")
		if startIdx == -1 {
			break
		}
		startIdx += idx

		// Find opening parenthesis
		parenStart := strings.Index(content[startIdx:], "(")
		if parenStart == -1 {
			idx = startIdx + 14
			continue
		}
		parenStart += startIdx

		// Extract function body block using brace/parenthesis matching (extremely robust)
		block, nextIdx := extractJavaScriptBlock(content, parenStart)
		if block == "" {
			idx = startIdx + 14
			continue
		}
		idx = nextIdx

		// Audit the isolated block
		res := auditRuleBlock(block, filePath)
		if res != nil {
			results = append(results, *res)
		}
	}

	return results
}

// extractJavaScriptBlock balances braces and parentheses to extract a JS statement safely
func extractJavaScriptBlock(content string, start int) (string, int) {
	parenCount := 0
	braceCount := 0
	end := start

	for i := start; i < len(content); i++ {
		char := content[i]
		if char == '(' {
			parenCount++
		} else if char == ')' {
			parenCount--
			if parenCount == 0 && braceCount == 0 {
				end = i
				return content[start : end+1], i + 1
			}
		} else if char == '{' {
			braceCount++
		} else if char == '}' {
			braceCount--
		}
	}
	return "", start + 1
}

// auditRuleBlock evaluates an isolated callback function block for security flaws
func auditRuleBlock(block string, filePath string) *PolkitRuleResult {
	// Look for yes/auth resolutions.
	// If it doesn't return YES or AUTH_SELF_KEEP, it's not granting privilege
	hasYes := strings.Contains(block, "polkit.Result.YES")
	hasAuthSelfKeep := strings.Contains(block, "polkit.Result.AUTH_SELF_KEEP")

	if !hasYes && !hasAuthSelfKeep {
		return nil
	}

	// 1. Extract action ID check (supporting double and single quotes)
	action := "Any Action"
	actionPattern := regexp.MustCompile(`action\.id\s*(?:==|===|=~)\s*"([^"]+)"`)
	if m := actionPattern.FindStringSubmatch(block); len(m) > 1 {
		action = m[1]
	} else {
		actionPatternSq := regexp.MustCompile(`action\.id\s*(?:==|===|=~)\s*'([^']+)'`)
		if mSq := actionPatternSq.FindStringSubmatch(block); len(mSq) > 1 {
			action = mSq[1]
		}
	}

	// 2. Extract groups checked (subject.isInGroup)
	var groups []string
	groupPattern := regexp.MustCompile(`subject\.isInGroup\s*\(\s*"([^"]+)"\s*\)`)
	for _, m := range groupPattern.FindAllStringSubmatch(block, -1) {
		if len(m) > 1 {
			groups = append(groups, m[1])
		}
	}
	groupPatternSq := regexp.MustCompile(`subject\.isInGroup\s*\(\s*'([^']+)'\s*\)`)
	for _, m := range groupPatternSq.FindAllStringSubmatch(block, -1) {
		if len(m) > 1 {
			groups = append(groups, m[1])
		}
	}

	// 3. Extract user checks (subject.user)
	var users []string
	userPattern := regexp.MustCompile(`subject\.user\s*(?:==|===)\s*"([^"]+)"`)
	for _, m := range userPattern.FindAllStringSubmatch(block, -1) {
		if len(m) > 1 {
			users = append(users, m[1])
		}
	}
	userPatternSq := regexp.MustCompile(`subject\.user\s*(?:==|===)\s*'([^']+)'`)
	for _, m := range userPatternSq.FindAllStringSubmatch(block, -1) {
		if len(m) > 1 {
			users = append(users, m[1])
		}
	}

	// Whitelist: standard administration groups that are perfectly safe
	standardPrivilegedGroups := map[string]bool{
		"root": true, "sudo": true, "wheel": true, "admin": true,
		"systemd-journal": true, "adm": true,
	}

	// Whitelist filtering (Zero False Positive Goal):
	// If the rule restricts authorization to standard administrative groups/users, skip completely!
	if len(groups) > 0 || len(users) > 0 {
		allPrivileged := true
		for _, g := range groups {
			if !standardPrivilegedGroups[strings.ToLower(g)] {
				allPrivileged = false
				break
			}
		}
		for _, u := range users {
			if u != "root" {
				allPrivileged = false
				break
			}
		}

		if allPrivileged {
			return nil // Perfectly normal administrative authorization, skip to avoid FPs
		}
	}

	// Build description
	authorized := "Any User"
	if len(groups) > 0 || len(users) > 0 {
		var auths []string
		for _, g := range groups {
			auths = append(auths, "Group: "+g)
		}
		for _, u := range users {
			auths = append(auths, "User: "+u)
		}
		authorized = strings.Join(auths, ", ")
	}

	reason := "Allows passwordless authorization to action: " + action
	if authorized == "Any User" {
		reason = "CRITICAL: Unconditional root/action authorization granted to any user for: " + action
	}

	return &PolkitRuleResult{
		FilePath:      filePath,
		Action:        action,
		Authorized:    authorized,
		IsDangerous:   true,
		Reason:        reason,
		Remediation:   fmt.Sprintf("chmod 0644 %s && replace polkit.Result.YES with polkit.Result.AUTH_ADMIN", filePath),
		ComplianceTag: "CIS-Linux-5.3.5 / NIST-AC-6",
	}
}

// stripComments removes JavaScript single and multi-line comments
func stripComments(content string) string {
	// Strip single line comments // ...
	reSingle := regexp.MustCompile(`//.*`)
	content = reSingle.ReplaceAllString(content, "")

	// Strip multi-line comments /* ... */
	reMulti := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	content = reMulti.ReplaceAllString(content, "")

	return content
}
