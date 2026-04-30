package scanners

import (
	"context"
	"os/exec"
	"path/filepath" // Added missing import
	"regexp"
	"strings"
	"time"
)

// CriticalSudoCommands: Direct shell escape - these ALWAYS allow privesc without conditions see and take root
var CriticalSudoCommands = []string{
	"bash", "sh", "zsh", "ksh", "tcsh", // Shell interpreters
	"vim", "vi", "nano", "less", "more", // Editors with shell escape (!bash)
	"ed", "python", "python3", "perl", "ruby", // Interpreters with shell capabilities
	"node", "php", // Runtime interpreters
	"cat", "awk", "sed", // Text tools with code execution
	"chmod", "chown", // Permission manipulation
	"visudo", "sudo", // Sudo itself
}

// ConditionalSudoCommands: Can enable privesc in exploitable combinations but also can be used for normal operations
var ConditionalSudoCommands = []string{
	"find",            // find -exec /bin/bash \;
	"docker",          // Container escape vectors
	"kubectl",         // Kubernetes cluster escape
	"mount", "umount", // Mount manipulation
}

type SudoPrivilegeResult struct {
	Command       string
	RunAs         string
	NoPassword    bool
	IsDangerous   bool
	HasSetEnv     bool
	HasLDPreload  bool   // env_keep contains LD_PRELOAD or LD_LIBRARY_PATH
	RiskLevel     string // CRITICAL, HIGH, MEDIUM, LOW
	Reason        string
}

// LDPreloadEnvVars: If any of these appear in env_keep, a NOPASSWD sudo becomes instant root
var LDPreloadEnvVars = []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG"}

func ScanSudoPrivileges(timeout time.Duration, password string) ([]SudoPrivilegeResult, error) {
	var results []SudoPrivilegeResult
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd

	// -n is Non-interactive, -l is List
	if password != "" {
		cmd = exec.CommandContext(ctx, "sudo", "-S", "-l")
		cmd.Stdin = strings.NewReader(password + "\n")
	} else {
		cmd = exec.CommandContext(ctx, "sudo", "-n", "-l")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return results, nil
	}

	lines := strings.Split(string(output), "\n")

	// First pass: scan for env_keep lines containing dangerous LD_* vars
	// This is the LD_PRELOAD privesc vector: env_keep += LD_PRELOAD + NOPASSWD = instant root
	hasLDPreloadInEnvKeep := false
	for _, line := range lines {
		lineLower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lineLower, "env_keep") {
			for _, ldVar := range LDPreloadEnvVars {
				if strings.Contains(line, ldVar) {
					hasLDPreloadInEnvKeep = true
					break
				}
			}
		}
	}

	// Inject a synthetic result for LD_PRELOAD env_keep if detected
	if hasLDPreloadInEnvKeep {
		results = append(results, SudoPrivilegeResult{
			Command:      "env_keep contains LD_PRELOAD/LD_LIBRARY_PATH",
			RunAs:        "root",
			NoPassword:   false,
			IsDangerous:  true,
			HasSetEnv:    true,
			HasLDPreload: true,
			RiskLevel:    "CRITICAL",
			Reason:       "sudoers env_keep preserves LD_PRELOAD/LD_LIBRARY_PATH: compile a .so, set LD_PRELOAD, run any NOPASSWD command -> instant root",
		})
	}

	// Regex to extract (User) [Flags] Command
	re := regexp.MustCompile(`\((.*?)\)\s+(?:(.*?):)?\s*(.*)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if !strings.Contains(line, "(") || !strings.Contains(line, ")") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) < 4 {
			continue
		}

		runAs := matches[1]
		flags := matches[2]
		cmdPart := matches[3]

		noPassword := strings.Contains(flags, "NOPASSWD")
		hasSetEnv := strings.Contains(flags, "SETENV")

		commands := strings.Split(cmdPart, ",")

		for _, cmdEntry := range commands {
			cmdEntry = strings.TrimSpace(cmdEntry)
			if cmdEntry == "" {
				continue
			}

			isDangerous := checkSudoDanger(cmdEntry)
			riskLevel := "LOW"
			reason := ""
			if isDangerous || hasSetEnv {
				riskLevel = "CRITICAL"
				reason = "Direct shell escape or SETENV privilege"
			} else if noPassword {
				riskLevel = "HIGH"
				reason = "NOPASSWD entry without dangerous command — context-dependent"
			}

			results = append(results, SudoPrivilegeResult{
				Command:      cmdEntry,
				RunAs:        runAs,
				NoPassword:   noPassword,
				IsDangerous:  isDangerous || hasSetEnv,
				HasSetEnv:    hasSetEnv,
				HasLDPreload: hasLDPreloadInEnvKeep,
				RiskLevel:    riskLevel,
				Reason:       reason,
			})
		}
	}
	return results, nil
}

func checkSudoDanger(command string) bool {
	upperCmd := strings.ToUpper(command)
	lowerCmd := strings.ToLower(command)

	// ALL is always a critical risk
	if strings.Contains(upperCmd, "ALL") {
		return true
	}

	// Clean the command to get just the binary name
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return false
	}

	// Use filepath.Base to get "python" from "/usr/bin/python"
	binary := filepath.Base(parts[0])

	// --- CRITICAL: Direct shell escape commands ---
	for _, critical := range CriticalSudoCommands {
		if strings.EqualFold(binary, critical) {
			return true
		}
	}

	// --- CONDITIONAL: Commands dangerous with specific flags/args ---
	for _, conditional := range ConditionalSudoCommands {
		if strings.EqualFold(binary, conditional) {
			// find -exec: Always dangerous with sudo
			if strings.EqualFold(binary, "find") && strings.Contains(lowerCmd, "-exec") {
				return true
			}
			// docker/kubectl: Container escape vectors
			if strings.EqualFold(binary, "docker") || strings.EqualFold(binary, "kubectl") {
				return true
			}
		}
	}

	return false
}
