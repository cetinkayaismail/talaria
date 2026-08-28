package scanners

import (
	"context"
	"os/exec"
	"path/filepath" // Added missing import
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
	Command       string `json:"command"`
	RunAs         string `json:"run_as"`
	NoPassword    bool   `json:"no_password"`
	IsDangerous   bool   `json:"is_dangerous"`
	HasSetEnv     bool   `json:"has_set_env"`
	HasLDPreload  bool   `json:"has_ld_preload"` // env_keep contains LD_PRELOAD or LD_LIBRARY_PATH
	RiskLevel     string `json:"risk_level"`     // CRITICAL, HIGH, MEDIUM, LOW
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
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
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	hasLDPreloadInEnvKeep := false

	// Check env_keep for LD_PRELOAD
	for _, line := range lines {
		if strings.Contains(line, "env_keep") {
			for _, v := range LDPreloadEnvVars {
				if strings.Contains(line, v) {
					hasLDPreloadInEnvKeep = true
					break
				}
			}
		}
	}

	// Parse command entries
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(") || strings.Contains(line, "NOPASSWD:") || strings.Contains(line, "ALL") {
			noPassword := strings.Contains(line, "NOPASSWD:")
			hasSetEnv := strings.Contains(line, "SETENV:")
			isDangerous := false
			runAs := "root"

			// Extract (runAs) if present
			if strings.HasPrefix(line, "(") {
				endIdx := strings.Index(line, ")")
				if endIdx != -1 {
					runAs = line[1:endIdx]
				}
			}

			// Clean the command entry
			cmdEntry := line
			if idx := strings.Index(line, ")"); idx != -1 {
				cmdEntry = strings.TrimSpace(line[idx+1:])
			}
			cmdEntry = strings.TrimPrefix(cmdEntry, "NOPASSWD:")
			cmdEntry = strings.TrimPrefix(cmdEntry, "SETENV:")
			cmdEntry = strings.TrimSpace(cmdEntry)

			isDangerous = checkSudoDanger(cmdEntry)

			riskLevel := "LOW"
			reason := "Normal sudo privilege"
			remediation := ""
			complianceTag := "CIS-Linux-5.3.4 / DISA-STIG-V-230534"

			if hasLDPreloadInEnvKeep {
				riskLevel = "CRITICAL"
				reason = "LD_PRELOAD in env_keep allows arbitrary code execution via shared library injection"
				remediation = "visudo -f /etc/sudoers (remove LD_PRELOAD from env_keep)"
			} else if isDangerous || hasSetEnv {
				riskLevel = "CRITICAL"
				reason = "Direct shell escape or SETENV privilege"
				remediation = "visudo -f /etc/sudoers (remove NOPASSWD/SETENV and restrict command arguments)"
			} else if noPassword {
				riskLevel = "HIGH"
				reason = "NOPASSWD entry without dangerous command — context-dependent"
				remediation = "visudo -f /etc/sudoers (require password authentication for privileged commands)"
			}

			results = append(results, SudoPrivilegeResult{
				Command:       cmdEntry,
				RunAs:         runAs,
				NoPassword:    noPassword,
				IsDangerous:   isDangerous || hasSetEnv,
				HasSetEnv:     hasSetEnv,
				HasLDPreload:  hasLDPreloadInEnvKeep,
				RiskLevel:     riskLevel,
				Reason:        reason,
				Remediation:   remediation,
				ComplianceTag: complianceTag,
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
