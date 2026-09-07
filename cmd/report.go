package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"talaria/core"
	"talaria/models"
)

type textSection struct {
	Title string
	Lines []string
}

// SaveReport writes the scan results to disk in the requested format (text, json, or sarif), with optional encryption.
func SaveReport(report *models.ScanReport, path, format, encryptKey string) error {
	var data []byte

	switch strings.ToLower(format) {
	case "json":
		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("JSON serialization failed: %w", err)
		}
		data = jsonData
	case "sarif":
		sarifData, err := core.GenerateSARIFReport(report)
		if err != nil {
			return fmt.Errorf("SARIF serialization failed: %w", err)
		}
		data = sarifData
	default:
		data = []byte(GenerateTextReport(report))
	}

	// Optional AES-256-GCM encryption
	if encryptKey != "" {
		encrypted, err := core.EncryptReport(data, encryptKey)
		if err != nil {
			fmt.Printf("\033[1;31m[-] Encryption failed: %v — saving plaintext\033[0m\n", err)
		} else {
			data = encrypted
			fmt.Printf("\033[1;32m[+] Report encrypted with AES-256-GCM\033[0m\n")
		}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}
	fmt.Printf("\033[1;32m[+] Report saved to %s\033[0m\n", path)
	return nil
}

// GenerateTextReport formats the ScanReport into human-readable text covering all scanner sections.
func GenerateTextReport(report *models.ScanReport) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Talaria Scan Report\n===================\nScan Time: %s\nTarget: %s @ %s\n\n", report.ScanTime, report.TargetUser, report.TargetScanPath))

	var sections []textSection

	// Secrets
	if len(report.Secrets) > 0 {
		var lines []string
		for _, r := range report.Secrets {
			lines = append(lines, fmt.Sprintf("[%s] %s\n  Type: %s", r.RiskLevel, r.Path, r.Type))
		}
		sections = append(sections, textSection{"Secrets", lines})
	}

	// SUID
	if len(report.SUID) > 0 {
		var lines []string
		for _, r := range report.SUID {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Reason: %s", r.Path, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"SUID Binaries", lines})
		}
	}

	// SGID
	if len(report.SGID) > 0 {
		var lines []string
		for _, r := range report.SGID {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Reason: %s", r.Path, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"SGID Binaries", lines})
		}
	}

	// Sudo Privileges
	if len(report.SudoPrivileges) > 0 {
		var lines []string
		for _, r := range report.SudoPrivileges {
			if r.IsDangerous || r.NoPassword {
				lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.Command, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Sudo Privileges", lines})
		}
	}

	// Sudo Tokens
	if len(report.SudoTokens) > 0 {
		var lines []string
		for _, r := range report.SudoTokens {
			lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.Vector, r.Reason))
		}
		sections = append(sections, textSection{"Sudo Tokens & TTY Hijack", lines})
	}

	// Capabilities
	if len(report.Capabilities) > 0 {
		var lines []string
		for _, r := range report.Capabilities {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Caps: %s", r.Path, r.Capabilities))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Capabilities", lines})
		}
	}

	// Writable Files
	if len(report.Writeable) > 0 {
		var lines []string
		for _, r := range report.Writeable {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.Path, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Writable Files", lines})
		}
	}

	// Cron Jobs
	if len(report.CronJobs) > 0 {
		var lines []string
		for _, r := range report.CronJobs {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Reason: %s", r.Command, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Cron Jobs", lines})
		}
	}

	// Systemd Timers
	if len(report.SystemdTimers) > 0 {
		var lines []string
		for _, r := range report.SystemdTimers {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Reason: %s", r.Path, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Systemd Timers", lines})
		}
	}

	// Network Connections
	if len(report.NetworkConnections) > 0 {
		var lines []string
		for _, r := range report.NetworkConnections {
			if r.State == "LISTEN" {
				severity := "INFO"
				if r.RiskLevel != "" {
					severity = r.RiskLevel
				}
				lines = append(lines, fmt.Sprintf("[%s] %s:%d (%s) — %s", severity, r.LocalAddr, r.LocalPort, r.Protocol, r.ProcessName))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Network Connections", lines})
		}
	}

	// NFS Exports
	if len(report.NFSExports) > 0 {
		var lines []string
		for _, r := range report.NFSExports {
			if r.HasNoRootSquash {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s — no_root_squash", r.Path))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"NFS Exports", lines})
		}
	}

	// Processes
	if len(report.Processes) > 0 {
		var lines []string
		for _, r := range report.Processes {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] PID %d (%s) — %s", r.PID, r.User, r.Command))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Processes", lines})
		}
	}

	// Sockets
	if len(report.Sockets) > 0 {
		var lines []string
		for _, r := range report.Sockets {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s — %s", r.Path, r.Service))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Sockets", lines})
		}
	}

	// File Permissions
	if len(report.FilePermissions) > 0 {
		var lines []string
		for _, r := range report.FilePermissions {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s (%s)\n  Issue: %s", r.Path, r.Permissions, r.Issue))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"File Permissions", lines})
		}
	}

	// File Perms Exploit
	if len(report.FilePermsExploit) > 0 {
		var lines []string
		for _, r := range report.FilePermsExploit {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s — %s", r.Path, r.ExploitMethod))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"File Permissions Exploit", lines})
		}
	}

	// Groups
	if len(report.Groups) > 0 {
		var lines []string
		for _, r := range report.Groups {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Reason: %s", r.GroupName, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Privileged Groups", lines})
		}
	}

	// PATH Hijack
	if len(report.PATHHijack) > 0 {
		var lines []string
		for _, r := range report.PATHHijack {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Reason: %s", r.Directory, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"PATH Hijacking", lines})
		}
	}

	// SSH Keys
	if len(report.SSHKeys) > 0 {
		var lines []string
		for _, r := range report.SSHKeys {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s (%s)\n  Reason: %s", r.Path, r.Type, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"SSH Keys", lines})
		}
	}

	// Ptrace Scope
	if report.PtraceScope != nil && report.PtraceScope.IsDangerous {
		sections = append(sections, textSection{"Ptrace Scope", []string{
			fmt.Sprintf("[CRITICAL] Scope: %d\n  Reason: %s", report.PtraceScope.Scope, report.PtraceScope.Reason),
		}})
	}

	// Container Escape
	if len(report.ContainerEscape) > 0 {
		var lines []string
		for _, r := range report.ContainerEscape {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Reason: %s", r.Vector, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Container Escape", lines})
		}
	}

	// D-Bus Policy
	if len(report.DBusPolicy) > 0 {
		var lines []string
		for _, r := range report.DBusPolicy {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Reason: %s", r.ServiceName, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"D-Bus Policies", lines})
		}
	}

	// Services
	if len(report.Services) > 0 {
		var lines []string
		for _, r := range report.Services {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s\n  Reason: %s", r.ServiceName, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Local Services", lines})
		}
	}

	// Packages
	if len(report.Packages) > 0 {
		var lines []string
		for _, r := range report.Packages {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.Name, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Package Managers", lines})
		}
	}

	// Vulnerabilities
	if len(report.Vulnerabilities) > 0 {
		var lines []string
		for _, r := range report.Vulnerabilities {
			if r.IsDangerous {
				for _, v := range r.Vulnerabilities {
					lines = append(lines, fmt.Sprintf("[CRITICAL] %s — %s (%s %s)", v.CVE, v.Name, r.Software, r.Version))
				}
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"System Vulnerabilities", lines})
		}
	}

	// Session Hijack
	if len(report.SessionHijack) > 0 {
		var lines []string
		for _, r := range report.SessionHijack {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s (owner: %s)\n  Reason: %s", r.Path, r.TargetUser, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Session Hijack", lines})
		}
	}

	// Kernel Config
	if len(report.KernelConfig) > 0 {
		var lines []string
		for _, r := range report.KernelConfig {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.ConfigKey, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Kernel Config", lines})
		}
	}

	// Polkit Rules
	if len(report.PolkitRules) > 0 {
		var lines []string
		for _, r := range report.PolkitRules {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s — %s (%s)", r.FilePath, r.Action, r.Authorized))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Polkit Rules", lines})
		}
	}

	// History Secrets
	if len(report.HistorySecrets) > 0 {
		var lines []string
		for _, r := range report.HistorySecrets {
			lines = append(lines, fmt.Sprintf("[%s] %s:%d\n  Cmd: %s", r.RiskLevel, r.HistoryFile, r.LineNumber, r.Command))
		}
		sections = append(sections, textSection{"Shell History Secrets", lines})
	}

	// XAuthority
	if len(report.XAuthority) > 0 {
		var lines []string
		for _, r := range report.XAuthority {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[CRITICAL] %s (owner: %s)\n  Reason: %s", r.Path, r.TargetUser, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"X11 Authority", lines})
		}
	}

	// Logrotate
	if len(report.Logrotate) > 0 {
		var lines []string
		for _, r := range report.Logrotate {
			lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.ConfigPath, r.Reason))
		}
		sections = append(sections, textSection{"Logrotate", lines})
	}

	// EnvironmentFile
	if len(report.EnvFileResults) > 0 {
		var lines []string
		for _, r := range report.EnvFileResults {
			lines = append(lines, fmt.Sprintf("[%s] %s → %s\n  Reason: %s", r.RiskLevel, r.ServiceFile, r.EnvFilePath, r.Reason))
		}
		sections = append(sections, textSection{"Systemd EnvironmentFile", lines})
	}

	// PAM
	if len(report.PAMResults) > 0 {
		var lines []string
		for _, r := range report.PAMResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.Path, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"PAM Security Policies", lines})
		}
	}

	// Sysctl
	if len(report.SysctlResults) > 0 {
		var lines []string
		for _, r := range report.SysctlResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s = %s (expected %s)\n  Reason: %s", r.RiskLevel, r.Key, r.CurrentValue, r.ExpectedVal, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Kernel Sysctl Hardening", lines})
		}
	}

	// Systemd Overrides
	if len(report.SystemdOverrides) > 0 {
		var lines []string
		for _, r := range report.SystemdOverrides {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s (%s)\n  Reason: %s", r.RiskLevel, r.Path, r.ServiceName, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Systemd Unit Overrides", lines})
		}
	}

	// SubUID
	if len(report.SubUIDResults) > 0 {
		var lines []string
		for _, r := range report.SubUIDResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s (%s)\n  Reason: %s", r.RiskLevel, r.Type, r.TargetUser, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Unprivileged Namespaces & SubUID", lines})
		}
	}

	// Mounts
	if len(report.MountResults) > 0 {
		var lines []string
		for _, r := range report.MountResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s (missing %s)\n  Reason: %s", r.RiskLevel, r.MountPoint, r.MissingFlag, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Shared Memory & Temp Mount Flags", lines})
		}
	}

	// ELF RPATH
	if len(report.ELFRPathResults) > 0 {
		var lines []string
		for _, r := range report.ELFRPathResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s (%s: %s)\n  Reason: %s", r.RiskLevel, r.Path, r.TagType, r.Value, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Dynamic ELF RPATH / RUNPATH", lines})
		}
	}

	// Auditd
	if len(report.AuditdResults) > 0 {
		var lines []string
		for _, r := range report.AuditdResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s (%d rules)\n  Reason: %s", r.RiskLevel, r.DaemonName, r.RuleCount, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Active System Audit Daemons", lines})
		}
	}

	// Udev
	if len(report.UdevResults) > 0 {
		var lines []string
		for _, r := range report.UdevResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s (%s)\n  Reason: %s", r.RiskLevel, r.RuleFile, r.Directive, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Udev Event Rules", lines})
		}
	}

	// Cron Dirs
	if len(report.CronDirResults) > 0 {
		var lines []string
		for _, r := range report.CronDirResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.Path, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Cron & Timer Directory Permissions", lines})
		}
	}

	// ProcEnv
	if len(report.ProcEnvResults) > 0 {
		var lines []string
		for _, r := range report.ProcEnvResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] PID %d (%s) — Key: %s (Preview: %s)\n  Reason: %s", r.RiskLevel, r.PID, r.ProcessName, r.Key, r.ValueSample, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Exposed Process Environment Secrets", lines})
		}
	}

	// LD/NSS
	if len(report.LDNSSResults) > 0 {
		var lines []string
		for _, r := range report.LDNSSResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.Path, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Dynamic Linker & NSS", lines})
		}
	}

	// Modprobe
	if len(report.ModprobeResults) > 0 {
		var lines []string
		for _, r := range report.ModprobeResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s\n  Reason: %s", r.RiskLevel, r.Path, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Modprobe Kernel Module Rules", lines})
		}
	}

	// Cloud Meta
	if len(report.CloudMetaResults) > 0 {
		var lines []string
		for _, r := range report.CloudMetaResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s — %s", r.RiskLevel, r.Provider, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Cloud Metadata & Kubernetes", lines})
		}
	}

	// VenvWrap
	if len(report.VenvWrapResults) > 0 {
		var lines []string
		for _, r := range report.VenvWrapResults {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s (%s)\n  Reason: %s", r.RiskLevel, r.Path, r.TargetType, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Python VirtualEnvs & Wrappers", lines})
		}
	}

	// Wildcards
	if len(report.Wildcards) > 0 {
		var lines []string
		for _, r := range report.Wildcards {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s (%s)\n  WorkingDir: %s\n  Reason: %s", r.RiskLevel, r.Command, r.VulnerableCmd, r.WorkingDir, r.Reason))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Wildcard Injections", lines})
		}
	}

	// Python Library Hijacking
	if len(report.PythonHijack) > 0 {
		var lines []string
		for _, r := range report.PythonHijack {
			if r.IsDangerous {
				lines = append(lines, fmt.Sprintf("[%s] %s (%s)\n  Path: %s\n  Reason: %s\n  Exploit: %s", r.RiskLevel, r.Type, r.ScriptName, r.Path, r.Reason, r.ExploitHint))
			}
		}
		if len(lines) > 0 {
			sections = append(sections, textSection{"Python Library Hijacking", lines})
		}
	}

	// Render all sections
	for _, sec := range sections {
		sb.WriteString(fmt.Sprintf("=== %s ===\n", sec.Title))
		for _, line := range sec.Lines {
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("\nSummary Counts:\nSecrets: %d | SUID: %d | SGID: %d | Sudo: %d | Sudo Tokens: %d\nCapabilities: %d | CronJobs: %d | Timers: %d | Writeable: %d\nNetwork: %d | NFS: %d | Processes: %d | Sockets: %d\nFilePerms: %d | FilePermsExploit: %d | Groups: %d | PATH Hijack: %d\nSSH Keys: %d | Container: %d | D-Bus: %d | Services: %d | Packages: %d\nVulnerabilities: %d | Sessions: %d | KernelConfig: %d | Polkit: %d\nHistory: %d | XAuth: %d | Logrotate: %d | EnvFile: %d\nPAM: %d | Sysctl: %d | SystemdOverrides: %d | SubUID: %d\nMounts: %d | ELF RPATH: %d | Auditd: %d | Udev: %d\nCronDirs: %d | ProcEnv: %d | LD/NSS: %d | Modprobe: %d\nCloudMeta: %d | VenvWrap: %d | Wildcards: %d | PythonHijack: %d\n",
		len(report.Secrets), len(report.SUID), len(report.SGID), len(report.SudoPrivileges), len(report.SudoTokens),
		len(report.Capabilities), len(report.CronJobs), len(report.SystemdTimers), len(report.Writeable),
		len(report.NetworkConnections), len(report.NFSExports), len(report.Processes), len(report.Sockets),
		len(report.FilePermissions), len(report.FilePermsExploit), len(report.Groups), len(report.PATHHijack),
		len(report.SSHKeys), len(report.ContainerEscape), len(report.DBusPolicy), len(report.Services), len(report.Packages),
		len(report.Vulnerabilities), len(report.SessionHijack), len(report.KernelConfig), len(report.PolkitRules),
		len(report.HistorySecrets), len(report.XAuthority), len(report.Logrotate), len(report.EnvFileResults),
		len(report.PAMResults), len(report.SysctlResults), len(report.SystemdOverrides), len(report.SubUIDResults),
		len(report.MountResults), len(report.ELFRPathResults), len(report.AuditdResults), len(report.UdevResults),
		len(report.CronDirResults), len(report.ProcEnvResults), len(report.LDNSSResults), len(report.ModprobeResults),
		len(report.CloudMetaResults), len(report.VenvWrapResults), len(report.Wildcards), len(report.PythonHijack)))

	return sb.String()
}

// EvaluatePolicy checks if any finding meets or exceeds the specified failOn threshold (Phase 4).
// Returns true if the policy failed (i.e. process should terminate with exit code 1).
func EvaluatePolicy(report *models.ScanReport, failOn string) (bool, string) {
	if failOn == "" {
		return false, ""
	}

	threshold := strings.ToUpper(failOn)

	criticalCount, highCount, mediumCount := countFindingsBySeverity(report)

	switch threshold {
	case "CRITICAL":
		if criticalCount > 0 {
			return true, fmt.Sprintf("CI/CD Policy Gate Violated: %d CRITICAL findings detected (threshold: %s)", criticalCount, threshold)
		}
	case "HIGH":
		if criticalCount > 0 || highCount > 0 {
			return true, fmt.Sprintf("CI/CD Policy Gate Violated: %d CRITICAL and %d HIGH findings detected (threshold: %s)", criticalCount, highCount, threshold)
		}
	case "MEDIUM":
		if criticalCount > 0 || highCount > 0 || mediumCount > 0 {
			return true, fmt.Sprintf("CI/CD Policy Gate Violated: %d CRITICAL, %d HIGH, and %d MEDIUM findings detected (threshold: %s)", criticalCount, highCount, mediumCount, threshold)
		}
	}

	return false, fmt.Sprintf("CI/CD Policy Gate Passed: 0 findings exceeded threshold '%s'", threshold)
}

func countFindingsBySeverity(report *models.ScanReport) (int, int, int) {
	critical := 0
	high := 0
	medium := 0

	addSeverity := func(risk string) {
		r := strings.ToUpper(risk)
		if strings.Contains(r, "CRITICAL") {
			critical++
		} else if strings.Contains(r, "HIGH") {
			high++
		} else if strings.Contains(r, "MEDIUM") {
			medium++
		}
	}

	for _, s := range report.Secrets {
		addSeverity(s.RiskLevel)
	}
	for _, s := range report.SUID {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.SGID {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.SudoPrivileges {
		if s.HasLDPreload || s.IsDangerous {
			critical++
		} else if s.NoPassword {
			high++
		} else {
			addSeverity(s.RiskLevel)
		}
	}
	for _, s := range report.SudoTokens {
		if s.IsDangerous {
			addSeverity(s.RiskLevel)
		}
	}
	for _, c := range report.Capabilities {
		if c.IsDangerous {
			critical++
		}
	}
	for _, w := range report.Writeable {
		if w.IsDangerous {
			addSeverity(w.RiskLevel)
		}
	}
	for _, c := range report.CronJobs {
		if c.IsDangerous {
			critical++
		}
	}
	for _, t := range report.SystemdTimers {
		if t.IsDangerous {
			critical++
		}
	}
	for _, w := range report.Wildcards {
		if w.IsDangerous {
			addSeverity(w.RiskLevel)
		}
	}
	for _, p := range report.PythonHijack {
		if p.IsDangerous {
			addSeverity(p.RiskLevel)
		}
	}
	for _, v := range report.Vulnerabilities {
		if v.IsDangerous {
			for _, sub := range v.Vulnerabilities {
				if sub.PatchStatus == "likely_patched" {
					medium++
				} else {
					critical++
				}
			}
		}
	}
	for _, c := range report.ContainerEscape {
		if c.IsDangerous {
			critical++
		}
	}
	for _, p := range report.PolkitRules {
		if p.IsDangerous {
			critical++
		}
	}
	for _, h := range report.HistorySecrets {
		addSeverity(h.RiskLevel)
	}
	for _, e := range report.ELFRPathResults {
		if e.IsDangerous {
			addSeverity(e.RiskLevel)
		}
	}
	for _, p := range report.ProcEnvResults {
		if p.IsDangerous {
			addSeverity(p.RiskLevel)
		}
	}
	for _, m := range report.MountResults {
		if m.IsDangerous {
			addSeverity(m.RiskLevel)
		}
	}
	for _, u := range report.UdevResults {
		if u.IsDangerous {
			addSeverity(u.RiskLevel)
		}
	}
	for _, d := range report.CronDirResults {
		if d.IsDangerous {
			addSeverity(d.RiskLevel)
		}
	}
	for _, l := range report.LDNSSResults {
		if l.IsDangerous {
			addSeverity(l.RiskLevel)
		}
	}
	for _, m := range report.ModprobeResults {
		if m.IsDangerous {
			addSeverity(m.RiskLevel)
		}
	}
	for _, c := range report.CloudMetaResults {
		if c.IsDangerous {
			addSeverity(c.RiskLevel)
		}
	}
	for _, v := range report.VenvWrapResults {
		if v.IsDangerous {
			addSeverity(v.RiskLevel)
		}
	}
	for _, s := range report.SystemdOverrides {
		if s.IsDangerous {
			addSeverity(s.RiskLevel)
		}
	}
	for _, p := range report.PAMResults {
		if p.IsDangerous {
			addSeverity(p.RiskLevel)
		}
	}
	for _, s := range report.SysctlResults {
		if s.IsDangerous {
			addSeverity(s.RiskLevel)
		}
	}
	for _, s := range report.SubUIDResults {
		if s.IsDangerous {
			addSeverity(s.RiskLevel)
		}
	}
	for _, n := range report.NetworkConnections {
		addSeverity(n.RiskLevel)
	}
	for _, n := range report.NFSExports {
		if n.HasNoRootSquash {
			critical++
		} else {
			addSeverity(n.RiskSummary)
		}
	}
	for _, s := range report.Sockets {
		if s.IsDangerous {
			critical++
		}
	}
	for _, f := range report.FilePermissions {
		if f.IsDangerous {
			critical++
		} else if f.IsWorldWritable || f.CanWrite {
			high++
		}
	}
	for _, f := range report.FilePermsExploit {
		if f.IsDangerous {
			critical++
		}
	}
	for _, g := range report.Groups {
		if g.IsDangerous {
			critical++
		}
	}
	for _, p := range report.PATHHijack {
		if p.IsDangerous {
			critical++
		}
	}
	for _, s := range report.SSHKeys {
		if s.IsDangerous {
			critical++
		}
	}
	if report.PtraceScope != nil && report.PtraceScope.IsDangerous {
		critical++
	}
	for _, d := range report.DBusPolicy {
		if d.IsDangerous {
			critical++
		}
	}
	for _, s := range report.Services {
		if s.IsDangerous {
			critical++
		}
	}
	for _, p := range report.Packages {
		if p.IsDangerous {
			addSeverity(p.RiskLevel)
		}
	}
	for _, s := range report.SessionHijack {
		if s.IsDangerous {
			critical++
		}
	}
	for _, k := range report.KernelConfig {
		if k.IsDangerous {
			addSeverity(k.RiskLevel)
		}
	}
	for _, x := range report.XAuthority {
		if x.IsDangerous {
			critical++
		}
	}
	for _, l := range report.Logrotate {
		addSeverity(l.RiskLevel)
	}
	for _, e := range report.EnvFileResults {
		addSeverity(e.RiskLevel)
	}
	for _, a := range report.AuditdResults {
		if a.IsDangerous {
			addSeverity(a.RiskLevel)
		}
	}

	return critical, high, medium
}
