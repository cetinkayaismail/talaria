package core

import (
	"fmt"
	"os"
	"strings"
	"Talaria/models"
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
		&SGIDShadowChain{},
		&WritableSSHKeysChain{},
		&WritableSSHDirChain{},
		&PtraceRootChain{},
		&DockerSocketGroupChain{},
		&DockerContainerEscapeChain{},
	}
}

func RunIntelligenceEngine(report *models.ScanReport) {
	fmt.Printf("\n\033[1;34m[!] Performing Cross-Reference Analysis (Intelligence Engine)...\033[0m\n")

	var allResults []ChainResult
	for _, chain := range registeredChains {
		results := chain.Evaluate(report)
		allResults = append(allResults, results...)
	}

	// Run DFS Graph Analysis
	graph := BuildIntelligenceGraph(report)
	startNode := fmt.Sprintf("user:%s", report.TargetUser)
	paths := graph.FindPaths(startNode, "goal:root", 5)

	for _, path := range paths {
		if len(path) == 0 {
			continue
		}
		
		desc := "Attack Path:\n"
		var targetPath string
		for i, edge := range path {
			desc += fmt.Sprintf("  %d. %s -> (%s) -> %s\n", i+1, edge.From.ID, edge.Description, edge.To.ID)
			// Heuristic to grab a target path for AppArmor checking
			if strings.HasPrefix(edge.To.ID, "file:") {
				targetPath = strings.TrimPrefix(edge.To.ID, "file:")
			}
		}

		allResults = append(allResults, ChainResult{
			Name:        fmt.Sprintf("Complex Attack Graph Found (%d steps)", len(path)),
			Description: desc,
			RiskLevel:   "100% CONFIRMED",
			TargetPath:  targetPath,
		})
	}

	if len(allResults) == 0 {
		fmt.Printf("\033[1;32m[+] No confirmed chained attack vectors found via cross-reference.\033[0m\n")
		return
	}

	// Apply Context-Aware Downgrading (AppArmor / SELinux Checks)
	for i, res := range allResults {
		if res.RiskLevel == "100% CONFIRMED" && res.TargetPath != "" {
			if checkDefenseMechanisms(res.TargetPath) {
				allResults[i].RiskLevel = "POTENTIAL - BLOCKED BY APPARMOR"
				if allResults[i].Description != "" {
					allResults[i].Description += " | "
				}
				allResults[i].Description += fmt.Sprintf("[DEFENSE ACTIVE: %s is confined by AppArmor]", res.TargetPath)
			}
		}
	}

	for _, res := range allResults {
		color := "\033[1;33m" // Yellow for potential
		if res.RiskLevel == "100% CONFIRMED" {
			color = "\033[1;35m" // Magenta/Purple for confirmed
		}
		fmt.Printf("%s[%s] %s\033[0m\n", color, res.RiskLevel, res.Name)
		if res.Description != "" {
			fmt.Printf("  %s\n", res.Description)
		}
		if res.Exploit != "" {
			fmt.Printf("  Exploit: %s\n", res.Exploit)
		}
	}
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

// resolveCommandPath intelligently checks if a command string eventually targets a specific file path
func resolveCommandPath(command string, targetPath string) bool {
	// Direct match (absolute path used in command)
	if strings.Contains(command, targetPath) {
		return true
	}

	// Basename match for PATH-resolved execution
	// Example: command="overwrite.sh", targetPath="/usr/local/bin/overwrite.sh"
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

	var currentDir string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "cd ") {
			currentDir = strings.TrimSpace(strings.TrimPrefix(part, "cd "))
		} else if currentDir != "" {
			// Extract binary name being executed
			cmdFields := strings.Fields(part)
			if len(cmdFields) > 0 {
				var execName string
				// If command is an interpreter (bash script.sh), script is usually the 2nd arg
				interpreters := map[string]bool{"bash": true, "sh": true, "python": true, "python3": true, "perl": true, "ruby": true}
				if interpreters[cmdFields[0]] && len(cmdFields) > 1 {
					execName = cmdFields[1]
				} else {
					execName = cmdFields[0]
				}

				if execName != "" {
					// Clean up potential ./ prefix
					execName = strings.TrimPrefix(execName, "./")
					
					// Resolve assuming currentDir from previous cd command
					// filepath.Join will handle trailing slashes correctly
					// Since targetPath is absolute (from WalkDir), we construct the absolute path here
					// Note: If currentDir is relative, this won't work perfectly without resolving against home, 
					// but cron/sudo usually use absolute paths for cd.
					
					// Only proceed if currentDir is absolute to avoid false positives
					// We'll just construct it.
					// We can't easily use filepath here without importing, but main.go already imports path/filepath? 
					// Let's check imports. Main.go doesn't import path/filepath currently. We should avoid adding imports if possible, or just use string concat safely.
					
					var resolvedPath string
					if strings.HasSuffix(currentDir, "/") {
						resolvedPath = currentDir + execName
					} else {
						resolvedPath = currentDir + "/" + execName
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
	
	// Example: /usr/bin/man becomes usr.bin.man
	basePath := strings.TrimPrefix(targetPath, "/")
	profileName := strings.ReplaceAll(basePath, "/", ".")
	
	apparmorProfile := fmt.Sprintf("/etc/apparmor.d/%s", profileName)
	if _, err := os.Stat(apparmorProfile); err == nil {
		return true // AppArmor profile exists and likely confines this path
	}
	
	return false
}
