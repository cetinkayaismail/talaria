package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"talaria/core"
	"talaria/models"
	"talaria/scanners"
)

// DispatchContext holds the shared state for scanner execution.
type DispatchContext struct {
	Report          *models.ScanReport
	Mu              *sync.Mutex
	Config          *Config
	Timeout         time.Duration
	IOSemaphore     chan struct{}
	SelectedModules map[string]bool
	ExcludedModules map[string]bool
	RunAll          bool
}

// ModuleDescriptor defines a declarative scanner module with phased execution (OPT-02).
type ModuleDescriptor struct {
	Name    string
	Aliases []string
	Phase   int  // 1: Independent scanners; 2: Correlated scanners
	NeedsIO bool // Gate with IOSemaphore to prevent file descriptor exhaustion
	Run     func(ctx *DispatchContext) error
}

// BuildModuleRegistry returns the complete table-driven scanner module registry.
func BuildModuleRegistry() []ModuleDescriptor {
	return []ModuleDescriptor{
		// ── PHASE 1: Independent Scanners ────────────────────────────────────
		{
			Name:    "secrets",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				var searchTargets []string
				if ctx.Config.RootPath != "/" {
					searchTargets = []string{ctx.Config.RootPath}
				} else {
					ctfPaths := []string{
						"/home", "/var/www", "/opt", "/srv", "/etc",
						"/etc/openvpn", "/etc/vpn", "/etc/irssi",
						"/var/www/html", "/opt/app", "/srv/app",
						"/var/backups", "/tmp", "/dev/shm",
					}
					if _, err := os.Stat("/root"); err == nil {
						ctfPaths = append(ctfPaths, "/root")
					}
					searchTargets = ctfPaths
				}

				for _, target := range searchTargets {
					if _, err := os.Stat(target); os.IsNotExist(err) {
						continue
					}
					files, content := scanners.ScanSecrets(target)
					ctx.Mu.Lock()
					ctx.Report.Secrets = append(ctx.Report.Secrets, files...)
					ctx.Report.SecretContent = append(ctx.Report.SecretContent, content...)
					ctx.Mu.Unlock()

					if len(files) > 0 {
						core.PrintSectionHeader(fmt.Sprintf("Secrets: %s", target))
						for _, f := range files {
							core.PrintFinding(f.RiskLevel, "Secret Found", map[string]string{
								"Type": f.Type,
								"Path": f.Path,
							}, f.Remediation)
						}
					}
				}

				rootFiles, rootContent := scanners.ScanRootSecrets()
				if len(rootFiles) > 0 {
					ctx.Mu.Lock()
					ctx.Report.Secrets = append(ctx.Report.Secrets, rootFiles...)
					ctx.Report.SecretContent = append(ctx.Report.SecretContent, rootContent...)
					ctx.Mu.Unlock()

					core.PrintSectionHeader("Root Secrets")
					for _, f := range rootFiles {
						core.PrintFinding("CRITICAL", "Root Secret Found", map[string]string{
							"Type": f.Type,
							"Path": f.Path,
						}, f.Remediation)
					}
				}
				return nil
			},
		},
		{
			Name:    "suid",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanSUID(ctx.Config.RootPath)
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.SUID = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("SUID Binaries")
					for _, r := range results {
						if r.IsDangerous {
							core.PrintFinding("CRITICAL", "Dangerous SUID Binary", map[string]string{
								"Path": r.Path,
							}, r.Remediation)
						} else {
							core.PrintFinding("INFO", "SUID Binary", map[string]string{
								"Path": r.Path,
							}, r.Remediation)
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "sgid",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanSGID(ctx.Config.RootPath)
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.SGID = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("SGID Binaries")
					for _, r := range results {
						core.PrintFinding("INFO", "SGID Binary", map[string]string{
							"Path":   r.Path,
							"Reason": r.Reason,
						}, r.Remediation)
					}
				}
				return nil
			},
		},
		{
			Name:    "processes",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanProcesses()
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.Processes = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Running Processes & ptrace")
					for _, r := range results {
						core.PrintFinding("INFO", "Suspicious Process", map[string]string{
							"PID":     fmt.Sprintf("%d", r.PID),
							"Command": r.Command,
							"User":    r.User,
						}, "")
					}
				}
				return nil
			},
		},
		{
			Name:    "cronjobs",
			Aliases: []string{"cron", "wildcards"},
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanCronJobs()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.CronJobs = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Cron Jobs & Timers")
						for _, r := range results {
							if r.IsDangerous {
								core.PrintFinding("CRITICAL", "CronJob Found", map[string]string{
									"Command": r.Command,
									"Reason":  r.Reason,
								}, r.Remediation)
							} else if r.IsRootJob {
								core.PrintFinding("INFO", "Root CronJob", map[string]string{
									"Command": r.Command,
								}, r.Remediation)
							}
						}
					}
				}

				systemdResults, err := scanners.ScanSystemdTimers()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.SystemdTimers = systemdResults
					ctx.Mu.Unlock()
					for _, r := range systemdResults {
						if r.IsDangerous {
							core.PrintFinding("CRITICAL", "Systemd Timer Found", map[string]string{
								"Path":   r.Path,
								"Reason": r.Reason,
							}, r.Remediation)
						}
					}
				}

				wildcardResults, err := scanners.ScanWildcardInjections()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.Wildcards = wildcardResults
					ctx.Mu.Unlock()
					for _, r := range wildcardResults {
						if r.IsDangerous {
							core.PrintFinding(r.RiskLevel, "Wildcard Injection Target", map[string]string{
								"Command":     r.Command,
								"Utility":     r.VulnerableCmd,
								"WorkingDir":  r.WorkingDir,
								"Source":      r.SourceFile,
								"Reason":      r.Reason,
								"ExploitHint": r.ExploitHint,
							}, r.Remediation)
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "sudo",
			Aliases: []string{"sudotokens", "sudokens"},
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanSudoPrivileges(ctx.Timeout, ctx.Config.SudoPassword)
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.SudoPrivileges = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Sudo Privileges")
						for _, r := range results {
							if r.NoPassword {
								core.PrintFinding("CRITICAL", "NOPASSWD Sudo", map[string]string{
									"Command": r.Command,
									"RunAs":   r.RunAs,
								}, r.Remediation)
							} else {
								core.PrintFinding("INFO", "Sudo Command", map[string]string{
									"Command": r.Command,
									"RunAs":   r.RunAs,
								}, r.Remediation)
							}
						}
					}
				}

				tokenResults, err := scanners.ScanSudoTokensAndTTY()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.SudoTokens = tokenResults
					ctx.Mu.Unlock()
					for _, r := range tokenResults {
						if r.IsDangerous {
							core.PrintFinding(r.RiskLevel, r.Vector, map[string]string{
								"Target": r.Path,
								"Reason": r.Reason,
							}, r.Remediation)
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "capabilities",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanCapabilities(ctx.Config.RootPath)
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.Capabilities = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Capabilities")
					for _, r := range results {
						if r.IsDangerous {
							core.PrintFinding("CRITICAL", "Dangerous Capability", map[string]string{
								"Path":         r.Path,
								"Capabilities": r.Capabilities,
							}, r.Remediation)
						} else {
							core.PrintFinding("INFO", "Capability Found", map[string]string{
								"Path":         r.Path,
								"Capabilities": r.Capabilities,
							}, r.Remediation)
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "nfs",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanNFSExports(ctx.Timeout)
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.NFSExports = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("NFS Exports")
					for _, r := range results {
						if r.IsDangerous {
							core.PrintFinding("CRITICAL", "Dangerous NFS Export", map[string]string{
								"Path":       r.Path,
								"ExportedTo": r.ExportedTo,
							}, r.Remediation)
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "network",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanNetworkConnections()
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.NetworkConnections = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Network Connections")
					for _, r := range results {
						if r.State == "LISTEN" {
							core.PrintFinding(r.RiskLevel, "Active Listener", map[string]string{
								"Address": fmt.Sprintf("%s:%d", r.LocalAddr, r.LocalPort),
								"Process": r.ProcessName,
								"PID":     fmt.Sprintf("%d", r.PID),
							}, "")
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "vulnerabilities",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanSystemVersions()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.Vulnerabilities = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("System Vulnerabilities")
						for _, r := range results {
							if r.IsDangerous {
								for _, v := range r.Vulnerabilities {
									severity := "CRITICAL"
									if v.PatchStatus == "likely_patched" {
										severity = "POTENTIAL"
									}

									details := map[string]string{
										"CVE":      v.CVE,
										"Name":     v.Name,
										"Version":  r.Version,
										"Software": r.Software,
									}
									if v.PatchStatus == "likely_patched" {
										details["Status"] = "Likely patched (backport detected)"
									}
									core.PrintFinding(severity, "Vulnerability Found", details, v.ExploitHint)
								}
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "writeable",
			Aliases: []string{"writable"},
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanWriteable(ctx.Config.RootPath)
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.Writeable = append(ctx.Report.Writeable, results...)
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Writable Files")
					for _, r := range results {
						if r.IsDangerous {
							core.PrintFinding(r.RiskLevel, "Dangerous Writable File", map[string]string{
								"Path":   r.Path,
								"Type":   r.Type,
								"Reason": r.Reason,
							}, r.Remediation)
						}
					}
				}

				if genResults, err := scanners.ScanSystemdGenerators(); err == nil && len(genResults) > 0 {
					ctx.Mu.Lock()
					ctx.Report.Writeable = append(ctx.Report.Writeable, genResults...)
					ctx.Mu.Unlock()
					for _, r := range genResults {
						core.PrintFinding("CRITICAL", "Systemd Generator Writable", map[string]string{
							"Path":   r.Path,
							"Reason": r.Reason,
						}, r.Remediation)
					}
				}

				if svcResults, err := scanners.ScanWritableServices(); err == nil && len(svcResults) > 0 {
					ctx.Mu.Lock()
					ctx.Report.Writeable = append(ctx.Report.Writeable, svcResults...)
					ctx.Mu.Unlock()
					for _, r := range svcResults {
						core.PrintFinding("CRITICAL", "Writable Systemd Service", map[string]string{
							"Path":   r.Path,
							"Reason": r.Reason,
						}, r.Remediation)
					}
				}

				if motdResults, err := scanners.ScanMotdProfiledHijack(); err == nil && len(motdResults) > 0 {
					ctx.Mu.Lock()
					ctx.Report.Writeable = append(ctx.Report.Writeable, motdResults...)
					ctx.Mu.Unlock()
					for _, r := range motdResults {
						core.PrintFinding("CRITICAL", r.Type, map[string]string{
							"Path":   r.Path,
							"Reason": r.Reason,
						}, r.Remediation)
					}
				}

				if anacronResults, err := scanners.ScanAnacronWritability(); err == nil && len(anacronResults) > 0 {
					ctx.Mu.Lock()
					ctx.Report.Writeable = append(ctx.Report.Writeable, anacronResults...)
					ctx.Mu.Unlock()
					for _, r := range anacronResults {
						core.PrintFinding("CRITICAL", r.Type, map[string]string{
							"Path":   r.Path,
							"Reason": r.Reason,
						}, r.Remediation)
					}
				}

				if atResults, err := scanners.ScanAtJobs(); err == nil && len(atResults) > 0 {
					ctx.Mu.Lock()
					ctx.Report.Writeable = append(ctx.Report.Writeable, atResults...)
					ctx.Mu.Unlock()
					for _, r := range atResults {
						core.PrintFinding("CRITICAL", r.Type, map[string]string{
							"Path":   r.Path,
							"Reason": r.Reason,
						}, r.Remediation)
					}
				}

				return nil
			},
		},
		{
			Name:    "initscripts",
			Aliases: []string{"sysv", "init"},
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanInitScripts()
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.Writeable = append(ctx.Report.Writeable, results...)
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("SysV Init Scripts")
					for _, r := range results {
						core.PrintFinding(r.RiskLevel, "Writable SysV Init Script", map[string]string{
							"Path":   r.Path,
							"Type":   r.Type,
							"Reason": r.Reason,
						}, r.Remediation)
					}
				}
				return nil
			},
		},
		{
			Name:    "logrotate",
			Aliases: []string{"logrotated"},
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanLogrotate()
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.Logrotate = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Logrotate Configurations")
					for _, r := range results {
						core.PrintFinding(r.RiskLevel, "Writable Logrotate Config", map[string]string{
							"Path":   r.ConfigPath,
							"Reason": r.Reason,
						}, "")
					}
				}
				return nil
			},
		},
		{
			Name:    "environmentfile",
			Aliases: []string{"envfile", "envfiles"},
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanSystemdEnvFiles()
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.EnvFileResults = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Systemd EnvironmentFile")
					for _, r := range results {
						hint := ""
						if ctx.Config != nil && !ctx.Config.AuditMode {
							hint = fmt.Sprintf("echo 'LD_PRELOAD=/tmp/evil.so' >> %s && systemctl restart %s", r.EnvFilePath, r.ServiceName)
						}
						core.PrintFinding(r.RiskLevel, "Writable Systemd EnvironmentFile", map[string]string{
							"ServiceFile": r.ServiceFile,
							"EnvFile":     r.EnvFilePath,
							"Injection":   r.InjectionType,
							"Reason":      r.Reason,
						}, hint)
					}
				}
				return nil
			},
		},
		{
			Name:    "sockets",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanUnixDomainSockets()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.Sockets = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Sockets")
						for _, r := range results {
							if r.IsDangerous {
								core.PrintFinding("CRITICAL", "Dangerous Socket", map[string]string{
									"Path":    r.Path,
									"Service": r.Service,
								}, "")
							} else if r.IsWritable {
								core.PrintFinding("INFO", "Writable Socket", map[string]string{"Path": r.Path}, "")
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "filepermissions",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanFilePermissions()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.FilePermissions = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("File Permissions")
						for _, r := range results {
							severity := "INFO"
							if r.IsDangerous {
								severity = "CRITICAL"
							} else if r.IsWorldWritable {
								severity = "HIGH"
							}

							core.PrintFinding(severity, "File Permission Issue", map[string]string{
								"Path":   r.Path,
								"Reason": r.Issue,
							}, "")
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "filepermsexploit",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanFilePermissionsExploit(ctx.Timeout)
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.FilePermsExploit = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("File Permissions Exploit")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									if strings.Contains(r.ExploitMethod, "PATH Hijacking") {
										hint = "Prepend a malicious binary to your PATH and run the target."
									} else {
										gtfoHint := scanners.GetExploitHint(r.Path, "suid")
										if gtfoHint != "" {
											hint = gtfoHint
										}
									}
								}
								core.PrintFinding("CRITICAL", "File Permissions Exploit", map[string]string{
									"Path":   r.Path,
									"Method": r.ExploitMethod,
									"Vector": r.PotentialAttackVector,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "groups",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanGroups()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.Groups = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Group Memberships")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode && r.ExploitHint != "" {
									hint = r.ExploitHint
								}
								core.PrintFinding("CRITICAL", "Privileged Group Membership", map[string]string{
									"Group":  r.GroupName,
									"Reason": r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "services",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanLocalServices()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.Services = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Local Services")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode && r.ExploitHint != "" {
									hint = r.ExploitHint
								}
								core.PrintFinding("CRITICAL", "Service Vulnerability", map[string]string{
									"Service": r.ServiceName,
									"Reason":  r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "packages",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanPackages()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.Packages = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Package Managers")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode && r.ExploitHint != "" {
									hint = r.ExploitHint
								}
								severity := "CRITICAL"
								if r.RiskLevel != "" {
									severity = r.RiskLevel
								}
								details := map[string]string{
									"Tool":   r.Name,
									"Reason": r.Reason,
								}
								if r.Path != "" {
									details["Path"] = r.Path
								}
								core.PrintFinding(severity, "Package Misconfiguration", details, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "pathhijack",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanPATH()
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.PATHHijack = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("PATH Hijacking")
					for _, r := range results {
						if r.IsDangerous {
							core.PrintFinding("CRITICAL", "PATH Hijacking Vector", map[string]string{
								"Dir":    r.Directory,
								"Reason": r.Reason,
							}, "")
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "sshkeys",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, _ := scanners.ScanSSHKeys()
				ctx.Mu.Lock()
				ctx.Report.SSHKeys = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("SSH Keys")
					for _, r := range results {
						if r.IsDangerous {
							if r.Type == "private_key" {
								core.PrintFinding("CRITICAL", "SSH Private Key Exposed", map[string]string{
									"Path":    r.Path,
									"Owner":   r.TargetUser,
									"Preview": r.Preview,
								}, fmt.Sprintf("chmod 400 %s && ssh -i %s %s@localhost", r.Path, r.Path, r.TargetUser))
							} else {
								core.PrintFinding("CRITICAL", "SSH Key Vector", map[string]string{
									"Path":   r.Path,
									"Type":   r.Type,
									"Reason": r.Reason,
								}, "")
							}
						} else if r.Type == "private_key" && r.Preview == "" {
							core.PrintFinding("INFO", "SSH Private Key Found (not readable)", map[string]string{
								"Path":  r.Path,
								"Owner": r.TargetUser,
							}, "")
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "ptrace",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				if result, err := scanners.ScanPtraceScope(); err == nil {
					ctx.Mu.Lock()
					ctx.Report.PtraceScope = result
					ctx.Mu.Unlock()
					if result.IsDangerous {
						core.PrintSectionHeader("Ptrace Scope")
						core.PrintFinding("CRITICAL", "Ptrace Scope Vulnerability", map[string]string{
							"Scope":  fmt.Sprintf("%d", result.Scope),
							"Reason": result.Reason,
						}, "")
					}
				}
				return nil
			},
		},
		{
			Name:    "container",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanContainer()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.ContainerEscape = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Container Escape")
						for _, r := range results {
							severity := "INFO"
							if r.IsDangerous {
								severity = "CRITICAL"
							}
							core.PrintFinding(severity, "Container Escape Vector", map[string]string{
								"Vector": r.Vector,
								"Reason": r.Reason,
							}, "")
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "dbus",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanDBusPolicy()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.DBusPolicy = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("D-Bus Policies")
						for _, r := range results {
							if r.IsDangerous {
								core.PrintFinding("CRITICAL", "D-Bus Policy Flaw", map[string]string{
									"Service": r.ServiceName,
									"Reason":  r.Reason,
								}, "")
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "sessions",
			Aliases: []string{"xauthority", "xauth"},
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanSessionHijack()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.SessionHijack = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Session Hijack")
						for _, r := range results {
							if r.IsDangerous {
								core.PrintFinding("CRITICAL", "Session Hijack Vector", map[string]string{
									"Socket": r.Path,
									"Owner":  r.TargetUser,
									"Reason": r.Reason,
								}, "")
							}
						}
					}
				}

				xauthResults, err := scanners.ScanXAuthority()
				if err == nil && len(xauthResults) > 0 {
					ctx.Mu.Lock()
					ctx.Report.XAuthority = xauthResults
					ctx.Mu.Unlock()
					if len(xauthResults) > 0 {
						core.PrintSectionHeader("X11 Authority")
						for _, r := range xauthResults {
							if r.IsDangerous {
								core.PrintFinding("CRITICAL", "X11 Session Hijack", map[string]string{
									"Path":   r.Path,
									"Owner":  r.TargetUser,
									"Reason": r.Reason,
								}, "")
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "kernelconfig",
			Phase:   1,
			NeedsIO: true,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanKernelConfig()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.KernelConfig = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Kernel Config")
						for _, r := range results {
							if r.IsDangerous {
								core.PrintFinding(r.RiskLevel, "Kernel Config Issue", map[string]string{
									"Config": r.ConfigKey,
									"Reason": r.Reason,
								}, "")
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "polkit",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanPolkitRules()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.PolkitRules = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Polkit Rules")
						for _, r := range results {
							if r.IsDangerous {
								core.PrintFinding("CRITICAL", "Dangerous Polkit Rule", map[string]string{
									"File":       r.FilePath,
									"Action":     r.Action,
									"Authorized": r.Authorized,
									"Reason":     r.Reason,
								}, "")
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "history",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanHistoryFiles()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.HistorySecrets = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Shell History Secrets")
						for _, r := range results {
							core.PrintFinding(r.RiskLevel, "Discovered Shell History Secret", map[string]string{
								"User":   r.User,
								"File":   r.HistoryFile,
								"Line":   strconv.Itoa(r.LineNumber),
								"Cmd":    r.Command,
								"Reason": r.Reason,
							}, "")
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "pam",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanPAM()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.PAMResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("PAM Security Policies")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "PAM Misconfiguration", map[string]string{
									"Path":   r.Path,
									"Type":   r.Type,
									"Reason": r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "sysctl",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanSysctlHardening()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.SysctlResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Kernel Sysctl Hardening")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "Kernel Hardening Gap", map[string]string{
									"Sysctl":   r.Key,
									"Current":  r.CurrentValue,
									"Expected": r.ExpectedVal,
									"Reason":   r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "systemdoverrides",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanSystemdOverrides()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.SystemdOverrides = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Systemd Unit Overrides & Drop-ins")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "Systemd Override Vulnerability", map[string]string{
									"Service": r.ServiceName,
									"Path":    r.Path,
									"Type":    r.Type,
									"Reason":  r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "subuid",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanSubUIDAuditor()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.SubUIDResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Unprivileged User Namespaces & SubUID/SubGID")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "SubUID/UserNS Misconfiguration", map[string]string{
									"Type":   r.Type,
									"User":   r.TargetUser,
									"Reason": r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "mounts",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanMountAuditor()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.MountResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Shared Memory & Temp Mount Flags")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "Mount Flag Hardening Gap", map[string]string{
									"MountPoint": r.MountPoint,
									"Missing":    r.MissingFlag,
									"Options":    r.Options,
									"Reason":     r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "udev",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanUdevAuditor()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.UdevResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Udev Event Rules & Execution Targets")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "Udev Rule Vulnerability", map[string]string{
									"RuleFile":  r.RuleFile,
									"Directive": r.Directive,
									"Target":    r.Path,
									"Reason":    r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "crondirs",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanCronDirsAuditor()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.CronDirResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Cron & Timer Directory Permissions")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "Cron Directory Writable", map[string]string{
									"Path":   r.Path,
									"Reason": r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "ldnss",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanLDNSSConfiguration()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.LDNSSResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Dynamic Linker & NSS Configurations")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "Dynamic Linker / NSS Finding", map[string]string{
									"Path":   r.Path,
									"Reason": r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "modprobe",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanModprobeRules()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.ModprobeResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Modprobe Kernel Module Rules")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								details := map[string]string{
									"Path":   r.Path,
									"Reason": r.Reason,
								}
								if r.Directive != "" {
									details["Directive"] = r.Directive
								}
								core.PrintFinding(r.RiskLevel, "Modprobe Rule Finding", details, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "cloudmeta",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanCloudAndContainerMetadata()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.CloudMetaResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Cloud Metadata & Kubernetes ServiceAccounts")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								details := map[string]string{
									"Provider": r.Provider,
									"Reason":   r.Reason,
								}
								if r.Path != "" {
									details["Path"] = r.Path
								}
								core.PrintFinding(r.RiskLevel, "Cloud / K8s Metadata Finding", details, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "venvwrap",
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanVirtualEnvsAndWrappers()
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.VenvWrapResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Python VirtualEnvs & Script Wrappers")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "VirtualEnv / Wrapper Vulnerability", map[string]string{
									"Type":   r.TargetType,
									"Path":   r.Path,
									"Reason": r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "python_hijack",
			Aliases: []string{"python", "pythonhijack"},
			Phase:   1,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				results, err := scanners.ScanPythonHijack()
				if err != nil {
					return err
				}
				ctx.Mu.Lock()
				ctx.Report.PythonHijack = results
				ctx.Mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Python Library & Search Path Hijacking")
					for _, r := range results {
						core.PrintFinding(r.RiskLevel, r.Type, map[string]string{
							"Path":        r.Path,
							"Script":      r.ScriptName,
							"Reason":      r.Reason,
							"ExploitHint": r.ExploitHint,
						}, r.Remediation)
					}
				}
				return nil
			},
		},

		// ── PHASE 2: Correlated Scanners (Consume Phase 1 results) ───────────
		{
			Name:    "elfrpath",
			Phase:   2,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				ctx.Mu.Lock()
				suidBinaries := ctx.Report.SUID
				ctx.Mu.Unlock()
				if len(suidBinaries) == 0 {
					return nil
				}
				results, err := scanners.ScanELFRPathAuditor(suidBinaries)
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.ELFRPathResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Dynamic ELF RPATH / RUNPATH Header Inspection")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "ELF RPATH/RUNPATH Vector", map[string]string{
									"Binary": r.Path,
									"Tag":    r.TagType,
									"Value":  r.Value,
									"Reason": r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "auditd",
			Phase:   2,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				ctx.Mu.Lock()
				procs := ctx.Report.Processes
				ctx.Mu.Unlock()
				results, err := scanners.ScanAuditdAuditor(procs)
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.AuditdResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Active System Audit Daemons & Logging")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "Audit Daemon Active", map[string]string{
									"Daemon": r.DaemonName,
									"Rules":  fmt.Sprintf("%d active rules", r.RuleCount),
									"Reason": r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
		{
			Name:    "procenv",
			Phase:   2,
			NeedsIO: false,
			Run: func(ctx *DispatchContext) error {
				ctx.Mu.Lock()
				procs := ctx.Report.Processes
				ctx.Mu.Unlock()
				results, err := scanners.ScanProcEnvAuditor(procs)
				if err == nil {
					ctx.Mu.Lock()
					ctx.Report.ProcEnvResults = results
					ctx.Mu.Unlock()
					if len(results) > 0 {
						core.PrintSectionHeader("Process Environment Exposed Secrets (/proc)")
						for _, r := range results {
							if r.IsDangerous {
								hint := ""
								if !ctx.Config.AuditMode {
									hint = r.ExploitHint
								}
								core.PrintFinding(r.RiskLevel, "Exposed Secret in Process Environ", map[string]string{
									"PID":     strconv.Itoa(r.PID),
									"Process": r.ProcessName,
									"Key":     r.Key,
									"Preview": r.ValueSample,
									"Reason":  r.Reason,
								}, hint)
							}
						}
					}
				}
				return nil
			},
		},
	}
}

// DispatchRegistry executes the registered scanners in phased concurrent groups (OPT-02).
func DispatchRegistry(ctx *DispatchContext, registry []ModuleDescriptor) {
	// Execute Phase 1 scanners
	runPhase(ctx, registry, 1)

	// Execute Phase 2 correlated scanners
	runPhase(ctx, registry, 2)
}

func runPhase(ctx *DispatchContext, registry []ModuleDescriptor, phase int) {
	var wg sync.WaitGroup

	for _, module := range registry {
		if module.Phase != phase {
			continue
		}

		mod := module

		isExcluded := ctx.ExcludedModules[mod.Name]
		if !isExcluded {
			for _, alias := range mod.Aliases {
				if ctx.ExcludedModules[alias] {
					isExcluded = true
					break
				}
			}
		}
		if isExcluded {
			continue
		}

		isSelected := ctx.RunAll || ctx.SelectedModules[mod.Name]
		if !isSelected {
			for _, alias := range mod.Aliases {
				if ctx.SelectedModules[alias] {
					isSelected = true
					break
				}
			}
		}
		if !isSelected {
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if mod.NeedsIO && ctx.IOSemaphore != nil {
				ctx.IOSemaphore <- struct{}{}
				defer func() { <-ctx.IOSemaphore }()
			}
			_ = mod.Run(ctx)
		}()
	}

	wg.Wait()
}
