package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"talaria/core"
	"talaria/models"
	"talaria/scanners"
)

func getAvailableFileDescriptors() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil {
		return rl.Cur
	}
	return 1024 // safe fallback
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	scanInput := flag.String("scan", "all",
		"Comma-separated list of modules to run. Use 'all' to run everything.\n"+
			"  Available modules:\n"+
			"    secrets         - Sensitive files & credentials (SSH keys, .env, config files)\n"+
			"    suid            - SUID binaries (GTFOBins-matched dangerous list)\n"+
			"    sgid            - SGID binaries (privileged group ownership detection)\n"+
			"    sudo            - sudo -l analysis (NOPASSWD, SETENV, LD_PRELOAD env_keep)\n"+
			"    capabilities    - Linux capabilities (cap_setuid, cap_sys_admin, etc.)\n"+
			"    cronjobs        - Cron jobs, systemd timers, wildcard injection\n"+
			"    processes       - Running processes (credentials in args, ptrace scope)\n"+
			"    ptrace          - ptrace_scope check (process injection vector)\n"+
			"    nfs             - NFS exports (no_root_squash detection)\n"+
			"    network         - Open ports & internal services\n"+
			"    writeable       - Writable files/dirs owned by root or other users\n"+
			"    sockets         - Unix sockets (Docker sock, privileged service sockets)\n"+
			"    filepermissions - Critical system file misconfigurations\n"+
			"    filepermsexploit- SUID/SGID scripts with relative binary calls (PATH hijack)\n"+
			"    groups          - Privileged group membership (docker, lxd, disk, shadow)\n"+
			"    pathhijack      - Writable/dot entries in $PATH\n"+
			"    sshkeys         - SSH authorized_keys writability & private key exposure\n"+
			"    vulnerabilities - Kernel & software version CVE checks (Dirty COW, PwnKit)\n"+
			"    container       - Container escape vectors (--privileged, docker.sock mount)\n"+
			"    dbus            - D-Bus policy misconfigurations\n"+
			"    services        - Local service audits (MySQL, Redis blank passwords)\n"+
			"    packages        - Package manager audits (doas, snap, flatpak)\n"+
			"    sessions        - Tmux/Screen session hijacking vectors\n"+
			"    kernelconfig    - Kernel config leak (CONFIG_STRICT_DEVMEM, etc.)\n"+
			"    polkit          - Custom PolicyKit JavaScript rules logic auditing\n"+
			"    environmentfile - Systemd EnvironmentFile= writability (LD_PRELOAD/PATH injection)\n"+
			"    pam             - PAM configurations, pam_exec scripts, pam_env, custom .so modules\n"+
			"    sysctl          - Kernel sysctl hardening baselines (symlinks, eBPF, kptr, ptrace)\n"+
			"    systemdoverrides- Systemd unit drop-in & override files (*.service.d/*.conf writability)\n"+
			"    subuid          - Unprivileged user namespaces & subuid/subgid range allocations\n"+
			"    mounts          - Shared memory & temp mount flags auditing (noexec/nosuid on /dev/shm)\n"+
			"    elfrpath        - Dynamic ELF RPATH / RUNPATH security header inspection on SUID binaries\n"+
			"    auditd          - System audit daemons (auditd, rsyslog, journald) & active rule counting\n"+
			"    udev            - Udev rule files & event execution target binary writability\n"+
			"    crondirs        - System task drop-in directory permission drift (/etc/cron.d, /var/spool/cron)\n"+
			"    procenv         - Process environment token & secret harvesting (/proc/[pid]/environ)\n"+
			"    ldnss           - Dynamic Linker search paths & NSS configuration (/etc/ld.so.conf.d)\n"+
			"    modprobe        - Modprobe rule files & install hook targets (/etc/modprobe.d)\n"+
			"    cloudmeta       - Kubernetes ServiceAccounts & Cloud IMDS endpoints\n"+
			"    venvwrap        - Python VirtualEnvs site-packages & /usr/local/bin wrapper scripts")
	searchPath := flag.String("path", "/", "Root directory for filesystem scans (default: /)")
	outputFile := flag.String("o", "", "Save report to file (combine with --format)")
	outputFormat := flag.String("format", "text", "Report format: text or json")
	sudoPassword := flag.String("pass", "", "Sudo password for sudo -l checks (optional)")
	excludeInput := flag.String("exclude", "", "Comma-separated modules to skip (e.g. network,secrets)")
	ctfMode := flag.Bool("ctf", false, "CTF / offensive mode: focuses on rapid root escalation, exploit 1-liners, and cleartext credentials (default)")
	auditMode := flag.Bool("audit", false, "Audit / compliance mode: focuses on remediation fix commands, masked credentials, CIS tags")
	professionalMode := flag.Bool("professional", false, "Alias for --audit")
	pMode := flag.Bool("p", false, "Alias for --audit (shorthand)")
	uiMode := flag.Bool("ui", false, "Enable visual summary dashboard card (default: stream clean text report)")
	noColor := flag.Bool("no-color", false, "Disable ANSI colors (also respects NO_COLOR environment variable)")
	ioLimit := flag.Int("io-limit", 0, "Max concurrent I/O scanners (default: auto based on RLIMIT_NOFILE)")

	encryptKey := flag.String("encrypt", "", "Encrypt saved report with AES-256-GCM using this passphrase (requires -o)")

	// Custom usage printer — groups core, mode, and presentation flags visually
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Talaria - Linux Privilege Escalation & Security Audit Scanner\n")
		fmt.Fprintf(os.Stderr, "Usage: talaria [flags]\n\n")
		fmt.Fprintf(os.Stderr, "CORE FLAGS:\n")
		for _, name := range []string{"scan", "exclude", "path", "o", "format", "pass", "io-limit", "encrypt"} {
			f := flag.Lookup(name)
			if f != nil {
				fmt.Fprintf(os.Stderr, "  --%-18s %s\n", f.Name, f.Usage)
			}
		}
		fmt.Fprintf(os.Stderr, "\nOPERATIONAL MODES:\n")
		for _, name := range []string{"ctf", "audit", "professional", "p"} {
			f := flag.Lookup(name)
			if f != nil {
				fmt.Fprintf(os.Stderr, "  --%-18s %s\n", f.Name, f.Usage)
			}
		}
		fmt.Fprintf(os.Stderr, "\nPRESENTATION FLAGS:\n")
		for _, name := range []string{"ui", "no-color"} {
			f := flag.Lookup(name)
			if f != nil {
				fmt.Fprintf(os.Stderr, "  --%-18s %s\n", f.Name, f.Usage)
			}
		}
		fmt.Fprintf(os.Stderr, "\nSee USAGE.md for detailed examples.\n")
	}

	flag.Parse()

	isAudit := *auditMode || *professionalMode || *pMode
	if *ctfMode && isAudit {
		fmt.Fprintf(os.Stderr, "Error: --ctf and --audit/--professional are mutually exclusive\n")
		os.Exit(1)
	}
	isProfessional := isAudit

	if isAudit {
		core.Config.Mode = core.ModeAudit
	} else {
		core.Config.Mode = core.ModeCTF
	}
	core.Config.EnableUI = *uiMode
	core.Config.NoColor = *noColor

	// In audit report mode, mask discovered credentials in output.
	// Default (CTF mode): show credentials in cleartext for immediate usability.
	scanners.AuditCfg.MaskSecrets = isAudit

	scanners.InitUserContext() // Initialize shared user context (D2)

	core.PrintBanner()

	selectedModules := make(map[string]bool)
	for _, m := range strings.Split(*scanInput, ",") {
		selectedModules[strings.TrimSpace(m)] = true
	}

	excludedModules := make(map[string]bool)
	if *excludeInput != "" {
		for _, m := range strings.Split(*excludeInput, ",") {
			excludedModules[strings.TrimSpace(m)] = true
		}
	}

	report := &models.ScanReport{
		ScanTime:       time.Now().Format(time.RFC1123),
		TargetUser:     os.Getenv("USER"),
		TargetScanPath: *searchPath,
		AuditMode:      isAudit,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// ── Dynamic I/O semaphore (#10) ──────────────────────────────────────────
	ioLimitVal := *ioLimit
	if ioLimitVal <= 0 {
		availableFDs := int(getAvailableFileDescriptors())
		// Use ~5% of available FDs, capped between 2 and 8
		ioLimitVal = min(max(availableFDs/20, 2), 8)
	}
	ioSemaphore := make(chan struct{}, ioLimitVal)
	if *ioLimit != 0 || ioLimitVal != 2 {
		fmt.Printf("%s[io] I/O concurrency limit: %d (based on RLIMIT_NOFILE=%d)%s\n", core.ColorGray, ioLimitVal, getAvailableFileDescriptors(), core.ColorReset)
	}

	fmt.Printf("%s[!] Talaria Assessment Started%s\n", core.ColorBlue, core.ColorReset)
	startTime := time.Now()
	runAll := selectedModules["all"]
	timeout := 2 * time.Second

	// Helper: lock, assign report data, unlock — print separately
	storeSecrets := func(files []scanners.SensitiveFileResult, content []scanners.SensitiveContentResult) {
		mu.Lock()
		report.Secrets = append(report.Secrets, files...)
		report.SecretContent = append(report.SecretContent, content...)
		mu.Unlock()
	}

	// --- SECRETS MODULE ---
	if (runAll || selectedModules["secrets"]) && !excludedModules["secrets"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var searchTargets []string
			if *searchPath != "/" {
				searchTargets = []string{*searchPath}
			} else {
				ctfPaths := []string{
					"/home", "/var/www", "/opt", "/srv", "/etc",
					"/etc/openvpn", "/etc/vpn", "/etc/irssi",
					"/var/www/html", "/opt/app", "/srv/app", // Deeper .env scanning paths (B3)
					"/var/backups",     // Backup copies of shadow/passwd (high value)
					"/tmp", "/dev/shm", // Temp credential files, ansible vaults, copied configs
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
				ioSemaphore <- struct{}{}
				files, content := scanners.ScanSecrets(target)
				<-ioSemaphore
				storeSecrets(files, content)

				if len(files) > 0 {
					core.PrintSectionHeader(fmt.Sprintf("Secrets: %s", target))
					for _, f := range files {
						reason := f.Type
						for _, c := range content {
							if c.Path == f.Path {
								reason += " | " + c.Snippet
								break
							}
						}
						core.PrintFinding(f.RiskLevel, "Secret Found", map[string]string{
							"Path":   f.Path,
							"Detail": reason,
						}, "")
					}
				}
			}

			rootFiles, rootContent := scanners.ScanRootSecrets()
			if len(rootFiles) > 0 {
				storeSecrets(rootFiles, rootContent)
				core.PrintSectionHeader("Root Secrets")
				for _, f := range rootFiles {
					reason := f.Type
					for _, c := range rootContent {
						if c.Path == f.Path {
							reason += " | " + c.Snippet
							break
						}
					}
					core.PrintFinding("CRITICAL", "Root Secret Found", map[string]string{
						"Path":   f.Path,
						"Detail": reason,
					}, "")
				}
			}
		}()
	}

	// --- SUID MODULE ---
	if (runAll || selectedModules["suid"]) && !excludedModules["suid"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanSUID(*searchPath)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.SUID = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("SUID Binaries")
					for _, r := range results {
						severity := "INFO"
						if r.IsDangerous {
							severity = "CRITICAL"
						}

						details := map[string]string{"Path": r.Path}
						if r.Reason != "" {
							details["Reason"] = r.Reason
						}

						hint := ""
						if !isProfessional && r.ExploitHint != "" {
							hint = r.ExploitHint
						}
						core.PrintFinding(severity, "SUID Binary", details, hint)
					}
				}
			}
		}()
	}

	// --- SGID MODULE ---
	if (runAll || selectedModules["sgid"]) && !excludedModules["sgid"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanSGID(*searchPath)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.SGID = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("SGID Binaries")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional && r.ExploitHint != "" {
								hint = r.ExploitHint
							}
							core.PrintFinding("CRITICAL", "SGID Binary Found", map[string]string{
								"Path":   r.Path,
								"Reason": r.Reason,
							}, hint)
						}
					}
				}
			}
		}()
	}

	// --- PROCESSES MODULE ---
	if (runAll || selectedModules["processes"]) && !excludedModules["processes"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanProcesses()
			if err == nil {
				mu.Lock()
				report.Processes = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Processes")
					for _, r := range results {
						if r.IsDangerous {
							details := map[string]string{
								"PID":     fmt.Sprintf("%d", r.PID),
								"User":    r.User,
								"Command": r.Command,
							}
							if len(r.EnvSecrets) > 0 {
								details["EnvSecrets"] = strings.Join(r.EnvSecrets, ", ")
							}
							core.PrintFinding("CRITICAL", "Dangerous Process", details, "")
						}
					}
				}
			}
		}()
	}

	// --- CRONJOBS & SYSTEMD MODULE ---
	if (runAll || selectedModules["cronjobs"]) && !excludedModules["cronjobs"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanCronJobs()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.CronJobs = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Cron Jobs & Timers")
					for _, r := range results {
						if r.IsDangerous {
							core.PrintFinding("CRITICAL", "CronJob Found", map[string]string{
								"Command": r.Command,
								"Reason":  r.Reason,
							}, "")
						} else if r.IsRootJob {
							core.PrintFinding("INFO", "Root CronJob", map[string]string{
								"Command": r.Command,
							}, "")
						}
					}
				}
			}

			ioSemaphore <- struct{}{}
			systemdResults, err := scanners.ScanSystemdTimers()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.SystemdTimers = systemdResults
				mu.Unlock()
				for _, r := range systemdResults {
					if r.IsDangerous {
						core.PrintFinding("CRITICAL", "Systemd Timer Found", map[string]string{
							"Path":   r.Path,
							"Reason": r.Reason,
						}, "")
					}
				}
			}
		}()
	}

	// --- SUDO PRIVILEGES MODULE ---
	if (runAll || selectedModules["sudo"]) && !excludedModules["sudo"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanSudoPrivileges(timeout, *sudoPassword)
			if err == nil {
				mu.Lock()
				report.SudoPrivileges = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Sudo Privileges")
					for _, r := range results {
						severity := "INFO"
						if r.HasLDPreload || r.IsDangerous {
							severity = "CRITICAL"
						} else if r.NoPassword {
							severity = "HIGH"
						}

						details := map[string]string{"Reason": r.Reason}
						if r.Command != "" {
							details["Command"] = r.Command
						}
						core.PrintFinding(severity, "Sudo Privilege", details, "")
					}
				}
			}

			// ── Sudo Tokens & TIOCSTI Terminal Hijack ─────────────────────
			tokenResults, err := scanners.ScanSudoTokensAndTTY()
			if err == nil && len(tokenResults) > 0 {
				mu.Lock()
				report.SudoTokens = tokenResults
				mu.Unlock()
				buf := core.NewSectionBuffer("Active Sudo Tokens & TTY Hijack")
				for _, r := range tokenResults {
					details := map[string]string{
						"Vector":      r.Vector,
						"Reason":      r.Reason,
						"Remediation": r.Remediation,
						"Compliance":  r.ComplianceTag,
					}
					if r.Path != "" {
						details["Path"] = r.Path
					}
					buf.AddFinding(r.RiskLevel, r.Vector, details, r.ExploitHint)
				}
				buf.Flush()
			}
		}()
	}

	// --- CAPABILITIES MODULE ---
	if (runAll || selectedModules["capabilities"]) && !excludedModules["capabilities"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanCapabilities(*searchPath)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.Capabilities = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Capabilities")
					for _, r := range results {
						if r.IsDangerous {
							core.PrintFinding("CRITICAL", "Capability Found", map[string]string{
								"Path":   r.Path,
								"Capabs": r.Capabilities,
							}, "")
						}
					}
				}
			}
		}()
	}

	// --- NFS EXPORTS MODULE ---
	if (runAll || selectedModules["nfs"]) && !excludedModules["nfs"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanNFSExports(timeout)
			if err == nil {
				mu.Lock()
				report.NFSExports = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("NFS Exports")
					for _, r := range results {
						if r.HasNoRootSquash {
							core.PrintFinding("CRITICAL", "NFS no_root_squash", map[string]string{"Path": r.Path}, "")
						}
					}
				}
			}
		}()
	}

	// --- NETWORK CONNECTIONS MODULE ---
	if (runAll || selectedModules["network"]) && !excludedModules["network"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanNetworkConnections()
			if err == nil {
				mu.Lock()
				report.NetworkConnections = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Network Connections")
					for _, r := range results {
						if r.State == "LISTEN" {
							severity := "INFO"
							if r.RiskLevel != "" {
								severity = r.RiskLevel
							} else if r.IsDangerous {
								severity = "CRITICAL"
							}

							details := map[string]string{
								"Addr":    fmt.Sprintf("%s:%d (%s)", r.LocalAddr, r.LocalPort, r.Protocol),
								"Process": r.ProcessName,
							}
							if r.Reason != "" {
								details["Reason"] = r.Reason
							}
							core.PrintFinding(severity, "Active Listener", details, "")
						}
					}
				}
			}
		}()
	}

	// --- SYSTEM VULNERABILITIES MODULE ---
	if (runAll || selectedModules["vulnerabilities"]) && !excludedModules["vulnerabilities"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanSystemVersions()
			if err == nil {
				mu.Lock()
				report.Vulnerabilities = results
				mu.Unlock()
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
		}()
	}

	// --- WRITEABLE MODULE ---
	if (runAll || selectedModules["writeable"]) && !excludedModules["writeable"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanWriteable(*searchPath)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.Writeable = append(report.Writeable, results...)
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Writeable Files")
					for _, r := range results {
						if r.IsDangerous {
							core.PrintFinding(r.RiskLevel, "Writable File Found", map[string]string{
								"Path":   r.Path,
								"Reason": r.Reason,
							}, "")
						}
					}
				}
			}

			genResults, err := scanners.ScanSystemdGenerators()
			if err == nil && len(genResults) > 0 {
				mu.Lock()
				report.Writeable = append(report.Writeable, genResults...)
				mu.Unlock()
				for _, r := range genResults {
					core.PrintFinding("CRITICAL", "Systemd Generator Writable", map[string]string{
						"Path":   r.Path,
						"Reason": r.Reason,
					}, "")
				}
			}

			// ── Writable systemd service files (#3) ─────────────────────────
			svcResults, err := scanners.ScanWritableServices()
			if err == nil && len(svcResults) > 0 {
				mu.Lock()
				report.Writeable = append(report.Writeable, svcResults...)
				mu.Unlock()
				for _, r := range svcResults {
					core.PrintFinding("CRITICAL", "Writable Systemd Service", map[string]string{
						"Path":   r.Path,
						"Reason": r.Reason,
					}, "")
				}
			}

			// ── Writable udev rules (#5) ───────────────────────────────────
			udevResults, err := scanners.ScanUdevRules()
			if err == nil && len(udevResults) > 0 {
				mu.Lock()
				report.Writeable = append(report.Writeable, udevResults...)
				mu.Unlock()
				for _, r := range udevResults {
					core.PrintFinding("CRITICAL", r.Type, map[string]string{
						"Path":   r.Path,
						"Reason": r.Reason,
					}, "")
				}
			}

			// ── MOTD & Profile.d Hijacking ─────────────────────────────────
			motdResults, err := scanners.ScanMotdProfiledHijack()
			if err == nil && len(motdResults) > 0 {
				mu.Lock()
				report.Writeable = append(report.Writeable, motdResults...)
				mu.Unlock()
				for _, r := range motdResults {
					core.PrintFinding("CRITICAL", r.Type, map[string]string{
						"Path":   r.Path,
						"Reason": r.Reason,
					}, "")
				}
			}

			// ── SysV Init Scripts (A2) ─────────────────────────────────────
			initResults, err := scanners.ScanInitScripts()
			if err == nil && len(initResults) > 0 {
				mu.Lock()
				report.Writeable = append(report.Writeable, initResults...)
				mu.Unlock()
				for _, r := range initResults {
					core.PrintFinding("CRITICAL", r.Type, map[string]string{
						"Path":   r.Path,
						"Reason": r.Reason,
					}, "")
				}
			}

			// ── Anacrontab Writability (B4) ─────────────────────────────────
			anacronResults, err := scanners.ScanAnacronWritability()
			if err == nil && len(anacronResults) > 0 {
				mu.Lock()
				report.Writeable = append(report.Writeable, anacronResults...)
				mu.Unlock()
				for _, r := range anacronResults {
					core.PrintFinding("CRITICAL", r.Type, map[string]string{
						"Path":   r.Path,
						"Reason": r.Reason,
					}, "")
				}
			}

			// ── At Job Queue (A5) ──────────────────────────────────────────
			atResults, err := scanners.ScanAtJobs()
			if err == nil && len(atResults) > 0 {
				mu.Lock()
				report.Writeable = append(report.Writeable, atResults...)
				mu.Unlock()
				for _, r := range atResults {
					core.PrintFinding("CRITICAL", r.Type, map[string]string{
						"Path":   r.Path,
						"Reason": r.Reason,
					}, "")
				}
			}

			// ── Logrotate Config Scanner (A3) ──────────────────────────────
			logrotateResults, err := scanners.ScanLogrotate()
			if err == nil && len(logrotateResults) > 0 {
				mu.Lock()
				report.Logrotate = logrotateResults
				mu.Unlock()
				for _, r := range logrotateResults {
					core.PrintFinding(r.RiskLevel, "Writable Logrotate Config", map[string]string{
						"Path":   r.ConfigPath,
						"Reason": r.Reason,
					}, "")
				}
			}

			// ── Systemd EnvironmentFile Scanner (A6) ─────────────────────────
			envFileResults, err := scanners.ScanSystemdEnvFiles()
			if err == nil && len(envFileResults) > 0 {
				mu.Lock()
				report.EnvFileResults = envFileResults
				mu.Unlock()
				core.PrintSectionHeader("Systemd EnvironmentFile")
				for _, r := range envFileResults {
					hint := ""
					if !isProfessional {
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
		}()
	}

	// --- SOCKETS MODULE ---
	if (runAll || selectedModules["sockets"]) && !excludedModules["sockets"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanUnixDomainSockets()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.Sockets = results
				mu.Unlock()
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
		}()
	}

	// --- FILE PERMISSIONS MODULE ---
	if (runAll || selectedModules["filepermissions"]) && !excludedModules["filepermissions"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanFilePermissions()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.FilePermissions = results
				mu.Unlock()
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
		}()
	}

	// --- FILE PERMS EXPLOIT MODULE ---
	if (runAll || selectedModules["filepermsexploit"]) && !excludedModules["filepermsexploit"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanFilePermissionsExploit(timeout)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.FilePermsExploit = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("File Permissions Exploit")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- GROUPS MODULE ---
	if (runAll || selectedModules["groups"]) && !excludedModules["groups"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanGroups()
			if err == nil {
				mu.Lock()
				report.Groups = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Group Memberships")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional && r.ExploitHint != "" {
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
		}()
	}

	// --- SERVICES MODULE ---
	if runAll || selectedModules["services"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanLocalServices()
			if err == nil {
				mu.Lock()
				report.Services = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Local Services")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional && r.ExploitHint != "" {
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
		}()
	}

	// --- PACKAGES MODULE ---
	if runAll || selectedModules["packages"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanPackages()
			if err == nil {
				mu.Lock()
				report.Packages = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Package Managers")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional && r.ExploitHint != "" {
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
		}()
	}

	// --- PATH HIJACKING MODULE ---
	if (runAll || selectedModules["pathhijack"]) && !excludedModules["pathhijack"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanPATH()
			if err == nil {
				mu.Lock()
				report.PATHHijack = results
				mu.Unlock()
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
			}
		}()
	}

	// --- SSH KEYS MODULE ---
	if (runAll || selectedModules["sshkeys"]) && !excludedModules["sshkeys"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, _ := scanners.ScanSSHKeys()
			<-ioSemaphore
			mu.Lock()
			report.SSHKeys = results
			mu.Unlock()
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
		}()
	}

	// --- PTRACE SCOPE MODULE ---
	if (runAll || selectedModules["ptrace"]) && !excludedModules["ptrace"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if result, err := scanners.ScanPtraceScope(); err == nil {
				mu.Lock()
				report.PtraceScope = result
				mu.Unlock()
				if result.IsDangerous {
					core.PrintSectionHeader("Ptrace Scope")
					core.PrintFinding("CRITICAL", "Ptrace Scope Vulnerability", map[string]string{
						"Scope":  fmt.Sprintf("%d", result.Scope),
						"Reason": result.Reason,
					}, "")
				}
			}
		}()
	}

	// --- CONTAINER ESCAPE MODULE ---
	if (runAll || selectedModules["container"]) && !excludedModules["container"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanContainer()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.ContainerEscape = results
				mu.Unlock()
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
		}()
	}

	// --- DBUS POLICY MODULE ---
	if (runAll || selectedModules["dbus"]) && !excludedModules["dbus"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanDBusPolicy()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.DBusPolicy = results
				mu.Unlock()
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
		}()
	}

	// --- SESSIONS MODULE (#4: Tmux/Screen hijack) ---
	if (runAll || selectedModules["sessions"]) && !excludedModules["sessions"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanSessionHijack()
			if err == nil {
				mu.Lock()
				report.SessionHijack = results
				mu.Unlock()
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
			// ── XAuthority Session Hijack (A4) ─────────────────────────────
			xauthResults, err := scanners.ScanXAuthority()
			if err == nil && len(xauthResults) > 0 {
				mu.Lock()
				report.XAuthority = xauthResults
				mu.Unlock()
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
		}()
	}

	// --- KERNEL CONFIG MODULE (#6) ---
	if (runAll || selectedModules["kernelconfig"]) && !excludedModules["kernelconfig"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanKernelConfig()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.KernelConfig = results
				mu.Unlock()
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
		}()
	}

	// --- POLKIT RULES MODULE ---
	if (runAll || selectedModules["polkit"]) && !excludedModules["polkit"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanPolkitRules()
			if err == nil {
				mu.Lock()
				report.PolkitRules = results
				mu.Unlock()
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
		}()
	}

	// --- SHELL HISTORY MODULE ---
	if (runAll || selectedModules["history"]) && !excludedModules["history"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanHistoryFiles()
			if err == nil {
				mu.Lock()
				report.HistorySecrets = results
				mu.Unlock()
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
		}()
	}

	// --- PAM MODULE AUDIT MODULE ---
	if (runAll || selectedModules["pam"]) && !excludedModules["pam"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanPAM()
			if err == nil {
				mu.Lock()
				report.PAMResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("PAM Security Policies")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- SYSCTL HARDENING MODULE ---
	if (runAll || selectedModules["sysctl"]) && !excludedModules["sysctl"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanSysctlHardening()
			if err == nil {
				mu.Lock()
				report.SysctlResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Kernel Sysctl Hardening")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- SYSTEMD OVERRIDES MODULE ---
	if (runAll || selectedModules["systemdoverrides"]) && !excludedModules["systemdoverrides"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanSystemdOverrides()
			if err == nil {
				mu.Lock()
				report.SystemdOverrides = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Systemd Unit Overrides & Drop-ins")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- SUBUID / UNPRIVILEGED USERNS MODULE ---
	if (runAll || selectedModules["subuid"]) && !excludedModules["subuid"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanSubUIDAuditor()
			if err == nil {
				mu.Lock()
				report.SubUIDResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Unprivileged Namespaces & SubUID Allocations")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
								hint = r.ExploitHint
							}
							core.PrintFinding(r.RiskLevel, "Unprivileged Namespace / SubUID Finding", map[string]string{
								"Type":   r.Type,
								"User":   r.TargetUser,
								"Reason": r.Reason,
							}, hint)
						}
					}
				}
			}
		}()
	}

	// --- MOUNT FLAGS AUDITOR MODULE ---
	if (runAll || selectedModules["mounts"]) && !excludedModules["mounts"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanMountAuditor()
			if err == nil {
				mu.Lock()
				report.MountResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Shared Memory & Temp Mount Flags")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- UDEV RULES & EVENT AUDITOR MODULE ---
	if (runAll || selectedModules["udev"]) && !excludedModules["udev"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanUdevAuditor()
			if err == nil {
				mu.Lock()
				report.UdevResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Udev Event Rules & Execution Targets")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- CRON & TIMER DIRECTORY PERMISSION DRIFT MODULE ---
	if (runAll || selectedModules["crondirs"]) && !excludedModules["crondirs"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanCronDirsAuditor()
			if err == nil {
				mu.Lock()
				report.CronDirResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Cron & Timer Directory Permissions")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- DYNAMIC LINKER & NSS CONFIGURATION MODULE ---
	if (runAll || selectedModules["ldnss"]) && !excludedModules["ldnss"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanLDNSSConfiguration()
			if err == nil {
				mu.Lock()
				report.LDNSSResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Dynamic Linker & NSS Configurations")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- MODPROBE RULES MODULE ---
	if (runAll || selectedModules["modprobe"]) && !excludedModules["modprobe"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanModprobeRules()
			if err == nil {
				mu.Lock()
				report.ModprobeResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Modprobe Kernel Module Rules")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- CLOUD & KUBERNETES METADATA MODULE ---
	if (runAll || selectedModules["cloudmeta"]) && !excludedModules["cloudmeta"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanCloudAndContainerMetadata()
			if err == nil {
				mu.Lock()
				report.CloudMetaResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Cloud Metadata & Kubernetes ServiceAccounts")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	// --- VIRTUALENV & WRAPPER SCRIPTS MODULE ---
	if (runAll || selectedModules["venvwrap"]) && !excludedModules["venvwrap"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := scanners.ScanVirtualEnvsAndWrappers()
			if err == nil {
				mu.Lock()
				report.VenvWrapResults = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Python VirtualEnvs & Script Wrappers")
					for _, r := range results {
						if r.IsDangerous {
							hint := ""
							if !isProfessional {
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
		}()
	}

	wg.Wait()

	// --- DYNAMIC ELF RPATH / RUNPATH MODULE ---
	if (runAll || selectedModules["elfrpath"]) && !excludedModules["elfrpath"] && len(report.SUID) > 0 {
		results, err := scanners.ScanELFRPathAuditor(report.SUID)
		if err == nil {
			report.ELFRPathResults = results
			if len(results) > 0 {
				core.PrintSectionHeader("Dynamic ELF RPATH / RUNPATH Header Inspection")
				for _, r := range results {
					if r.IsDangerous {
						hint := ""
						if !isProfessional {
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
	}

	// --- AUDITD & LOGGING DETECTION MODULE ---
	if (runAll || selectedModules["auditd"]) && !excludedModules["auditd"] {
		results, err := scanners.ScanAuditdAuditor(report.Processes)
		if err == nil {
			report.AuditdResults = results
			if len(results) > 0 {
				core.PrintSectionHeader("Active System Audit Daemons & Logging")
				for _, r := range results {
					if r.IsDangerous {
						hint := ""
						if !isProfessional {
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
	}

	// --- PROCESS ENVIRONMENT SECRET HARVESTER MODULE ---
	if (runAll || selectedModules["procenv"]) && !excludedModules["procenv"] {
		results, err := scanners.ScanProcEnvAuditor(report.Processes)
		if err == nil {
			report.ProcEnvResults = results
			if len(results) > 0 {
				core.PrintSectionHeader("Process Environment Exposed Secrets (/proc)")
				for _, r := range results {
					if r.IsDangerous {
						hint := ""
						if !isProfessional {
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
	}

	// --- CROSS-REFERENCING (Analysis Phase) ---
	core.RunIntelligenceEngine(report)

	if *outputFile != "" {
		saveReport(report, *outputFile, *outputFormat, *encryptKey)
	}

	duration := time.Since(startTime).String()
	core.PrintSummary(report, duration)
}

func saveReport(report *models.ScanReport, path string, format string, encryptKey string) {
	var data []byte
	if strings.ToLower(format) == "json" {
		data, _ = json.MarshalIndent(report, "", "  ")
	} else {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Talaria Scan Report\n===================\nScan Time: %s\nTarget: %s @ %s\n\n", report.ScanTime, report.TargetUser, report.TargetScanPath))

		if len(report.SUID) > 0 {
			sb.WriteString("=== SUID Binaries ===\n")
			for _, r := range report.SUID {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[CRITICAL] %s\n  Reason: %s\n", r.Path, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.Writeable) > 0 {
			sb.WriteString("=== Writable Files ===\n")
			for _, r := range report.Writeable {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s\n  Reason: %s\n", r.RiskLevel, r.Path, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.CronJobs) > 0 {
			sb.WriteString("=== Cron Jobs ===\n")
			for _, r := range report.CronJobs {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[CRITICAL] %s\n  Reason: %s\n", r.Command, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.PAMResults) > 0 {
			sb.WriteString("=== PAM Security Policies ===\n")
			for _, r := range report.PAMResults {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s\n  Reason: %s\n", r.RiskLevel, r.Path, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.SysctlResults) > 0 {
			sb.WriteString("=== Kernel Sysctl Hardening ===\n")
			for _, r := range report.SysctlResults {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s = %s (expected %s)\n  Reason: %s\n", r.RiskLevel, r.Key, r.CurrentValue, r.ExpectedVal, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.SystemdOverrides) > 0 {
			sb.WriteString("=== Systemd Unit Overrides ===\n")
			for _, r := range report.SystemdOverrides {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s (%s)\n  Reason: %s\n", r.RiskLevel, r.Path, r.ServiceName, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.SubUIDResults) > 0 {
			sb.WriteString("=== Unprivileged Namespaces & SubUID Allocations ===\n")
			for _, r := range report.SubUIDResults {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s (%s)\n  Reason: %s\n", r.RiskLevel, r.Type, r.TargetUser, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.MountResults) > 0 {
			sb.WriteString("=== Shared Memory & Temp Mount Flags ===\n")
			for _, r := range report.MountResults {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s (missing %s)\n  Reason: %s\n", r.RiskLevel, r.MountPoint, r.MissingFlag, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.ELFRPathResults) > 0 {
			sb.WriteString("=== Dynamic ELF RPATH / RUNPATH Vectors ===\n")
			for _, r := range report.ELFRPathResults {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s (%s: %s)\n  Reason: %s\n", r.RiskLevel, r.Path, r.TagType, r.Value, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.AuditdResults) > 0 {
			sb.WriteString("=== Active System Audit Daemons ===\n")
			for _, r := range report.AuditdResults {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s (%d rules)\n  Reason: %s\n", r.RiskLevel, r.DaemonName, r.RuleCount, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.UdevResults) > 0 {
			sb.WriteString("=== Udev Event Rules & Execution Targets ===\n")
			for _, r := range report.UdevResults {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s (%s)\n  Reason: %s\n", r.RiskLevel, r.RuleFile, r.Directive, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.CronDirResults) > 0 {
			sb.WriteString("=== Cron & Timer Directory Permissions ===\n")
			for _, r := range report.CronDirResults {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] %s\n  Reason: %s\n", r.RiskLevel, r.Path, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		if len(report.ProcEnvResults) > 0 {
			sb.WriteString("=== Exposed Process Environment Secrets ===\n")
			for _, r := range report.ProcEnvResults {
				if r.IsDangerous {
					sb.WriteString(fmt.Sprintf("[%s] PID %d (%s) — Key: %s (Preview: %s)\n  Reason: %s\n", r.RiskLevel, r.PID, r.ProcessName, r.Key, r.ValueSample, r.Reason))
				}
			}
			sb.WriteString("\n")
		}

		sb.WriteString(fmt.Sprintf("\nSummary Counts:\nSecrets: %d\nCronJobs: %d\nSudo Privs: %d\nCapabilities: %d\nPAM Issues: %d\nSysctl Gaps: %d\nSystemd Overrides: %d\nSubUID Findings: %d\nMount Gaps: %d\nELF RPATH Vectors: %d\nAudit Daemons: %d\nUdev Findings: %d\nCronDir Findings: %d\nProcEnv Secrets: %d\n",
			len(report.Secrets), len(report.CronJobs), len(report.SudoPrivileges), len(report.Capabilities), len(report.PAMResults), len(report.SysctlResults), len(report.SystemdOverrides), len(report.SubUIDResults), len(report.MountResults), len(report.ELFRPathResults), len(report.AuditdResults), len(report.UdevResults), len(report.CronDirResults), len(report.ProcEnvResults)))
		data = []byte(sb.String())
	}

	// ── Optional AES-256-GCM encryption ─────────────────────────────────────
	if encryptKey != "" {
		encrypted, err := core.EncryptReport(data, encryptKey)
		if err != nil {
			fmt.Printf("\033[1;31m[-] Encryption failed: %v — saving plaintext\033[0m\n", err)
		} else {
			data = encrypted
			fmt.Printf("\033[1;32m[+] Report encrypted with AES-256-GCM\033[0m\n")
		}
	}

	_ = os.WriteFile(path, data, 0600)
	fmt.Printf("\033[1;32m[+] Report saved to %s\033[0m\n", path)
}
