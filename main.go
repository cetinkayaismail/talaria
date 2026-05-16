package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
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
			"    kernelconfig    - Kernel config leak (CONFIG_STRICT_DEVMEM, etc.)")
	searchPath   := flag.String("path", "/", "Root directory for filesystem scans (default: /)")
	outputFile   := flag.String("o", "", "Save report to file (combine with --format)")
	outputFormat := flag.String("format", "text", "Report format: text or json")
	sudoPassword := flag.String("pass", "", "Sudo password for sudo -l checks (optional)")
	excludeInput := flag.String("exclude", "", "Comma-separated modules to skip (e.g. network,secrets)")
	professionalMode := flag.Bool("professional", false, "Professional reporting mode (hides exploit hints, cleaner output)")
	pMode := flag.Bool("p", false, "Professional reporting mode (shorthand)")
	ioLimit := flag.Int("io-limit", 0, "Max concurrent I/O scanners (default: auto based on RLIMIT_NOFILE)")

	// ── Delay/jitter (existing stealth tier 1) ────────────────────────────────
	isStealth   := flag.Bool("stealth", false, "[STEALTH] Enable random delays between module launches")
	customDelay := flag.Duration("delay", 0, "[STEALTH] Base delay between module launches (e.g. 150ms)")
	customJitter:= flag.Duration("jitter", 0, "[STEALTH] Max random jitter added on top of base delay")

	// ── Advanced stealth flags (inactive by default) ──────────────────────────
	maskName     := flag.String("mask", "",
		"[STEALTH] Overwrite process name in ps/top/htop.\n"+
		"          Example: --mask '[kworker/u2:1]'")
	selfDestruct := flag.Bool("self-destruct", false,
		"[STEALTH] Delete the binary from disk after scan completes (report written first)")
	atimeRestore := flag.Bool("atime-restore", false,
		"[STEALTH] Restore file access timestamps after reading sensitive files.\n"+
		"          Prevents atime-based forensic detection.")
	throttleLoad := flag.Float64("throttle", 0,
		"[STEALTH] Pause when system load/CPU exceeds this ratio (e.g. 0.8 = 80%).\n"+
		"          Reduces I/O burst anomaly signatures. 0 = disabled.")
	encryptKey   := flag.String("encrypt", "",
		"[STEALTH] Encrypt report with AES-256-GCM using this passphrase.\n"+
		"          Requires -o to be set. Output is base64-encoded ciphertext.")

	// Custom usage printer — groups core, stealth and reporting flags visually
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Talaria - Linux Privilege Escalation Scanner\n")
		fmt.Fprintf(os.Stderr, "Usage: talaria [flags]\n\n")
		fmt.Fprintf(os.Stderr, "CORE FLAGS:\n")
		for _, name := range []string{"scan", "exclude", "path", "o", "format", "pass", "io-limit"} {
			f := flag.Lookup(name)
			if f != nil {
				fmt.Fprintf(os.Stderr, "  --%-18s %s\n", f.Name, f.Usage)
			}
		}
		fmt.Fprintf(os.Stderr, "\nREPORTING FLAGS:\n")
		for _, name := range []string{"professional", "p"} {
			f := flag.Lookup(name)
			if f != nil {
				fmt.Fprintf(os.Stderr, "  --%-18s %s\n", f.Name, f.Usage)
			}
		}
		fmt.Fprintf(os.Stderr, "\nSTEALTH FLAGS (all inactive by default):\n")
		for _, name := range []string{"stealth", "delay", "jitter", "mask", "atime-restore", "throttle", "encrypt", "self-destruct"} {
			f := flag.Lookup(name)
			if f != nil {
				fmt.Fprintf(os.Stderr, "  --%-18s %s\n", f.Name, f.Usage)
			}
		}
		fmt.Fprintf(os.Stderr, "\nSee USAGE.md for detailed examples and the stealth bundle workflow.\n")
	}

	flag.Parse()

	isProfessional := *professionalMode || *pMode

	rand.Seed(time.Now().UnixNano())
	baseDelay := *customDelay
	maxJitter := *customJitter
	if *isStealth {
		if baseDelay == 0 {
			baseDelay = 150 * time.Millisecond
		}
		if maxJitter == 0 {
			maxJitter = 100 * time.Millisecond
		}
	}

	// ── Stealth: activate package-level config (no-op when flags not set) ────
	if *maskName != "" {
		scanners.MaskProcess(*maskName)
	}
	if *atimeRestore {
		scanners.StealthCfg.AtimeRestore = true
	}

	core.PrintBanner()
	if *maskName != "" {
		fmt.Printf("%s[stealth] Process masked as: %s%s\n", core.ColorGray, *maskName, core.ColorReset)
	}
	if *atimeRestore {
		fmt.Printf("%s[stealth] atime-restore: enabled%s\n", core.ColorGray, core.ColorReset)
	}

	// ── Lazy CPU count for adaptive throttle (computed once) ─────────────────
	numCPUs := 1
	if *throttleLoad > 0 {
		numCPUs = scanners.GetNumCPUs()
		fmt.Printf("%s[stealth] Adaptive throttle: load/cpu > %.2f → extra pause (cpus=%d)%s\n",
			core.ColorGray, *throttleLoad, numCPUs, core.ColorReset)
	}

	applyEvasion := func() {
		delay := baseDelay

		// Adaptive throttle: if system is already busy, slow down to blend in
		if *throttleLoad > 0 {
			load := scanners.GetSystemLoad()
			loadPerCPU := load / float64(numCPUs)
			if loadPerCPU > *throttleLoad {
				// Scale extra pause with how far over threshold we are
				extra := time.Duration((loadPerCPU-*throttleLoad)*1000) * time.Millisecond
				if extra > 5*time.Second {
					extra = 5 * time.Second // cap at 5s so we don't hang forever
				}
				delay += extra
			}
		}

		if delay > 0 {
			jitter := 0
			if maxJitter > 0 {
				jitter = rand.Intn(int(maxJitter))
			}
			time.Sleep(delay + time.Duration(jitter))
		}
	}

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
		StealthMode:    *isStealth,
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
				applyEvasion()
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
			applyEvasion()
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
			applyEvasion()
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
			applyEvasion()
			results, err := scanners.ScanProcesses()
			if err == nil {
				mu.Lock()
				report.Processes = results
				mu.Unlock()
				if len(results) > 0 {
					core.PrintSectionHeader("Processes")
					for _, r := range results {
						if r.IsDangerous {
							core.PrintFinding("CRITICAL", "Dangerous Process", map[string]string{
								"PID":     fmt.Sprintf("%d", r.PID),
								"User":    r.User,
								"Command": r.Command,
							}, "")
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
			applyEvasion()
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
			applyEvasion()
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
		}()
	}

	// --- CAPABILITIES MODULE ---
	if (runAll || selectedModules["capabilities"]) && !excludedModules["capabilities"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applyEvasion()
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
			applyEvasion()
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
			applyEvasion()
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
							if r.IsDangerous {
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
			applyEvasion()
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
									"CVE":     v.CVE,
									"Name":    v.Name,
									"Version": r.Version,
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
			applyEvasion()
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
		}()
	}

	// --- SOCKETS MODULE ---
	if (runAll || selectedModules["sockets"]) && !excludedModules["sockets"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applyEvasion()
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
			applyEvasion()
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
			applyEvasion()
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
								hint = "Prepend a malicious binary to your PATH and run the target."
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
			applyEvasion()
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
			applyEvasion()
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
			applyEvasion()
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
							core.PrintFinding("CRITICAL", "Package Misconfiguration", map[string]string{
								"Tool":   r.Name,
								"Reason": r.Reason,
							}, hint)
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
			applyEvasion()
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
			applyEvasion()
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
			applyEvasion()
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
			applyEvasion()
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
			applyEvasion()
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
			applyEvasion()
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
		}()
	}

	// --- KERNEL CONFIG MODULE (#6) ---
	if (runAll || selectedModules["kernelconfig"]) && !excludedModules["kernelconfig"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applyEvasion()
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

	wg.Wait()

	// --- CROSS-REFERENCING (Analysis Phase) ---
	core.RunIntelligenceEngine(report)

	if *outputFile != "" {
		saveReport(report, *outputFile, *outputFormat, *encryptKey)
	}

	duration := time.Since(startTime).String()
	core.PrintSummary(report, duration)

	// ── Self-Destruct ────────────────────────────────────────────────────────
	if *selfDestruct {
		exePath, err := os.Executable()
		if err == nil {
			if err := os.Remove(exePath); err == nil {
				fmt.Printf("\033[1;90m[stealth] Binary removed: %s\033[0m\n", exePath)
			} else {
				fmt.Printf("\033[1;31m[stealth] Self-destruct failed: %v\033[0m\n", err)
			}
		}
	}
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

		sb.WriteString(fmt.Sprintf("\nSummary Counts:\nSecrets: %d\nCronJobs: %d\nSudo Privs: %d\nCapabilities: %d\n",
			len(report.Secrets), len(report.CronJobs), len(report.SudoPrivileges), len(report.Capabilities)))
		data = []byte(sb.String())
	}

	// ── Optional AES-256-GCM encryption ─────────────────────────────────────
	if encryptKey != "" {
		encrypted, err := scanners.EncryptReport(data, encryptKey)
		if err != nil {
			fmt.Printf("\033[1;31m[stealth] Encryption failed: %v — saving plaintext\033[0m\n", err)
		} else {
			data = encrypted
			fmt.Printf("\033[1;90m[stealth] Report encrypted with AES-256-GCM\033[0m\n")
		}
	}

	_ = os.WriteFile(path, data, 0600)
	fmt.Printf("\033[1;32m[+] Report saved to %s\033[0m\n", path)
}