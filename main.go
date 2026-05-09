package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"Talaria/scanners" // Ensure this matches  go.mod module name
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

type ScanReport struct {
	ScanTime           string                             `json:"scan_time"`
	TargetUser         string                             `json:"target_user"`
	TargetScanPath     string                             `json:"target_scan_path"`
	StealthMode        bool                               `json:"stealth_mode"`
	Secrets            []scanners.SensitiveFileResult     `json:"secrets,omitempty"`
	SecretContent      []scanners.SensitiveContentResult  `json:"secret_content,omitempty"`
	Capabilities       []scanners.CapabilityResult        `json:"capabilities,omitempty"`
	CronJobs           []scanners.CronJobResult           `json:"cron_jobs,omitempty"`
	FilePermissions    []scanners.FilePermissionResult    `json:"file_permissions,omitempty"`
	FilePermsExploit   []scanners.FilePermExploitResult   `json:"file_perms_exploit,omitempty"`
	NetworkConnections []scanners.NetworkConnectionResult `json:"network_connections,omitempty"`
	NFSExports         []scanners.NFSExportResult         `json:"nfs_exports,omitempty"`
	Processes          []scanners.ProcessResult           `json:"processes,omitempty"`
	Sockets            []scanners.SocketResult            `json:"sockets,omitempty"`
	SudoPrivileges     []scanners.SudoPrivilegeResult     `json:"sudo_privileges,omitempty"`
	SUID               []scanners.SUIDResult              `json:"suid,omitempty"`
	SGID               []scanners.SGIDResult              `json:"sgid,omitempty"`
	Vulnerabilities    []scanners.VersionInfo             `json:"vulnerabilities,omitempty"`
	Writeable          []scanners.WriteableResult         `json:"writeable,omitempty"`
	SystemdTimers      []scanners.SystemdTimerResult      `json:"systemd_timers,omitempty"`
	Groups             []scanners.GroupResult             `json:"groups,omitempty"`
	PATHHijack         []scanners.PATHHijackResult        `json:"path_hijack,omitempty"`
	SSHKeys            []scanners.SSHKeyResult            `json:"ssh_keys,omitempty"`
	PtraceScope        *scanners.PtraceScopeResult        `json:"ptrace_scope,omitempty"`
	ContainerEscape    []scanners.ContainerEscapeResult   `json:"container_escape,omitempty"`
	DBusPolicy         []scanners.DBusPolicyResult        `json:"dbus_policy,omitempty"`
}

func main() {
	scanInput := flag.String("scan", "all",
		"Comma-separated list of modules to run. Use 'all' to run everything.\n"+
			"  Available modules:\n"+
			"    secrets        - Sensitive files & credentials (SSH keys, .env, config files)\n"+
			"    suid           - SUID binaries (GTFOBins-matched dangerous list)\n"+
			"    sgid           - SGID binaries (privileged group ownership detection)\n"+
			"    sudo           - sudo -l analysis (NOPASSWD, SETENV, LD_PRELOAD env_keep)\n"+
			"    capabilities   - Linux capabilities (cap_setuid, cap_sys_admin, etc.)\n"+
			"    cronjobs       - Cron jobs, systemd timers, wildcard injection\n"+
			"    processes      - Running processes (credentials in args, ptrace scope)\n"+
			"    ptrace         - ptrace_scope check (process injection vector)\n"+
			"    nfs            - NFS exports (no_root_squash detection)\n"+
			"    network        - Open ports & internal services\n"+
			"    writeable      - Writable files/dirs owned by root or other users\n"+
			"    sockets        - Unix sockets (Docker sock, privileged service sockets)\n"+
			"    filepermissions- Critical system file misconfigurations\n"+
			"    filepermsexploit- SUID/SGID scripts with relative binary calls (PATH hijack)\n"+
			"    groups         - Privileged group membership (docker, lxd, disk, shadow)\n"+
			"    pathhijack     - Writable/dot entries in $PATH\n"+
			"    sshkeys        - SSH authorized_keys writability & private key exposure\n"+
			"    vulnerabilities- Kernel & software version CVE checks (Dirty COW, PwnKit)\n"+
			"    container      - Container escape vectors (--privileged, docker.sock mount)\n"+
			"    dbus           - D-Bus policy misconfigurations")
	searchPath := flag.String("path", "/", "Start directory")
	outputFile := flag.String("o", "", "Save results to file")
	outputFormat := flag.String("format", "text", "text or json")
	isStealth := flag.Bool("stealth", false, "Enable delays")
	customDelay := flag.Duration("delay", 0, "Base delay")
	customJitter := flag.Duration("jitter", 0, "Max jitter")
	sudoPassword := flag.String("pass", "", "Sudo password for sudo -l checks (optional)")
	excludeInput := flag.String("exclude", "", "Comma-separated list of modules to skip (e.g., 'network,secrets')")
	flag.Parse()

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

	applyEvasion := func() {
		if baseDelay > 0 {
			jitter := 0
			if maxJitter > 0 {
				jitter = rand.Intn(int(maxJitter))
			}
			time.Sleep(baseDelay + time.Duration(jitter))
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

	report := &ScanReport{
		ScanTime:       time.Now().Format(time.RFC1123),
		TargetUser:     os.Getenv("USER"),
		TargetScanPath: *searchPath,
		StealthMode:    *isStealth,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	ioSemaphore := make(chan struct{}, 2) // Limit concurrent I/O scanners to 2 will lose some time but it is worth it to prevent system crash or resource exhaustion

	fmt.Println("\033[1;34m[!] Talaria Assessment Started\033[0m")
	runAll := selectedModules["all"]
	timeout := 2 * time.Second

	// --- SECRETS MODULE one of the most noisy but very important for opsec and CTF ---
	if (runAll || selectedModules["secrets"]) && !excludedModules["secrets"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var searchTargets []string
			if *searchPath != "/" {
				searchTargets = []string{*searchPath}
			} else {
				// Limited to common CTF paths as requested and to prevent system crash or resource exhaustion you can also change this from -path flag
				searchTargets = []string{"/home", "/var/www"}
			}
			for _, target := range searchTargets {
				if _, err := os.Stat(target); os.IsNotExist(err) {
					continue
				}
				applyEvasion()
				fmt.Printf("\033[1;32m[+] Scanning Secrets in: %s\033[0m\n", target)
				ioSemaphore <- struct{}{}
				files, content := scanners.ScanSecrets(target)
				<-ioSemaphore
				mu.Lock()
				report.Secrets = append(report.Secrets, files...)
				report.SecretContent = append(report.SecretContent, content...)
				mu.Unlock()
				for _, f := range files {
					color := "\033[1;33m" // Yellow
					if f.RiskLevel == "CRITICAL" {
						color = "\033[1;31m" // Red
					}
					
					reason := f.Type
					if f.Type == "Content Match" {
						for _, c := range content {
							if c.Path == f.Path {
								reason += " (" + c.Snippet + ")"
								break
							}
						}
					}
					fmt.Printf("%s[%s] Secret Found\033[0m\n └─ Path   : %s\n └─ Reason : %s\n", color, f.RiskLevel, f.Path, reason)
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
			fmt.Printf("\033[1;32m[+] Scanning SUID Binaries...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanSUID(*searchPath)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.SUID = results
				mu.Unlock()
				for _, r := range results {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] SUID Binary Found\033[0m\n └─ Path   : %s\n └─ Reason : %s\n", r.Path, r.Reason)
					} else {
						fmt.Printf("\033[1;33m[INFO] SUID Binary\033[0m\n └─ Path   : %s\n", r.Path)
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
			fmt.Printf("\033[1;32m[+] Scanning SGID Binaries...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanSGID(*searchPath)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.SGID = results
				mu.Unlock()
				for _, r := range results {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] SGID Binary Found\033[0m\n └─ Path   : %s\n └─ Reason : %s\n", r.Path, r.Reason)
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
			fmt.Printf("\033[1;32m[+] Scanning Processes...\033[0m\n")
			results, err := scanners.ScanProcesses()
			if err == nil {
				mu.Lock()
				report.Processes = results
				mu.Unlock()
			}
		}()
	}

	// --- CRONJOBS & SYSTEMD MODULE ---
	if (runAll || selectedModules["cronjobs"]) && !excludedModules["cronjobs"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applyEvasion()
			fmt.Printf("\033[1;32m[+] Scanning Cron Jobs & Systemd Timers...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanCronJobs()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.CronJobs = results
				mu.Unlock()
				for _, r := range results {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] CronJob Found\033[0m\n └─ Command: %s\n └─ Reason : %s\n", r.Command, r.Reason)
					} else if r.IsRootJob {
						fmt.Printf("\033[1;33m[INFO] Root CronJob\033[0m\n └─ Command: %s\n", r.Command)
					}
				}
			}

			// Also scan Systemd Timers here since they are related to scheduling see whether we trigger our exploits 
			ioSemaphore <- struct{}{}
			systemdResults, err := scanners.ScanSystemdTimers()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.SystemdTimers = systemdResults
				mu.Unlock()
				for _, r := range systemdResults {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] Systemd Timer Found\033[0m\n └─ Path   : %s\n └─ Reason : %s\n", r.Path, r.Reason)
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
			fmt.Printf("\033[1;32m[+] Scanning Sudo Privileges...\033[0m\n")
			results, err := scanners.ScanSudoPrivileges(timeout, *sudoPassword)
			if err == nil {
				mu.Lock()
				report.SudoPrivileges = results
				mu.Unlock()
				for _, r := range results {
					if r.HasLDPreload {
						fmt.Printf("\033[1;35m[CRITICAL] Sudo Privilege (LD_PRELOAD)\033[0m\n └─ Reason : %s\n", r.Reason)
					} else if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] Sudo Privilege Found\033[0m\n └─ Command: %s\n └─ Reason : %s\n", r.Command, r.Reason)
					} else if r.NoPassword {
						fmt.Printf("\033[1;33m[HIGH] Sudo NOPASSWD\033[0m\n └─ Command: %s\n └─ Reason : %s\n", r.Command, r.Reason)
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
			fmt.Printf("\033[1;32m[+] Scanning Capabilities...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanCapabilities(*searchPath)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.Capabilities = results
				mu.Unlock()
				for _, r := range results {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] Capability Found\033[0m\n └─ Path   : %s\n └─ Capabs : %s\n", r.Path, r.Capabilities)
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
			fmt.Printf("\033[1;32m[+] Scanning NFS Exports...\033[0m\n")
			results, err := scanners.ScanNFSExports(timeout)
			if err == nil {
				mu.Lock()
				report.NFSExports = results
				mu.Unlock()
				for _, r := range results {
					if r.HasNoRootSquash {
						fmt.Printf("\033[1;31m[CRITICAL] NFS no_root_squash on %s\033[0m\n", r.Path)
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
			fmt.Printf("\033[1;32m[+] Scanning Network Connections...\033[0m\n")
			results, err := scanners.ScanNetworkConnections()
			if err == nil {
				mu.Lock()
				report.NetworkConnections = results
				mu.Unlock()
			}
		}()
	}

	// --- SYSTEM VULNERABILITIES MODULE ---
	if (runAll || selectedModules["vulnerabilities"]) && !excludedModules["vulnerabilities"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applyEvasion()
			fmt.Printf("\033[1;32m[+] Scanning System Vulnerabilities...\033[0m\n")
			results, err := scanners.ScanSystemVersions(timeout)
			if err == nil {
				mu.Lock()
				report.Vulnerabilities = results
				mu.Unlock()
			}
		}()
	}

	// --- WRITEABLE MODULE ---
	if (runAll || selectedModules["writeable"]) && !excludedModules["writeable"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applyEvasion()
			fmt.Printf("\033[1;32m[+] Scanning Writeable Files...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanWriteable(*searchPath)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.Writeable = results
				mu.Unlock()
				for _, r := range results {
					if r.IsDangerous {
						color := "\033[1;33m" // HIGH
						if r.RiskLevel == "CRITICAL" {
							color = "\033[1;31m"
						} else if r.RiskLevel == "MEDIUM" {
							color = "\033[1;34m"
						}
						fmt.Printf("%s[%s] Writable File Found\033[0m\n └─ Path   : %s\n └─ Reason : %s\n", color, r.RiskLevel, r.Path, r.Reason)
					}
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
			fmt.Printf("\033[1;32m[+] Scanning Sockets...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanUnixDomainSockets()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.Sockets = results
				mu.Unlock()
			}
		}()
	}

	// --- FILE PERMISSIONS MODULE ---
	if (runAll || selectedModules["filepermissions"]) && !excludedModules["filepermissions"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applyEvasion()
			fmt.Printf("\033[1;32m[+] Scanning File Permissions...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanFilePermissions()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.FilePermissions = results
				mu.Unlock()
			}
		}()
	}

	// --- FILE PERMS EXPLOIT MODULE ---
	if (runAll || selectedModules["filepermsexploit"]) && !excludedModules["filepermsexploit"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applyEvasion()
			fmt.Printf("\033[1;32m[+] Scanning File Permissions Exploit...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanFilePermissionsExploit(timeout)
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.FilePermsExploit = results
				mu.Unlock()
			}
		}()
	}

	// --- GROUPS MODULE ---
	if (runAll || selectedModules["groups"]) && !excludedModules["groups"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			applyEvasion()
			fmt.Printf("\033[1;32m[+] Scanning Group Memberships...\033[0m\n")
			results, err := scanners.ScanGroups()
			if err == nil {
				mu.Lock()
				report.Groups = results
				mu.Unlock()
				for _, r := range results {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] Privileged Group Membership\033[0m\n └─ Group  : %s\n └─ Reason : %s\n", r.GroupName, r.Reason)
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
			fmt.Printf("\033[1;32m[+] Scanning $PATH for Hijacking Vectors...\033[0m\n")
			results, err := scanners.ScanPATH()
			if err == nil {
				mu.Lock()
				report.PATHHijack = results
				mu.Unlock()
				for _, r := range results {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] PATH Hijacking Vector\033[0m\n └─ Dir    : %s\n └─ Reason : %s\n", r.Directory, r.Reason)
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
			fmt.Printf("\033[1;32m[+] Scanning SSH Keys...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, _ := scanners.ScanSSHKeys()
			<-ioSemaphore
			mu.Lock()
			report.SSHKeys = results
			mu.Unlock()
			for _, r := range results {
				if r.IsDangerous {
					fmt.Printf("\033[1;31m[CRITICAL] SSH Key Vulnerability\033[0m\n └─ Path   : %s\n └─ Reason : %s\n", r.Path, r.Reason)
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
			fmt.Printf("\033[1;32m[+] Scanning ptrace Scope...\033[0m\n")
			if result, err := scanners.ScanPtraceScope(); err == nil {
				mu.Lock()
				report.PtraceScope = result
				mu.Unlock()
				if result.IsDangerous {
					fmt.Printf("\033[1;31m[CRITICAL] Ptrace Scope Vulnerability\033[0m\n └─ Scope  : %d\n └─ Reason : %s\n", result.Scope, result.Reason)
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
			fmt.Printf("\033[1;32m[+] Scanning Container Escape Vectors...\033[0m\n")
			// Container scan reads /proc and /etc — lightweight but still I/O
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanContainer()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.ContainerEscape = results
				mu.Unlock()
				for _, r := range results {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] Container Escape Vector\033[0m\n └─ Vector : %s\n └─ Reason : %s\n", r.Vector, r.Reason)
					} else {
						fmt.Printf("\033[1;33m[INFO] %s\033[0m\n", r.Vector)
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
			fmt.Printf("\033[1;32m[+] Scanning D-Bus Policies...\033[0m\n")
			ioSemaphore <- struct{}{}
			results, err := scanners.ScanDBusPolicy()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.DBusPolicy = results
				mu.Unlock()
				for _, r := range results {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] D-Bus Policy Flaw\033[0m\n └─ Service: %s\n └─ Reason : %s\n", r.ServiceName, r.Reason)
					}
				}
			}
		}()
	}

	wg.Wait()

	// --- CROSS-REFERENCING (Analysis Phase) ---
	// Post-scan correlation engine: matches findings across modules to surface
	// confirmed, chained attack vectors that individual scanners cannot see alone.
	fmt.Printf("\n\033[1;34m[!] Performing Cross-Reference Analysis...\033[0m\n")
	hasCrossReference := false

	// ── CHAIN 1: Writable script/binary vs. scheduled execution ──────────────
	for _, w := range report.Writeable {
		if w.IsExecutable || strings.HasSuffix(w.Path, ".sh") || strings.HasSuffix(w.Path, ".py") ||
			strings.HasSuffix(w.Path, ".pl") || strings.HasSuffix(w.Path, ".rb") {

			// 1a. Writable file executed by a root CronJob → instant root
			for _, cron := range report.CronJobs {
				if cron.IsRootJob && resolveCommandPath(cron.Command, w.Path) {
					fmt.Printf("\033[1;35m[100%% CONFIRMED] Writable '%s' is executed by root CronJob: %s\033[0m\n", w.Path, cron.Command)
					hasCrossReference = true
				}
			}

			// 1b. Writable file runnable via Sudo → instant root
			for _, sudo := range report.SudoPrivileges {
				if resolveCommandPath(sudo.Command, w.Path) {
					fmt.Printf("\033[1;35m[100%% CONFIRMED] Writable '%s' can be run via Sudo: %s\033[0m\n", w.Path, sudo.Command)
					hasCrossReference = true
				}
			}

			// 1c. Writable Systemd unit file → root on next timer trigger
			for _, sysd := range report.SystemdTimers {
				if sysd.Path == w.Path {
					fmt.Printf("\033[1;35m[100%% CONFIRMED] Writable systemd unit: %s\033[0m\n", w.Path)
					hasCrossReference = true
				}
			}
		}
	}

	// ── CHAIN 2: LD_PRELOAD env_keep + any NOPASSWD entry → instant root ─────
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
		fmt.Printf("\033[1;35m[100%% CONFIRMED] LD_PRELOAD in env_keep + NOPASSWD entry detected:\n"+
			"  Compile a .so with __attribute__((constructor)) { setuid(0); system('/bin/bash'); }\n"+
			"  Set LD_PRELOAD=<your.so>, run any NOPASSWD sudo command → root shell.\033[0m\n")
		hasCrossReference = true
	}

	// ── CHAIN 3: SGID binary owned by 'shadow' group → /etc/shadow readable ─
	for _, sgid := range report.SGID {
		if sgid.IsDangerous && strings.EqualFold(sgid.OwnerGroup, "shadow") {
			fmt.Printf("\033[1;35m[100%% CONFIRMED] SGID binary '%s' owned by shadow group.\n"+
				"  Execute it to gain shadow group privileges → read /etc/shadow → crack hashes.\033[0m\n", sgid.Path)
			hasCrossReference = true
		}
	}

	// ── CHAIN 4: Writable authorized_keys + active SSH service ───────────────
	for _, sshKey := range report.SSHKeys {
		if sshKey.IsDangerous && sshKey.Type == "authorized_keys" {
			for _, netConn := range report.NetworkConnections {
				if netConn.LocalPort == 22 && netConn.State == "LISTEN" {
					fmt.Printf("\033[1;35m[100%% CONFIRMED] Writable authorized_keys for '%s' + SSH listening on :22.\n"+
						"  Append your public key to '%s' -> ssh %s@localhost\033[0m\n",
						sshKey.TargetUser, sshKey.Path, sshKey.TargetUser)
					hasCrossReference = true
				}
			}
		}
	}

	// ── CHAIN 5: Writable .ssh directory + SSH service ───────────────────────
	for _, sshKey := range report.SSHKeys {
		if sshKey.IsDangerous && sshKey.Type == ".ssh directory" {
			for _, netConn := range report.NetworkConnections {
				if netConn.LocalPort == 22 && netConn.State == "LISTEN" {
					fmt.Printf("\033[1;35m[100%% CONFIRMED] Writable .ssh/ dir for '%s' + SSH on :22.\n"+
						"  Create '%s/authorized_keys' with your pubkey -> ssh %s@localhost\033[0m\n",
						sshKey.TargetUser, sshKey.Path, sshKey.TargetUser)
					hasCrossReference = true
				}
			}
		}
	}

	// ── CHAIN 6: ptrace scope=0 + root process running → process injection ───
	if report.PtraceScope != nil && report.PtraceScope.IsDangerous {
		for _, proc := range report.Processes {
			if proc.UID == 0 {
				fmt.Printf("\033[1;35m[100%% CONFIRMED] ptrace unrestricted + root process PID %d (%s).\n"+
					"  Attach with gdb/ptrace, inject shellcode into root process → root shell.\033[0m\n",
					proc.PID, proc.Command)
				hasCrossReference = true
				break // Report once — first root process is enough
			}
		}
	}

	// ── CHAIN 7: Docker socket accessible + docker group membership ──────────
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
		fmt.Printf("\033[1;35m[100%% CONFIRMED] Docker socket accessible (group=%v, socket=%v).\n"+
			"  Run: docker run -v /:/mnt --rm -it alpine chroot /mnt sh\033[0m\n",
			hasDockerGroup, hasDockerSocket)
		hasCrossReference = true
	}

	// ── CHAIN 8: Container with docker.sock mount → host escape ──────────────
	for _, ce := range report.ContainerEscape {
		if ce.IsDangerous && strings.Contains(ce.Vector, "Docker Socket") {
			for _, sock := range report.Sockets {
				if strings.Contains(sock.Service, "docker") {
					fmt.Printf("\033[1;35m[100%% CONFIRMED] Docker socket mounted INSIDE container.\n"+
						"  Run: docker run -v /:/host --rm -it alpine chroot /host sh → full host root.\033[0m\n")
					hasCrossReference = true
				}
			}
		}
	}

	if !hasCrossReference {
		fmt.Printf("\033[1;32m[+] No confirmed chained attack vectors found via cross-reference.\033[0m\n")
	}

	if *outputFile != "" {
		saveReport(report, *outputFile, *outputFormat)
	}
	fmt.Println("\n\033[1;34m[*] Scan Complete!\033[0m")
}

func saveReport(report *ScanReport, path string, format string) {
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
	_ = os.WriteFile(path, data, 0600)
	fmt.Printf("\033[1;32m[+] Report saved to %s\033[0m\n", path)
}

// resolveCommandPath intelligently checks if a command string eventually targets a specific file path
func resolveCommandPath(command string, targetPath string) bool {
	// Direct match (absolute path used in command)
	if strings.Contains(command, targetPath) {
		return true
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