package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"Talaria/scanners" // Ensure this matches your go.mod module name
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
	Vulnerabilities    []scanners.VersionInfo             `json:"vulnerabilities,omitempty"`
	Writeable          []scanners.WriteableResult         `json:"writeable,omitempty"`
	SystemdTimers      []scanners.SystemdTimerResult      `json:"systemd_timers,omitempty"`
	Groups             []scanners.GroupResult             `json:"groups,omitempty"`
	PATHHijack         []scanners.PATHHijackResult        `json:"path_hijack,omitempty"`
}

func main() {
	scanInput := flag.String("scan", "all", "Modules: secrets, suid, processes, groups, cronjobs, etc.")
	searchPath := flag.String("path", "/", "Start directory")
	outputFile := flag.String("o", "", "Save results to file")
	outputFormat := flag.String("format", "text", "text or json")
	isStealth := flag.Bool("stealth", false, "Enable delays")
	customDelay := flag.Duration("delay", 0, "Base delay")
	customJitter := flag.Duration("jitter", 0, "Max jitter")
	sudoPassword := flag.String("pass", "", "Sudo password for sudo -l checks (optional)")
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

	report := &ScanReport{
		ScanTime:       time.Now().Format(time.RFC1123),
		TargetUser:     os.Getenv("USER"),
		TargetScanPath: *searchPath,
		StealthMode:    *isStealth,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	ioSemaphore := make(chan struct{}, 2) // Limit concurrent I/O scanners to 2

	fmt.Println("\033[1;34m[!] Talaria Assessment Started\033[0m")
	runAll := selectedModules["all"]
	timeout := 2 * time.Second

	// --- SECRETS MODULE ---
	if runAll || selectedModules["secrets"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var searchTargets []string
			if *searchPath != "/" {
				searchTargets = []string{*searchPath}
			} else {
				// Limited to common CTF paths as requested
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
					fmt.Printf("%s[!!!] %s: %s\033[0m\n", color, f.RiskLevel, f.Path)
				}
			}
		}()
	}

	// --- SUID MODULE ---
	if runAll || selectedModules["suid"] {
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
						fmt.Printf("\033[1;31m[CRITICAL] SUID: %s\033[0m\n", r.Path)
					} else {
						fmt.Printf("\033[1;33m[INFO] SUID: %s\033[0m\n", r.Path)
					}
				}
			}
		}()
	}

	// --- PROCESSES MODULE ---
	if runAll || selectedModules["processes"] {
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
	if runAll || selectedModules["cronjobs"] {
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
						fmt.Printf("\033[1;31m[CRITICAL] CronJob %s: %s\033[0m\n", r.Reason, r.Command)
					} else if r.IsRootJob {
						fmt.Printf("\033[1;33m[INFO] Root CronJob: %s\033[0m\n", r.Command)
					}
				}
			}

			// Also scan Systemd Timers here since they are related to scheduling
			ioSemaphore <- struct{}{}
			systemdResults, err := scanners.ScanSystemdTimers()
			<-ioSemaphore
			if err == nil {
				mu.Lock()
				report.SystemdTimers = systemdResults
				mu.Unlock()
				for _, r := range systemdResults {
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] Systemd %s: %s\033[0m\n", r.Reason, r.Path)
					}
				}
			}
		}()
	}

	// --- SUDO PRIVILEGES MODULE ---
	if runAll || selectedModules["sudo"] {
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
					if r.IsDangerous {
						fmt.Printf("\033[1;31m[CRITICAL] Sudo Privilege: %s\033[0m\n", r.Command)
					} else if r.NoPassword {
						fmt.Printf("\033[1;33m[HIGH] Sudo NOPASSWD: %s\033[0m\n", r.Command)
					}
				}
			}
		}()
	}

	// --- CAPABILITIES MODULE ---
	if runAll || selectedModules["capabilities"] {
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
						fmt.Printf("\033[1;31m[CRITICAL] Capability %s on %s\033[0m\n", r.Capabilities, r.Path)
					}
				}
			}
		}()
	}

	// --- NFS EXPORTS MODULE ---
	if runAll || selectedModules["nfs"] {
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
	if runAll || selectedModules["network"] {
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
	if runAll || selectedModules["vulnerabilities"] {
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
	if runAll || selectedModules["writeable"] {
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
			}
		}()
	}

	// --- SOCKETS MODULE ---
	if runAll || selectedModules["sockets"] {
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
	if runAll || selectedModules["filepermissions"] {
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
	if runAll || selectedModules["filepermsexploit"] {
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
	if runAll || selectedModules["groups"] {
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
						fmt.Printf("\033[1;31m[CRITICAL] Member of privileged group '%s': %s\033[0m\n", r.GroupName, r.Reason)
					}
				}
			}
		}()
	}

	// --- PATH HIJACKING MODULE ---
	if runAll || selectedModules["pathhijack"] {
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
						fmt.Printf("\033[1;31m[CRITICAL] PATH Hijacking: %s -> %s\033[0m\n", r.Reason, r.Directory)
					}
				}
			}
		}()
	}

	wg.Wait()

	// --- CROSS-REFERENCING (Analysis Phase) ---
	// Match writeable files against Cron jobs and Sudo privileges
	fmt.Printf("\n\033[1;34m[!] Performing Cross-Reference Analysis...\033[0m\n")
	hasCrossReference := false

	for _, w := range report.Writeable {
		if w.IsExecutable || strings.HasSuffix(w.Path, ".sh") || strings.HasSuffix(w.Path, ".py") {
			
			// 1. Check if the writeable file is run by a Root CronJob
			for _, cron := range report.CronJobs {
				if cron.IsRootJob && strings.Contains(cron.Command, w.Path) {
					fmt.Printf("\033[1;35m[100%% CONFIRMED CRITICAL] Writeable file '%s' is executed by root CronJob: %s\033[0m\n", w.Path, cron.Command)
					hasCrossReference = true
				}
			}

			// 2. Check if the writeable file can be run via Sudo
			for _, sudo := range report.SudoPrivileges {
				if strings.Contains(sudo.Command, w.Path) {
					fmt.Printf("\033[1;35m[100%% CONFIRMED CRITICAL] Writeable file '%s' can be executed via Sudo: %s\033[0m\n", w.Path, sudo.Command)
					hasCrossReference = true
				}
			}

			// 3. Check Systemd Timers
			for _, sysd := range report.SystemdTimers {
				// A crude but effective check: does the systemd path itself match, or does it run our script?
				// (Parsing ExecStart from the file would be better, but path match works for hijacked units)
				if sysd.Path == w.Path {
					fmt.Printf("\033[1;35m[100%% CONFIRMED CRITICAL] Writeable Systemd unit file: %s\033[0m\n", w.Path)
					hasCrossReference = true
				}
			}
		}
	}
	
	if !hasCrossReference {
		fmt.Printf("\033[1;32m[+] No direct cross-reference execution vectors found.\033[0m\n")
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
		data = []byte(fmt.Sprintf(
			"Scan Time: %s\nSecrets Found: %d\nSUID Found: %d\nCronJobs Found: %d\nSudo Privs Found: %d\nCapabilities Found: %d\n",
			report.ScanTime,
			len(report.Secrets),
			len(report.SUID),
			len(report.CronJobs),
			len(report.SudoPrivileges),
			len(report.Capabilities),
		))
	}
	_ = os.WriteFile(path, data, 0644)
	fmt.Printf("\033[1;32m[+] Report saved to %s\033[0m\n", path)
}