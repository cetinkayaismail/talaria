package cmd

import (
	"flag"
	"fmt"
	"strings"
)

// Config encapsulates all parsed command-line flags and runtime settings.
type Config struct {
	ScanModules     string
	ExcludeModules  string
	RootPath        string
	OutputFile      string
	OutputFormat    string
	SudoPassword    string
	IOLimit         int
	EncryptKey      string
	CTFMode         bool
	AuditMode       bool
	ShowUI          bool
	NoColor         bool
	QuietMode       bool   // Phase 4: Suppress interactive banners for CI/CD pipelines
	FailOn          string // Phase 4: CI/CD policy threshold: CRITICAL, HIGH, MEDIUM
}

// ParseFlags registers and parses all command-line arguments.
func ParseFlags(args []string) (*Config, error) {
	fs := flag.NewFlagSet("talaria", flag.ContinueOnError)

	cfg := &Config{}

	fs.StringVar(&cfg.ScanModules, "scan", "all", "Comma-separated list of modules to run, or 'all'.")
	fs.StringVar(&cfg.ExcludeModules, "exclude", "", "Comma-separated list of modules to skip.")
	fs.StringVar(&cfg.RootPath, "path", "/", "Root directory for filesystem scans.")
	fs.StringVar(&cfg.OutputFile, "o", "", "Save report to file (requires --format).")
	fs.StringVar(&cfg.OutputFormat, "format", "text", "Report format: 'text', 'json', or 'sarif'.")
	fs.StringVar(&cfg.SudoPassword, "pass", "", "Sudo password for sudo -l checks (optional).")
	fs.IntVar(&cfg.IOLimit, "io-limit", 0, "Max concurrent I/O scanners (default: auto based on RLIMIT_NOFILE).")
	fs.StringVar(&cfg.EncryptKey, "encrypt", "", "Encrypt saved report with AES-256-GCM using this passphrase (requires -o).")

	fs.BoolVar(&cfg.CTFMode, "ctf", false, "CTF / offensive mode: focuses on rapid root escalation and GTFOBins 1-liners (default).")
	fs.BoolVar(&cfg.AuditMode, "audit", false, "Audit / compliance mode: focuses on remediation fix commands and CIS tags.")
	fs.BoolVar(&cfg.AuditMode, "professional", false, "Alias for --audit.")
	fs.BoolVar(&cfg.AuditMode, "p", false, "Alias for --audit (shorthand).")

	fs.BoolVar(&cfg.ShowUI, "ui", false, "Enable visual summary dashboard card.")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI colors.")

	// Phase 4 CI/CD Flags
	fs.StringVar(&cfg.FailOn, "fail-on", "", "CI/CD Policy Gate: Exit code 1 if findings meet or exceed severity (CRITICAL, HIGH, MEDIUM).")
	fs.BoolVar(&cfg.QuietMode, "quiet", false, "Pipeline mode: suppress ASCII banners and animated headers.")
	fs.BoolVar(&cfg.QuietMode, "q", false, "Alias for --quiet (shorthand).")

	fs.Usage = func() {
		PrintUsage()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Validate FailOn flag if provided
	if cfg.FailOn != "" {
		normalized := strings.ToUpper(cfg.FailOn)
		if normalized != "CRITICAL" && normalized != "HIGH" && normalized != "MEDIUM" {
			return nil, fmt.Errorf("invalid --fail-on value '%s': must be CRITICAL, HIGH, or MEDIUM", cfg.FailOn)
		}
		cfg.FailOn = normalized
	}

	// Validate mode mutual exclusivity
	if cfg.CTFMode && cfg.AuditMode {
		return nil, fmt.Errorf("cannot specify both --ctf and --audit modes")
	}

	// Validate encryption flag requires output file
	if cfg.EncryptKey != "" && cfg.OutputFile == "" {
		return nil, fmt.Errorf("--encrypt requires -o (output file path)")
	}

	// Validate report output format
	fmtNorm := strings.ToLower(cfg.OutputFormat)
	if fmtNorm != "text" && fmtNorm != "json" && fmtNorm != "sarif" {
		return nil, fmt.Errorf("invalid --format value '%s': must be 'text', 'json', or 'sarif'", cfg.OutputFormat)
	}
	cfg.OutputFormat = fmtNorm

	return cfg, nil
}

// PrintUsage prints the full CLI reference documentation.
func PrintUsage() {
	fmt.Println("Talaria - Linux Privilege Escalation & Security Audit Scanner")
	fmt.Println("Usage: talaria [flags]")
	fmt.Println("\nCORE FLAGS:")
	fmt.Println("  --scan               Comma-separated list of modules to run. Use 'all' to run everything.")
	fmt.Println("  --exclude            Comma-separated modules to skip (e.g. network,secrets)")
	fmt.Println("  --path               Root directory for filesystem scans (default: /)")
	fmt.Println("  --o                  Save report to file (combine with --format)")
	fmt.Println("  --format             Report format: text, json, or sarif")
	fmt.Println("  --pass               Sudo password for sudo -l checks (optional)")
	fmt.Println("  --io-limit           Max concurrent I/O scanners (default: auto based on RLIMIT_NOFILE)")
	fmt.Println("  --encrypt            Encrypt saved report with AES-256-GCM using this passphrase (requires -o)")
	fmt.Println("\nOPERATIONAL MODES:")
	fmt.Println("  --ctf                CTF / offensive mode: rapid root escalation and GTFOBins exploits (default)")
	fmt.Println("  --audit              Audit / compliance mode: remediation commands and CIS/NIST tags")
	fmt.Println("  --professional       Alias for --audit")
	fmt.Println("  --p                  Alias for --audit (shorthand)")
	fmt.Println("\nCI/CD & AUTOMATION (PHASE 4):")
	fmt.Println("  --fail-on=SEVERITY   Exit code 1 if findings meet or exceed threshold (CRITICAL, HIGH, MEDIUM)")
	fmt.Println("  --quiet, -q          Pipeline mode: suppress banner and decorative output for CI/CD logs")
	fmt.Println("\nPRESENTATION FLAGS:")
	fmt.Println("  --ui                 Enable visual summary dashboard card")
	fmt.Println("  --no-color           Disable ANSI colors (also respects NO_COLOR environment variable)")
	fmt.Println("\nAvailable modules:")
	fmt.Println("  secrets, suid, sgid, sudo, capabilities, cronjobs, processes, ptrace, nfs,")
	fmt.Println("  network, writeable, sockets, filepermissions, filepermsexploit, groups,")
	fmt.Println("  pathhijack, sshkeys, vulnerabilities, container, dbus, services, packages,")
	fmt.Println("  sessions, kernelconfig, polkit, environmentfile, pam, sysctl, systemdoverrides,")
	fmt.Println("  subuid, mounts, elfrpath, auditd, udev, crondirs, procenv, ldnss, modprobe,")
	fmt.Println("  cloudmeta, venvwrap, sudokens, wildcards, python_hijack, initscripts, logrotate")
}
