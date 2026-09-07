package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"
	"sync"
	"syscall"
	"time"

	"talaria/core"
	"talaria/models"
	"talaria/scanners"
)

// Execute acts as the central command orchestrator for the Talaria application.
// Returns an exit code: 0 for success/compliant, 1 for CI/CD policy violation, 2 for CLI usage errors.
func Execute() int {
	startTime := time.Now()

	cfg, err := ParseFlags(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[-] Argument error: %v\n", err)
		return 2
	}

	// 1. Initialize System & User Context
	scanners.InitUserContext()
	targetUser := "unknown"
	if u, err := user.Current(); err == nil {
		targetUser = u.Username
	}

	// 2. Configure Presentation Engine
	core.Config.NoColor = cfg.NoColor
	core.Config.EnableUI = cfg.ShowUI
	if cfg.AuditMode {
		core.Config.Mode = core.ModeAudit
		scanners.AuditCfg.MaskSecrets = true
	} else {
		core.Config.Mode = core.ModeCTF
		scanners.AuditCfg.MaskSecrets = false
	}

	if !cfg.QuietMode {
		core.PrintBanner()
	}

	// 3. Configure Dynamic I/O Semaphore based on RLIMIT_NOFILE
	ioConcurrency := determineIOConcurrency(cfg.IOLimit)
	if !cfg.QuietMode {
		fmt.Printf("[io] I/O concurrency limit: %d (based on RLIMIT_NOFILE=%d)\n", ioConcurrency, getAvailableFileDescriptors())
		fmt.Printf("[!] Talaria Assessment Started\n\n")
	}

	ioSemaphore := make(chan struct{}, ioConcurrency)

	// 4. Parse Selected and Excluded Modules
	selectedModules := make(map[string]bool)
	runAll := false
	if strings.ToLower(cfg.ScanModules) == "all" {
		runAll = true
	} else {
		for _, mod := range strings.Split(cfg.ScanModules, ",") {
			m := strings.TrimSpace(strings.ToLower(mod))
			if m != "" {
				selectedModules[m] = true
			}
		}
	}

	excludedModules := make(map[string]bool)
	if cfg.ExcludeModules != "" {
		for _, mod := range strings.Split(cfg.ExcludeModules, ",") {
			m := strings.TrimSpace(strings.ToLower(mod))
			if m != "" {
				excludedModules[m] = true
			}
		}
	}

	report := &models.ScanReport{
		ScanTime:       startTime.Format(time.RFC3339),
		TargetUser:     targetUser,
		TargetScanPath: cfg.RootPath,
		AuditMode:      cfg.AuditMode,
	}

	var mu sync.Mutex
	dispatchCtx := &DispatchContext{
		Report:          report,
		Mu:              &mu,
		Config:          cfg,
		Timeout:         15 * time.Second,
		IOSemaphore:     ioSemaphore,
		SelectedModules: selectedModules,
		ExcludedModules: excludedModules,
		RunAll:          runAll,
	}

	// 5. Execute Scanners via Table-Driven Module Registry (OPT-02)
	registry := BuildModuleRegistry()
	DispatchRegistry(dispatchCtx, registry)

	// 6. Execute Intelligence Engine (Cross-Reference & Graph Analysis)
	core.RunIntelligenceEngine(report)

	// 7. Output Final Summary Dashboard
	duration := time.Since(startTime).String()
	core.PrintSummary(report, duration)

	// 8. Save Report if requested
	if cfg.OutputFile != "" {
		if err := SaveReport(report, cfg.OutputFile, cfg.OutputFormat, cfg.EncryptKey); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to save report: %v\n", err)
		}
	}

	// 9. CI/CD Policy Gating (--fail-on)
	if cfg.FailOn != "" {
		failed, msg := EvaluatePolicy(report, cfg.FailOn)
		if failed {
			fmt.Fprintf(os.Stderr, "\n\033[1;31m[-] %s\033[0m\n", msg)
			return 1
		}
		if !cfg.QuietMode {
			fmt.Printf("\n\033[1;32m[+] %s\033[0m\n", msg)
		}
	}

	return 0
}

func determineIOConcurrency(requested int) int {
	if requested > 0 {
		return requested
	}
	rlimit := getAvailableFileDescriptors()
	limit := int(rlimit / 64)
	if limit < 2 {
		limit = 2
	}
	if limit > 64 {
		limit = 64
	}
	return limit
}

func getAvailableFileDescriptors() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil {
		return rl.Cur
	}
	return 1024
}
