package core

import (
	"fmt"
	"strings"
	"sync"
	"talaria/models"
)

var printMu sync.Mutex

// ANSI Color Codes
const (
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
	ColorRed    = "\033[1;31m"
	ColorGreen  = "\033[1;32m"
	ColorYellow = "\033[1;33m"
	ColorBlue   = "\033[1;34m"
	ColorPurple = "\033[1;35m"
	ColorCyan   = "\033[1;36m"
	ColorGray   = "\033[1;90m"
)

// PrintBanner displays the Talaria ASCII banner
func PrintBanner() {
	banner := `
  ████████╗ █████╗ ██╗      █████╗ ██████╗ ██╗ █████╗ 
  ╚══██╔══╝██╔══██╗██║     ██╔══██╗██╔══██╗██║██╔══██╗
     ██║   ███████║██║     ███████║██████╔╝██║███████║
     ██║   ██╔══██║██║     ██╔══██║██╔══██╗██║██╔══██║
     ██║   ██║  ██║███████╗██║  ██║██║  ██║██║██║  ██║
     ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
    >> Linux Privilege Escalation & Lateral Intelligence <<
`
	fmt.Printf("%s%s%s\n", ColorBlue, banner, ColorReset)
}

// PrintSectionHeader prints a clear, bordered section header
func PrintSectionHeader(title string) {
	printMu.Lock()
	defer printMu.Unlock()

	width := 60
	title = " " + strings.ToUpper(title) + " "
	sideLen := (width - len(title)) / 2
	if sideLen < 3 {
		sideLen = 3
	}
	line := strings.Repeat("─", sideLen)
	fmt.Printf("\n%s%s[%s%s%s]%s%s\n", ColorGray, line, ColorBold+ColorBlue, title, ColorReset+ColorGray, line, ColorReset)
}

// PrintFinding prints a structured finding block
func PrintFinding(severity string, title string, details map[string]string, exploit string) {
	printMu.Lock()
	defer printMu.Unlock()

	color := ColorGray
	label := severity
	
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		color = ColorRed
	case "HIGH":
		color = ColorPurple
	case "LATERAL MOVEMENT CONFIRMED":
		color = ColorCyan
	case "MEDIUM":
		color = ColorYellow
	case "LOW", "INFO":
		color = ColorBlue
	}

	fmt.Printf("%s[%s] %s%s\n", color, label, title, ColorReset)
	
	// Print details in a tree format
	keys := []string{}
	for k := range details {
		keys = append(keys, k)
	}
	
	for i, k := range keys {
		prefix := " ├─"
		if i == len(keys)-1 && exploit == "" {
			prefix = " └─"
		}
		fmt.Printf("%s %-8s: %s\n", prefix, k, details[k])
	}
	
	if exploit != "" {
		fmt.Printf(" └─ %sExploit : %s%s\n", ColorYellow, exploit, ColorReset)
	}
}

// PrintSummary displays the final dashboard of findings
func PrintSummary(report *models.ScanReport, duration string) {
	PrintSectionHeader("SCAN SUMMARY")
	
	critical := 0
	high := 0
	medium := 0

	// Helper to count by risk level
	countRisk := func(level string) {
		switch strings.ToUpper(level) {
		case "CRITICAL": critical++
		case "HIGH": high++
		case "MEDIUM": medium++
		}
	}

	for _, s := range report.Secrets { countRisk(s.RiskLevel) }
	for _, s := range report.SUID { if s.IsDangerous { critical++ } }
	for _, s := range report.SGID { if s.IsDangerous { critical++ } }
	for _, s := range report.SudoPrivileges { 
		if s.HasLDPreload || s.IsDangerous { critical++ } else if s.NoPassword { high++ }
	}
	for _, s := range report.CronJobs { if s.IsDangerous { critical++ } }
	for _, s := range report.SystemdTimers { if s.IsDangerous { critical++ } }
	for _, s := range report.Capabilities { if s.IsDangerous { critical++ } }
	for _, s := range report.Writeable { if s.RiskLevel == "CRITICAL" { critical++ } else if s.RiskLevel == "HIGH" { high++ } else if s.RiskLevel == "MEDIUM" { medium++ } }
	for _, s := range report.Vulnerabilities { if s.IsDangerous { critical++ } }
	for _, s := range report.PATHHijack { if s.IsDangerous { critical++ } }
	for _, s := range report.SSHKeys { if s.IsDangerous { critical++ } }
	for _, s := range report.SessionHijack { if s.IsDangerous { critical++ } }
	for _, s := range report.ContainerEscape { if s.IsDangerous { critical++ } }
	for _, s := range report.DBusPolicy { if s.IsDangerous { critical++ } }
	for _, s := range report.KernelConfig { if s.RiskLevel == "CRITICAL" { critical++ } else if s.RiskLevel == "HIGH" { high++ } else if s.RiskLevel == "MEDIUM" { medium++ } }
	for _, s := range report.HistorySecrets { countRisk(s.RiskLevel) }
	for _, s := range report.Logrotate { countRisk(s.RiskLevel) }
	for _, s := range report.EnvFileResults { countRisk(s.RiskLevel) }

	// Logic for lateral counts would need RunIntelligenceEngine results or similar
	// For now, let's keep it simple

	fmt.Printf("  %s%-20s: %d%s\n", ColorRed, "CRITICAL FINDINGS", critical, ColorReset)
	fmt.Printf("  %s%-20s: %d%s\n", ColorPurple, "HIGH RISK", high, ColorReset)
	fmt.Printf("  %s%-20s: %d%s\n", ColorYellow, "MEDIUM RISK", medium, ColorReset)
	
	fmt.Printf("\n%s[*] Report saved to: %s%s\n", ColorGreen, "models/ScanReport", ColorReset)
	fmt.Printf("%s[*] Total execution time: %s%s\n", ColorGray, duration, ColorReset)
}
