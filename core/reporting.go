package core

import (
	"fmt"
	"strings"
	"sync"
	"talaria/models"
)

var printMu sync.Mutex

// EngineMode represents the operational presentation profile
type EngineMode int

const (
	// ModeCTF is the offensive root-finder profile: focuses on rapid exploitation,
	// GTFOBins 1-liners, cleartext credentials, and lowest screen noise (default).
	ModeCTF EngineMode = iota

	// ModeAudit is the blue-team compliance profile: focuses on remediation fix commands,
	// CIS/NIST compliance tags, and credential masking.
	ModeAudit
)

// ReportingConfig controls output rendering behavior
type ReportingConfig struct {
	Mode     EngineMode
	EnableUI bool
	NoColor  bool
}

// Config is the global active reporting configuration
var Config = ReportingConfig{
	Mode:     ModeCTF,
	EnableUI: false,
	NoColor:  false,
}

// ANSI Color Codes
const (
	rawReset  = "\033[0m"
	rawBold   = "\033[1m"
	rawRed    = "\033[1;31m"
	rawGreen  = "\033[1;32m"
	rawYellow = "\033[1;33m"
	rawBlue   = "\033[1;34m"
	rawPurple = "\033[1;35m"
	rawCyan   = "\033[1;36m"
	rawGray   = "\033[1;90m"
)

func c(code string) string {
	if Config.NoColor || !ShouldUseColor() {
		return ""
	}
	return code
}

// Exported color helpers for backward compatibility
var (
	ColorReset  = rawReset
	ColorBold   = rawBold
	ColorRed    = rawRed
	ColorGreen  = rawGreen
	ColorYellow = rawYellow
	ColorBlue   = rawBlue
	ColorPurple = rawPurple
	ColorCyan   = rawCyan
	ColorGray   = rawGray
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
    >> Linux Privilege Escalation & Lateral Intelligence <<`

	if ShouldUseColor() && !Config.NoColor {
		fmt.Printf("%s%s%s\n\n", rawBlue, banner, rawReset)
	} else {
		fmt.Printf("%s\n\n", banner)
	}
}

// PrintSectionHeader prints a stream-friendly or UI-bordered section header
func PrintSectionHeader(title string) {
	printMu.Lock()
	defer printMu.Unlock()
	renderSectionHeaderLocked(title)
}

func renderSectionHeaderLocked(title string) {
	upperTitle := strings.ToUpper(strings.TrimSpace(title))

	if Config.EnableUI && IsTerminal() {
		termWidth, _ := GetTerminalWidth()
		bracketed := fmt.Sprintf("[ %s ]", upperTitle)
		sideLen := (termWidth - len(bracketed)) / 2
		if sideLen < 3 {
			sideLen = 3
		}
		line := strings.Repeat("=", sideLen)
		fmt.Printf("\n%s%s%s%s%s%s\n", c(rawGray), line, c(rawBold+rawBlue)+bracketed+c(rawReset), c(rawGray), line, c(rawReset))
	} else {
		// Clean stream-friendly header: universal across all shells, pipes, and minimal Alpine boxes
		fmt.Printf("\n=== %s ===\n", upperTitle)
	}
}

// PrintFinding prints a structured finding block adapted to CTF vs Audit mode
func PrintFinding(severity string, title string, details map[string]string, exploit string) {
	printMu.Lock()
	defer printMu.Unlock()
	renderFindingLocked(severity, title, details, exploit)
}

func renderFindingLocked(severity string, title string, details map[string]string, exploit string) {
	sevColor := c(rawGray)
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		sevColor = c(rawRed)
	case "HIGH":
		sevColor = c(rawPurple)
	case "LATERAL MOVEMENT CONFIRMED":
		sevColor = c(rawCyan)
	case "MEDIUM":
		sevColor = c(rawYellow)
	case "LOW", "INFO":
		sevColor = c(rawBlue)
	}

	// Extract mode-specific fields
	remediation := ""
	compliance := ""

	cleanDetails := make(map[string]string)
	for k, v := range details {
		switch strings.ToLower(k) {
		case "remediation":
			remediation = v
		case "compliance", "compliancetag", "compliance_tag":
			compliance = v
		default:
			cleanDetails[k] = v
		}
	}

	termWidth, _ := GetTerminalWidth()

	// 1. Header Line
	if Config.Mode == ModeAudit && compliance != "" {
		fmt.Printf("%s[%s] %s%s %s[%s]%s\n", sevColor, severity, title, c(rawReset), c(rawCyan), compliance, c(rawReset))
	} else {
		fmt.Printf("%s[%s] %s%s\n", sevColor, severity, title, c(rawReset))
	}

	// 2. Details in a clean indentation
	keys := []string{}
	for k := range cleanDetails {
		keys = append(keys, k)
	}

	for _, k := range keys {
		val := cleanDetails[k]
		line := fmt.Sprintf("  - %-8s: %s", k, val)
		if len(line) > termWidth && IsTerminal() {
			indent := fmt.Sprintf("    %-8s  ", "")
			line = fmt.Sprintf("  - %-8s: %s", k, WrapText(val, termWidth, indent))
		}
		fmt.Println(line)
	}

	// 3. Mode-specific Action Payload
	if Config.Mode == ModeAudit {
		if remediation != "" {
			fmt.Printf("  %s[-] Remediation : %s%s\n", c(rawGreen), remediation, c(rawReset))
		}
	} else {
		// CTF Mode (default): display exploit 1-liner prominently
		if exploit != "" {
			fmt.Printf("  %s[!] Exploit     : %s%s\n", c(rawYellow), exploit, c(rawReset))
		}
	}
}

// SectionFinding holds an in-memory finding item for batch flushing.
type SectionFinding struct {
	Severity string
	Title    string
	Details  map[string]string
	Exploit  string
}

// SectionBuffer buffers section headers and findings to output them atomically,
// preventing concurrent scanners from interleaving their output on stdout.
type SectionBuffer struct {
	Title    string
	Findings []SectionFinding
}

// NewSectionBuffer creates a new in-memory section buffer.
func NewSectionBuffer(title string) *SectionBuffer {
	return &SectionBuffer{
		Title:    title,
		Findings: make([]SectionFinding, 0),
	}
}

// AddFinding queues a finding into the section buffer.
func (sb *SectionBuffer) AddFinding(severity string, title string, details map[string]string, exploit string) {
	sb.Findings = append(sb.Findings, SectionFinding{
		Severity: severity,
		Title:    title,
		Details:  details,
		Exploit:  exploit,
	})
}

// Flush atomically renders the section header and all queued findings under a single mutex lock.
func (sb *SectionBuffer) Flush() {
	if len(sb.Findings) == 0 {
		return
	}
	printMu.Lock()
	defer printMu.Unlock()

	renderSectionHeaderLocked(sb.Title)
	for _, f := range sb.Findings {
		renderFindingLocked(f.Severity, f.Title, f.Details, f.Exploit)
	}
}

// PrintSummary displays the final scan outcome
func PrintSummary(report *models.ScanReport, duration string) {
	printMu.Lock()
	defer printMu.Unlock()

	critical := 0
	high := 0
	medium := 0

	countRisk := func(level string) {
		switch strings.ToUpper(level) {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		}
	}

	for _, s := range report.Secrets {
		countRisk(s.RiskLevel)
	}
	for _, s := range report.SUID {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.SGID {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.SudoPrivileges {
		if s.HasLDPreload || s.IsDangerous {
			critical++
		} else if s.NoPassword {
			high++
		}
	}
	for _, s := range report.CronJobs {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.SystemdTimers {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.Capabilities {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.Writeable {
		if s.RiskLevel == "CRITICAL" {
			critical++
		} else if s.RiskLevel == "HIGH" {
			high++
		} else if s.RiskLevel == "MEDIUM" {
			medium++
		}
	}
	for _, s := range report.Vulnerabilities {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.PATHHijack {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.SSHKeys {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.SessionHijack {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.ContainerEscape {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.DBusPolicy {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.KernelConfig {
		countRisk(s.RiskLevel)
	}
	for _, s := range report.HistorySecrets {
		countRisk(s.RiskLevel)
	}
	for _, s := range report.Logrotate {
		countRisk(s.RiskLevel)
	}
	for _, s := range report.EnvFileResults {
		countRisk(s.RiskLevel)
	}
	for _, s := range report.NetworkConnections {
		countRisk(s.RiskLevel)
	}
	for _, s := range report.FilePermissions {
		if s.IsDangerous {
			critical++
		} else if s.CanWrite {
			high++
		}
	}
	for _, s := range report.FilePermsExploit {
		if s.IsDangerous {
			critical++
		}
	}
	for _, s := range report.SudoTokens {
		countRisk(s.RiskLevel)
	}
	for _, s := range report.SudoersDropin {
		countRisk(s.RiskLevel)
	}
	for _, s := range report.ShellRC {
		countRisk(s.RiskLevel)
	}
	for _, a := range report.AtJobs {
		countRisk(a.RiskLevel)
	}
	for _, f := range report.Fstab {
		countRisk(f.RiskLevel)
	}
	for _, s := range report.SnapAudit {
		countRisk(s.RiskLevel)
	}
	for _, g := range report.GitHooks {
		countRisk(g.RiskLevel)
	}
	for _, x := range report.Xinetd {
		countRisk(x.RiskLevel)
	}

	modeStr := "CTF / OFFENSIVE"
	if Config.Mode == ModeAudit {
		modeStr = "ENTERPRISE AUDIT"
	}

	if Config.EnableUI && IsTerminal() {
		termWidth, _ := GetTerminalWidth()
		border := strings.Repeat("-", termWidth-2)
		fmt.Printf("\n+%s+\n", border)
		fmt.Printf("| TALARIA SCAN SUMMARY // Mode: %-36s |\n", modeStr)
		fmt.Printf("+%s+\n", border)
		fmt.Printf("|   CRITICAL FINDINGS : %-39d |\n", critical)
		fmt.Printf("|   HIGH RISK         : %-39d |\n", high)
		fmt.Printf("|   MEDIUM RISK       : %-39d |\n", medium)
		fmt.Printf("|   Execution Time    : %-39s |\n", duration)
		fmt.Printf("+%s+\n\n", border)
	} else {
		// Clean stream summary
		fmt.Printf("\n=== SCAN SUMMARY [%s] ===\n", modeStr)
		fmt.Printf("[✓] Scan completed in %s\n", duration)
		fmt.Printf("    Findings: %d Critical, %d High, %d Medium\n", critical, high, medium)
		if Config.Mode == ModeAudit {
			if critical+high > 0 {
				fmt.Printf("    Audit Status: Non-compliant (%d high-priority policy violations require remediation)\n\n", critical+high)
			} else {
				fmt.Printf("    Audit Status: Passed (zero critical or high findings)\n\n")
			}
		} else {
			if critical > 0 {
				fmt.Printf("    Target Status: Root privilege escalation vector identified above.\n\n")
			} else {
				fmt.Printf("    Target Status: No trivial root vector identified.\n\n")
			}
		}
	}
}
