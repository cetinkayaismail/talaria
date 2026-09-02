package scanners

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// NFSExportResult holds the findings for a specific NFS share
type NFSExportResult struct {
	Path            string `json:"path"`
	ExportedTo      string `json:"exported_to"`
	Options         string `json:"options"`
	HasNoRootSquash bool   `json:"has_no_root_squash"`
	HasNoAllSquash  bool   `json:"has_no_all_squash"`
	IsWritable      bool   `json:"is_writable"`
	IsDangerous     bool   `json:"is_dangerous"`
	RiskSummary     string `json:"risk_summary"`
	Remediation     string `json:"remediation,omitempty"`
	ComplianceTag   string `json:"compliance_tag,omitempty"`
}

// ScanNFSExports identifies misconfigured NFS shares that could lead to PrivEsc
func ScanNFSExports(timeout time.Duration) ([]NFSExportResult, error) {
	var results []NFSExportResult

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 1. Primary Check: Read /etc/exports (Standard configuration file)
	// Native file reading is preferred over shell commands for stealth
	if content, err := os.ReadFile("/etc/exports"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Ignore comments and empty lines
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			result := parseNFSExportLine(line)
			if result != nil {
				results = append(results, *result)
			}
		}
	}

	// 2. Dynamic Check: Use showmount to see active exports (Fallback)
	cmd := exec.CommandContext(ctx, "showmount", "-e", "localhost")
	if output, err := cmd.Output(); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		isFirstLine := true
		for scanner.Scan() {
			if isFirstLine {
				isFirstLine = false // Skip "Export list for localhost:" header
				continue
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 2 {
				results = append(results, NFSExportResult{
					Path:          parts[0],
					ExportedTo:    parts[1],
					Options:       "Active Export",
					IsDangerous:   true,
					RiskSummary:   "NFS share is active - check /etc/exports for squash options",
					Remediation:   "Ensure 'root_squash' option is configured in /etc/exports",
					ComplianceTag: "CIS-Linux-2.2.7 / DISA-STIG-V-230300",
				})
			}
		}
	}

	return results, nil
}

// parseNFSExportLine extracts security flags from an export entry
func parseNFSExportLine(line string) *NFSExportResult {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	path := parts[0]
	exportedClients := strings.Join(parts[1:], " ")

	noRootSquash := false
	noAllSquash := false
	isWritable := false
	isDangerous := false
	risks := []string{}

	// Analyze each client/option set (e.g., *(rw,no_root_squash))
	for _, part := range parts[1:] {
		if strings.Contains(part, "(") && strings.Contains(part, ")") {
			start := strings.Index(part, "(")
			end := strings.Index(part, ")")
			options := strings.Split(part[start+1:end], ",")

			for _, opt := range options {
				opt = strings.TrimSpace(opt)
				switch opt {
				case "no_root_squash":
					noRootSquash = true
					isDangerous = true
					risks = append(risks, "no_root_squash")
				case "no_all_squash":
					noAllSquash = true
					risks = append(risks, "no_all_squash")
				case "rw", "read-write":
					isWritable = true
				case "insecure":
					isDangerous = true
					risks = append(risks, "insecure_port")
				}
			}
		}
	}

	// Logic for Critical Vulnerability: RW + no_root_squash = High probability of PrivEsc
	summary := strings.Join(risks, ", ")
	remediation := ""
	complianceTag := "CIS-Linux-2.2.7 / DISA-STIG-V-230300"

	if isWritable && noRootSquash {
		isDangerous = true
		summary = "CRITICAL: RW + no_root_squash (Direct PrivEsc via SUID upload)"
		remediation = "Replace 'no_root_squash' with 'root_squash' in /etc/exports and run 'exportfs -ra'"
	} else if noRootSquash {
		remediation = "Replace 'no_root_squash' with 'root_squash' in /etc/exports and run 'exportfs -ra'"
	}

	return &NFSExportResult{
		Path:            path,
		ExportedTo:      exportedClients,
		Options:         strings.Join(parts[1:], " "),
		HasNoRootSquash: noRootSquash,
		HasNoAllSquash:  noAllSquash,
		IsWritable:      isWritable,
		IsDangerous:     isDangerous,
		RiskSummary:     summary,
		Remediation:     remediation,
		ComplianceTag:   complianceTag,
	}
}
