package core

import (
	"encoding/json"
	"fmt"
	"strings"

	"talaria/models"
)

// SARIF v2.1.0 Data Structures according to OASIS Standard
// Schema: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json

// SARIFLog represents the root document of a SARIF v2.1.0 report.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single static analysis run.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
	Results     []SARIFResult     `json:"results"`
}

// SARIFTool describes the analysis tool that generated the run.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the primary analysis engine.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule represents a rule definition in the driver rules catalog.
type SARIFRule struct {
	ID                   string                         `json:"id"`
	Name                 string                         `json:"name"`
	ShortDescription     SARIFMultiformatMessageString `json:"shortDescription"`
	FullDescription      *SARIFMultiformatMessageString `json:"fullDescription,omitempty"`
	DefaultConfiguration SARIFConfiguration             `json:"defaultConfiguration"`
	HelpURI              string                         `json:"helpUri,omitempty"`
	Properties           map[string]interface{}         `json:"properties,omitempty"`
}

// SARIFConfiguration defines rule default severity settings.
type SARIFConfiguration struct {
	Level string `json:"level"` // "error", "warning", "note", "none"
}

// SARIFMultiformatMessageString holds formatted text descriptions.
type SARIFMultiformatMessageString struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFInvocation describes the environment and execution metrics of the run.
type SARIFInvocation struct {
	ExecutionSuccessful bool                   `json:"executionSuccessful"`
	StartTimeUTC        string                 `json:"startTimeUtc,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

// SARIFResult represents an individual finding discovered by a scanner.
type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"` // "error", "warning", "note"
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Fixes      []SARIFFix             `json:"fixes,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage holds message text for results and fixes.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes the location of a finding.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation specifies the artifact and region of a finding.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation specifies file URI.
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SARIFRegion specifies line location within an artifact.
type SARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// SARIFFix represents suggested remediation action.
type SARIFFix struct {
	Description SARIFMessage `json:"description"`
}

// sarifBuilder collects rules and findings into an indexed catalog.
type sarifBuilder struct {
	ruleMap   map[string]int
	rules     []SARIFRule
	results   []SARIFResult
	criticals int
	highs     int
	mediums   int
	lows      int
}

func newSARIFBuilder() *sarifBuilder {
	return &sarifBuilder{
		ruleMap: make(map[string]int),
		rules:   make([]SARIFRule, 0),
		results: make([]SARIFResult, 0),
	}
}

func (b *sarifBuilder) registerRule(id, name, shortDesc, fullDesc string, defaultLevel string, tags []string) int {
	if idx, exists := b.ruleMap[id]; exists {
		return idx
	}

	idx := len(b.rules)
	b.ruleMap[id] = idx

	rule := SARIFRule{
		ID:   id,
		Name: name,
		ShortDescription: SARIFMultiformatMessageString{
			Text: shortDesc,
		},
		DefaultConfiguration: SARIFConfiguration{
			Level: defaultLevel,
		},
		Properties: map[string]interface{}{
			"tags": tags,
		},
	}
	if fullDesc != "" {
		rule.FullDescription = &SARIFMultiformatMessageString{
			Text: fullDesc,
		}
	}
	b.rules = append(b.rules, rule)
	return idx
}

func (b *sarifBuilder) addResult(ruleID, ruleName, shortDesc, fullDesc, riskLevel, path, message, remediation, complianceTag, exploitHint string, tags []string) {
	sarifLevel := mapRiskToSARIFLevel(riskLevel)

	switch sarifLevel {
	case "error":
		if strings.Contains(strings.ToUpper(riskLevel), "CRITICAL") {
			b.criticals++
		} else {
			b.highs++
		}
	case "warning":
		b.mediums++
	default:
		b.lows++
	}

	ruleIdx := b.registerRule(ruleID, ruleName, shortDesc, fullDesc, sarifLevel, tags)

	result := SARIFResult{
		RuleID:    ruleID,
		RuleIndex: ruleIdx,
		Level:     sarifLevel,
		Message: SARIFMessage{
			Text: message,
		},
		Properties: map[string]interface{}{
			"riskLevel": riskLevel,
		},
	}

	if complianceTag != "" {
		result.Properties["complianceTag"] = complianceTag
	}
	if remediation != "" {
		result.Properties["remediation"] = remediation
		result.Fixes = []SARIFFix{
			{
				Description: SARIFMessage{
					Text: fmt.Sprintf("Remediation: %s", remediation),
				},
			},
		}
	}
	if exploitHint != "" {
		result.Properties["exploitHint"] = exploitHint
	}

	if path != "" {
		uri := path
		if !strings.HasPrefix(uri, "file://") && strings.HasPrefix(uri, "/") {
			uri = "file://" + uri
		}
		result.Locations = []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: uri,
					},
					Region: &SARIFRegion{
						StartLine: 1,
					},
				},
			},
		}
	}

	b.results = append(b.results, result)
}

func mapRiskToSARIFLevel(riskLevel string) string {
	r := strings.ToUpper(riskLevel)
	switch {
	case strings.Contains(r, "CRITICAL") || strings.Contains(r, "HIGH") || strings.Contains(r, "100% CONFIRMED"):
		return "error"
	case strings.Contains(r, "MEDIUM"):
		return "warning"
	case strings.Contains(r, "LOW") || strings.Contains(r, "INFO") || strings.Contains(r, "POTENTIAL"):
		return "note"
	default:
		return "note"
	}
}

// GenerateSARIFReport serializes a ScanReport into standardized SARIF v2.1.0 JSON.
func GenerateSARIFReport(report *models.ScanReport) ([]byte, error) {
	builder := newSARIFBuilder()

	// 1. Secrets
	for _, s := range report.Secrets {
		msg := fmt.Sprintf("Exposed %s in %s", s.Type, s.Path)
		builder.addResult(
			"TAL-SEC-001", "ExposedSensitiveFile",
			"Exposed sensitive credential or key file found",
			"A sensitive file such as a private key, cloud credential, or password file is accessible.",
			s.RiskLevel, s.Path, msg, s.Remediation, s.ComplianceTag, "",
			[]string{"security", "credentials", "secrets"},
		)
	}
	for _, sc := range report.SecretContent {
		msg := fmt.Sprintf("Hardcoded secret snippet discovered in %s: %s", sc.Path, sc.Snippet)
		builder.addResult(
			"TAL-SEC-002", "HardcodedSecretContent",
			"Hardcoded secret content discovered in file",
			"File contains inline cleartext passwords, API tokens, or credentials.",
			"HIGH", sc.Path, msg, sc.Remediation, sc.ComplianceTag, "",
			[]string{"security", "credentials", "secrets"},
		)
	}

	// 2. SUID / SGID
	for _, su := range report.SUID {
		if !su.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Dangerous SUID binary '%s' allows root escalation: %s", su.Path, su.Reason)
		builder.addResult(
			"TAL-SUID-001", "DangerousSUIDBinary",
			"Dangerous SUID binary with exploit vector discovered",
			"Binary runs with effective root UID and contains known GTFOBins or shell bypass vectors.",
			"CRITICAL", su.Path, msg, su.Remediation, su.ComplianceTag, su.ExploitHint,
			[]string{"security", "privilege-escalation", "suid"},
		)
	}
	for _, sg := range report.SGID {
		if !sg.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Dangerous SGID binary '%s' (owner group: %s): %s", sg.Path, sg.OwnerGroup, sg.Reason)
		builder.addResult(
			"TAL-SGID-001", "DangerousSGIDBinary",
			"Dangerous SGID binary discovered",
			"Binary runs with group privileges and contains exploitable execution vectors.",
			"CRITICAL", sg.Path, msg, sg.Remediation, sg.ComplianceTag, sg.ExploitHint,
			[]string{"security", "privilege-escalation", "sgid"},
		)
	}

	// 3. Sudo Privileges & Tokens
	for _, sp := range report.SudoPrivileges {
		risk := sp.RiskLevel
		if risk == "" {
			if sp.HasLDPreload || sp.IsDangerous {
				risk = "CRITICAL"
			} else if sp.NoPassword {
				risk = "HIGH"
			} else {
				risk = "MEDIUM"
			}
		}
		msg := fmt.Sprintf("Sudo rule allows command '%s' as run_as '%s' (NoPassword: %t): %s", sp.Command, sp.RunAs, sp.NoPassword, sp.Reason)
		builder.addResult(
			"TAL-SUDO-001", "InsecureSudoRule",
			"Insecure or exploitable sudo rule",
			"Sudoers configuration grants unprivileged users execution rights on exploitable commands.",
			risk, "", msg, sp.Remediation, sp.ComplianceTag, "",
			[]string{"security", "privilege-escalation", "sudo"},
		)
	}
	for _, st := range report.SudoTokens {
		if !st.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Active sudo ticket or writable timestamp vector: %s (%s)", st.Vector, st.Reason)
		builder.addResult(
			"TAL-SUDO-002", "SudoTokenReuse",
			"Active sudo ticket reuse or writable ticket directory",
			"Unexpired sudo credential allows passwordless elevation or terminal session injection.",
			st.RiskLevel, st.Path, msg, st.Remediation, st.ComplianceTag, st.ExploitHint,
			[]string{"security", "privilege-escalation", "sudo"},
		)
	}

	// 4. POSIX File Capabilities
	for _, cap := range report.Capabilities {
		if !cap.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Dangerous Linux file capability '%s' on %s", cap.Capabilities, cap.Path)
		builder.addResult(
			"TAL-CAP-001", "DangerousFileCapability",
			"Dangerous Linux capability granted to binary",
			"Binary possesses elevated POSIX capabilities such as CAP_SETUID, CAP_DAC_OVERRIDE, or CAP_SYS_ADMIN.",
			"CRITICAL", cap.Path, msg, cap.Remediation, cap.ComplianceTag, cap.ExploitHint,
			[]string{"security", "privilege-escalation", "capabilities"},
		)
	}

	// 5. Writable System Files
	for _, w := range report.Writeable {
		if !w.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Writable system file '%s' (%s): %s", w.Path, w.Type, w.Reason)
		builder.addResult(
			"TAL-WRIT-001", "WritableSystemFile",
			"Critical system file or script is user-writable",
			"A privileged script, generator, or configuration file can be modified by unprivileged users.",
			w.RiskLevel, w.Path, msg, w.Remediation, w.ComplianceTag, "",
			[]string{"security", "privilege-escalation", "writable-file"},
		)
	}

	// 6. Cron Jobs & Drop-in Directories
	for _, c := range report.CronJobs {
		if !c.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Vulnerable cron entry '%s' in %s: %s", c.Command, c.CronFile, c.Reason)
		builder.addResult(
			"TAL-CRON-001", "VulnerableCronJob",
			"Vulnerable or user-writable cron job discovered",
			"Cron job executes unquoted binaries, writable scripts, or insecure relative paths as root.",
			"CRITICAL", c.CronFile, msg, c.Remediation, c.ComplianceTag, "",
			[]string{"security", "privilege-escalation", "cron"},
		)
	}
	for _, cd := range report.CronDirResults {
		if !cd.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Writable cron directory '%s': %s", cd.Path, cd.Reason)
		builder.addResult(
			"TAL-CRON-002", "WritableCronDirectory",
			"Cron drop-in directory is user-writable",
			"Unprivileged users can inject new scheduled jobs into /etc/cron.* to execute code as root.",
			cd.RiskLevel, cd.Path, msg, cd.Remediation, cd.ComplianceTag, cd.ExploitHint,
			[]string{"security", "privilege-escalation", "cron"},
		)
	}

	// 7. Wildcards in Shell Scripts
	for _, w := range report.Wildcards {
		if !w.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Wildcard injection vulnerability in '%s' via '%s' in directory '%s': %s", w.Command, w.VulnerableCmd, w.WorkingDir, w.Reason)
		builder.addResult(
			"TAL-WILD-001", "WildcardInjection",
			"Shell script wildcard expansion parameter injection",
			"Root script or cron job executes vulnerable command with wildcard * inside user-writable working directory.",
			w.RiskLevel, w.SourceFile, msg, w.Remediation, w.ComplianceTag, w.ExploitHint,
			[]string{"security", "privilege-escalation", "wildcard"},
		)
	}

	// 8. Python Library & Search Path Hijacking
	for _, p := range report.PythonHijack {
		if !p.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Python search path hijacking on '%s' (type: %s): %s", p.Path, p.Type, p.Reason)
		builder.addResult(
			"TAL-PYTH-001", "PythonLibraryHijack",
			"Python sys.path or standard library directory writable",
			"Root-owned Python script or global site-packages directory allows library injection.",
			p.RiskLevel, p.Path, msg, p.Remediation, p.ComplianceTag, p.ExploitHint,
			[]string{"security", "privilege-escalation", "python"},
		)
	}

	// 9. NFS Exports (no_root_squash)
	for _, n := range report.NFSExports {
		if !n.HasNoRootSquash {
			continue
		}
		msg := fmt.Sprintf("NFS export '%s' configured with no_root_squash: %s", n.Path, n.RiskSummary)
		builder.addResult(
			"TAL-NFS-001", "NFSNoRootSquash",
			"NFS export allows client root privilege preservation (no_root_squash)",
			"NFS share allows remote clients to upload and execute SUID root binaries.",
			"CRITICAL", "/etc/exports", msg, n.Remediation, n.ComplianceTag, "",
			[]string{"security", "privilege-escalation", "nfs"},
		)
	}

	// 10. Container Breakouts
	for _, ce := range report.ContainerEscape {
		if !ce.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Container breakout vector '%s': %s", ce.Vector, ce.Reason)
		builder.addResult(
			"TAL-CONT-001", "ContainerEscapeVector",
			"Exposed Docker socket or privileged container escape vector",
			"Container possesses mounted docker.sock, dangerous capabilities, or host IPC namespaces.",
			"HIGH", "", msg, ce.Remediation, ce.ComplianceTag, "",
			[]string{"security", "container", "docker"},
		)
	}

	// 11. Systemd EnvironmentFile
	for _, ef := range report.EnvFileResults {
		if !ef.IsWritable {
			continue
		}
		msg := fmt.Sprintf("Writable Systemd EnvironmentFile '%s' for service '%s' (injection: %s): %s", ef.EnvFilePath, ef.ServiceName, ef.InjectionType, ef.Reason)
		builder.addResult(
			"TAL-ENVF-001", "WritableEnvironmentFile",
			"Systemd EnvironmentFile is user-writable",
			"Modifying this environment file injects malicious LD_PRELOAD or PATH variables on service restart.",
			ef.RiskLevel, ef.EnvFilePath, msg, "", "CIS-Linux-5.1.8", "",
			[]string{"security", "privilege-escalation", "systemd"},
		)
	}

	// 12. Logrotate Configurations
	for _, lr := range report.Logrotate {
		if !lr.IsWritable && len(lr.PostrotatePaths) == 0 {
			continue
		}
		msg := fmt.Sprintf("Writable Logrotate configuration '%s': %s", lr.ConfigPath, lr.Reason)
		builder.addResult(
			"TAL-LOGR-001", "WritableLogrotateConfig",
			"Logrotate configuration file is user-writable",
			"Modifying this file allows arbitrary command execution via postrotate script directives.",
			lr.RiskLevel, lr.ConfigPath, msg, lr.Remediation, lr.ComplianceTag, "",
			[]string{"security", "privilege-escalation", "logrotate"},
		)
	}

	// 13. Process Environment Secrets
	for _, pe := range report.ProcEnvResults {
		if !pe.IsDangerous {
			continue
		}
		msg := fmt.Sprintf("Exposed secret in PID %d (%s) environment variable '%s': %s", pe.PID, pe.ProcessName, pe.Key, pe.Reason)
		builder.addResult(
			"TAL-PROC-001", "ProcessEnvironmentSecret",
			"Sensitive credential exposed in /proc/[pid]/environ",
			"Process environment contains accessible passwords, API tokens, or secrets.",
			pe.RiskLevel, fmt.Sprintf("/proc/%d/environ", pe.PID), msg, pe.Remediation, pe.ComplianceTag, pe.ExploitHint,
			[]string{"security", "credentials", "process"},
		)
	}

	// Build Invocations with Enterprise Summary Metrics
	invocations := []SARIFInvocation{
		{
			ExecutionSuccessful: true,
			StartTimeUTC:        report.ScanTime,
			Properties: map[string]interface{}{
				"targetUser":       report.TargetUser,
				"targetScanPath":   report.TargetScanPath,
				"auditMode":        report.AuditMode,
				"totalFindings":    len(builder.results),
				"criticalFindings": builder.criticals,
				"highFindings":     builder.highs,
				"mediumFindings":   builder.mediums,
				"lowFindings":      builder.lows,
			},
		},
	}

	log := SARIFLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "Talaria",
						Version:        "2.0.0",
						InformationURI: "https://github.com/cetinkayaismail/talaria",
						Rules:          builder.rules,
					},
				},
				Invocations: invocations,
				Results:     builder.results,
			},
		},
	}

	return json.MarshalIndent(log, "", "  ")
}
