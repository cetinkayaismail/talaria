package core

import (
	"encoding/json"
	"testing"

	"talaria/models"
	"talaria/scanners"
)

func TestGenerateSARIFReport(t *testing.T) {
	report := &models.ScanReport{
		ScanTime:       "2026-09-07T10:00:00Z",
		TargetUser:     "testuser",
		TargetScanPath: "/",
		AuditMode:      true,
		Secrets: []scanners.SensitiveFileResult{
			{
				Path:          "/home/testuser/.ssh/id_rsa",
				Type:          "RSA Private Key",
				RiskLevel:     "CRITICAL",
				Remediation:   "chmod 0600 /home/testuser/.ssh/id_rsa",
				ComplianceTag: "CIS-Linux-5.2.4",
			},
		},
		SUID: []scanners.SUIDResult{
			{
				Path:          "/usr/bin/find",
				IsDangerous:   true,
				Reason:        "find has GTFOBins exec exploit",
				ExploitHint:   "find . -exec /bin/sh -p \\; -quit",
				Remediation:   "chmod u-s /usr/bin/find",
				ComplianceTag: "CIS-Linux-5.1.1",
			},
		},
		Wildcards: []scanners.WildcardResult{
			{
				SourceFile:    "/etc/crontab",
				Command:       "tar -czf backup.tar.gz *",
				VulnerableCmd: "tar",
				WorkingDir:    "/tmp",
				IsDangerous:   true,
				RiskLevel:     "CRITICAL",
				Reason:        "tar wildcard parameter injection in /tmp",
				ExploitHint:   "touch /tmp/--checkpoint=1 && touch /tmp/--checkpoint-action=exec=sh",
				Remediation:   "Replace * with explicit file list or specify directory path",
			},
		},
	}

	data, err := GenerateSARIFReport(report)
	if err != nil {
		t.Fatalf("GenerateSARIFReport failed: %v", err)
	}

	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("Failed to parse generated SARIF as valid JSON: %v", err)
	}

	// 1. Verify schema and version
	if sarifLog.Version != "2.1.0" {
		t.Errorf("Expected SARIF version '2.1.0', got %q", sarifLog.Version)
	}
	if sarifLog.Schema == "" {
		t.Errorf("Expected non-empty $schema")
	}

	// 2. Verify Runs and Tool Driver
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(sarifLog.Runs))
	}
	run := sarifLog.Runs[0]
	if run.Tool.Driver.Name != "Talaria" {
		t.Errorf("Expected driver name 'Talaria', got %q", run.Tool.Driver.Name)
	}

	// 3. Verify Rules
	if len(run.Tool.Driver.Rules) < 3 {
		t.Errorf("Expected at least 3 rules, got %d", len(run.Tool.Driver.Rules))
	}

	// 4. Verify Results count
	if len(run.Results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(run.Results))
	}

	// 5. Verify Invocations metrics
	if len(run.Invocations) != 1 {
		t.Fatalf("Expected 1 invocation, got %d", len(run.Invocations))
	}
	inv := run.Invocations[0]
	if !inv.ExecutionSuccessful {
		t.Errorf("Expected ExecutionSuccessful to be true")
	}
	totalFindings, ok := inv.Properties["totalFindings"].(float64)
	if !ok || int(totalFindings) != 3 {
		t.Errorf("Expected totalFindings metric 3, got %v", inv.Properties["totalFindings"])
	}

	// 6. Verify Result location, fixes, and ruleIndex mapping
	foundSUID := false
	for _, res := range run.Results {
		if res.RuleID == "TAL-SUID-001" {
			foundSUID = true
			if res.Level != "error" {
				t.Errorf("Expected level 'error' for critical SUID finding, got %q", res.Level)
			}
			if len(res.Locations) == 0 {
				t.Errorf("Expected non-empty locations for SUID finding")
			} else {
				loc := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
				if loc != "file:///usr/bin/find" {
					t.Errorf("Expected URI 'file:///usr/bin/find', got %q", loc)
				}
			}
			if len(res.Fixes) == 0 {
				t.Errorf("Expected non-empty fixes for SUID finding with remediation")
			}
		}
	}
	if !foundSUID {
		t.Errorf("Expected to find TAL-SUID-001 result")
	}
}
