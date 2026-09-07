package cmd

import (
	"encoding/json"
	"os"
	"testing"

	"talaria/models"
	"talaria/scanners"
)

func TestEvaluatePolicy(t *testing.T) {
	reportWithCritical := &models.ScanReport{
		SUID: []scanners.SUIDResult{
			{Path: "/usr/bin/bash", IsDangerous: true},
		},
	}

	reportWithHigh := &models.ScanReport{
		Writeable: []scanners.WriteableResult{
			{Path: "/etc/cron.daily/job", IsDangerous: true, RiskLevel: "HIGH"},
		},
	}

	reportClean := &models.ScanReport{}

	// Test 1: Critical threshold against critical finding -> should fail (violation)
	failed, msg := EvaluatePolicy(reportWithCritical, "CRITICAL")
	if !failed {
		t.Fatalf("Expected policy failure on CRITICAL finding, got passed (%s)", msg)
	}

	// Test 2: Critical threshold against clean report -> should pass
	failed, _ = EvaluatePolicy(reportClean, "CRITICAL")
	if failed {
		t.Fatalf("Expected policy pass on clean report, got failure")
	}

	// Test 3: Critical threshold against HIGH only finding -> should pass
	failed, _ = EvaluatePolicy(reportWithHigh, "CRITICAL")
	if failed {
		t.Fatalf("Expected policy pass for --fail-on=CRITICAL with only HIGH findings")
	}

	// Test 4: High threshold against HIGH finding -> should fail
	failed, _ = EvaluatePolicy(reportWithHigh, "HIGH")
	if !failed {
		t.Fatalf("Expected policy failure for --fail-on=HIGH with HIGH finding")
	}
}

func TestSaveReportSARIF(t *testing.T) {
	report := &models.ScanReport{
		ScanTime:       "2026-09-07T10:00:00Z",
		TargetUser:     "root",
		TargetScanPath: "/",
		AuditMode:      true,
		SUID: []scanners.SUIDResult{
			{Path: "/usr/bin/find", IsDangerous: true, Reason: "GTFOBins"},
		},
	}

	tmpFile := t.TempDir() + "/report.sarif"
	if err := SaveReport(report, tmpFile, "sarif", ""); err != nil {
		t.Fatalf("SaveReport failed with format 'sarif': %v", err)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read generated SARIF file: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(content, &parsed); err != nil {
		t.Fatalf("Generated SARIF file is not valid JSON: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Errorf("Expected version '2.1.0', got %v", parsed["version"])
	}
}

