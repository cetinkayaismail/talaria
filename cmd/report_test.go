package cmd

import (
	"talaria/models"
	"talaria/scanners"
	"testing"
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
