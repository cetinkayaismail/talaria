package cmd

import (
	"testing"
)

func TestParseFlagsValid(t *testing.T) {
	cfg, err := ParseFlags([]string{"--scan", "cronjobs,sudo", "--fail-on", "CRITICAL", "--quiet"})
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.ScanModules != "cronjobs,sudo" {
		t.Errorf("Expected ScanModules 'cronjobs,sudo', got %q", cfg.ScanModules)
	}
	if cfg.FailOn != "CRITICAL" {
		t.Errorf("Expected FailOn 'CRITICAL', got %q", cfg.FailOn)
	}
	if !cfg.QuietMode {
		t.Errorf("Expected QuietMode to be true")
	}
}

func TestParseFlagsFailOnCaseInsensitive(t *testing.T) {
	cfg, err := ParseFlags([]string{"--fail-on", "high"})
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if cfg.FailOn != "HIGH" {
		t.Errorf("Expected FailOn normalized to 'HIGH', got %q", cfg.FailOn)
	}
}

func TestParseFlagsInvalidFailOn(t *testing.T) {
	_, err := ParseFlags([]string{"--fail-on", "INVALID"})
	if err == nil {
		t.Fatal("Expected error for invalid --fail-on value, got nil")
	}
}
