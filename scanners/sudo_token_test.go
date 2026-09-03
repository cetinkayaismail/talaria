package scanners

import (
	"testing"
)

func TestScanSudoTokensAndTTY(t *testing.T) {
	InitUserContext()

	results, err := ScanSudoTokensAndTTY()
	if err != nil {
		t.Fatalf("ScanSudoTokensAndTTY returned error: %v", err)
	}

	// Should return a valid slice without panics
	for _, r := range results {
		if r.Vector == "" {
			t.Errorf("Expected non-empty Vector name, got empty string")
		}
		if r.RiskLevel == "" {
			t.Errorf("Expected non-empty RiskLevel for vector %s", r.Vector)
		}
		if r.Reason == "" {
			t.Errorf("Expected non-empty Reason for vector %s", r.Vector)
		}
	}
}
