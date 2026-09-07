package scanners

import (
	"testing"
)

func TestScanInitScripts(t *testing.T) {
	InitUserContext()
	results, err := ScanInitScripts()
	if err != nil {
		t.Fatalf("ScanInitScripts returned unexpected error: %v", err)
	}
	// On most systems results could be empty or non-empty, but must not crash
	for _, r := range results {
		if r.Path == "" {
			t.Errorf("Expected non-empty Path in InitScript finding")
		}
		if r.RiskLevel != "CRITICAL" {
			t.Errorf("Expected CRITICAL risk level for writable init script, got %s", r.RiskLevel)
		}
	}
}
