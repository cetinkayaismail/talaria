package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractFirstImport(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test_job.py")
	content := `#!/usr/bin/env python3
# Some comment
import sys
from requests import get
import yaml

print("running")
`
	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	mod := extractFirstImport(scriptPath)
	if mod != "requests" {
		t.Errorf("Expected first import 'requests', got %q", mod)
	}
}

func TestDiscoverPythonSearchPaths(t *testing.T) {
	paths := discoverPythonSearchPaths()
	if len(paths) == 0 {
		t.Fatal("Expected non-empty search paths list")
	}

	foundDist := false
	for _, p := range paths {
		if filepath.Base(p) == "dist-packages" || filepath.Base(p) == "site-packages" {
			foundDist = true
			break
		}
	}
	if !foundDist {
		t.Error("Expected dist-packages or site-packages in search paths")
	}
}

func TestScanPythonHijackSafeExecution(t *testing.T) {
	// Must execute safely without panicking, hanging, or crashing
	results, err := ScanPythonHijack()
	if err != nil {
		t.Fatalf("ScanPythonHijack returned unexpected error: %v", err)
	}
	t.Logf("ScanPythonHijack returned %d findings", len(results))
}
