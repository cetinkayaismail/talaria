package scanners

import (
	"testing"
)

func TestLookupGTFOBin(t *testing.T) {
	// Known GTFOBins binaries
	known := []string{"bash", "nmap", "vim", "python", "curl"}
	for _, bin := range known {
		entry, found := LookupGTFOBin(bin)
		if !found {
			t.Errorf("Expected %s to be found in GTFOBins catalog", bin)
		}
		if entry.ExploitHint == "" && !entry.SUID && !entry.Sudo && !entry.Shell {
			t.Errorf("Expected non-empty capabilities for %s", bin)
		}
	}

	// Non-existent binary
	_, found := LookupGTFOBin("nonexistent_safe_binary_xyz_123")
	if found {
		t.Errorf("Expected nonexistent binary to return false, but was found")
	}
}

func TestGetExploitHint(t *testing.T) {
	hint := GetExploitHint("/usr/bin/bash", "suid")
	if hint == "" {
		t.Error("Expected non-empty exploit hint for /usr/bin/bash with SUID capability")
	}
}
