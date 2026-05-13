package scanners

import (
	"testing"
)

func TestCompareDistroVersions(t *testing.T) {
	tests := []struct {
		current  string
		fixed    string
		expected int // 1: current >= fixed, -1: current < fixed, 0: identical
	}{
		{"5.4.0-150", "5.4.0-101", 1},
		{"5.4.0-101", "5.4.0-150", -1},
		{"5.4.0-101", "5.4.0-101", 0},
		{"5.4.0", "5.4.0-101", 0}, // Base matches, but current has no patch info -> ambiguous, but we treat as base match
		{"5.5.0-101", "5.4.0-150", 1},
		{"4.15.0-140", "4.15.0-140", 0},
		{"4.15.0-141", "4.15.0-140", 1},
	}

	for _, tt := range tests {
		res := compareDistroVersions(tt.current, tt.fixed)
		if res != tt.expected {
			t.Errorf("compareDistroVersions(%s, %s) = %d; want %d", tt.current, tt.fixed, res, tt.expected)
		}
	}
}

func TestCheckKernelRange(t *testing.T) {
	// Mock distro info
	ubuntu := DistroInfo{ID: "ubuntu", VersionID: "20.04"}

	// Mock vulnerability (CVE-2023-32629 - fixed in 5.4.0-153)
	vuln := KernelVulnerability{
		CVE:        "CVE-2023-32629",
		MinVersion: [3]int{5, 4, 0},
		MaxVersion: [3]int{5, 4, 253},
		FixedIn:    map[string]string{"ubuntu": "5.4.0-153"},
	}

	// Case 1: Vulnerable (lower patch number)
	res1 := checkKernelRangeWithVuln([3]int{5, 4, 0}, "5.4.0-120", ubuntu, vuln)
	if len(res1) == 0 || res1[0].PatchStatus != "vulnerable" {
		t.Errorf("Expected vulnerable, got %+v", res1)
	}

	// Case 2: Likely patched (higher patch number)
	res2 := checkKernelRangeWithVuln([3]int{5, 4, 0}, "5.4.0-155", ubuntu, vuln)
	if len(res2) == 0 || res2[0].PatchStatus != "likely_patched" {
		t.Errorf("Expected likely_patched, got %+v", res2)
	}

	// Case 3: Copy Fail (CVE-2026-31431) - Vulnerable
	copyFail := KernelVulnerability{
		CVE:        "CVE-2026-31431",
		MinVersion: [3]int{4, 10, 0},
		MaxVersion: [3]int{6, 19, 11},
	}
	res3 := checkKernelRangeWithVuln([3]int{6, 1, 0}, "6.1.0", ubuntu, copyFail)
	if len(res3) == 0 || res3[0].PatchStatus != "vulnerable" {
		t.Errorf("Expected vulnerable for Copy Fail, got %+v", res3)
	}
}

// Helper for testing
func checkKernelRangeWithVuln(parsed [3]int, rawVer string, distro DistroInfo, v KernelVulnerability) []KernelVulnerability {
	var found []KernelVulnerability
	if versionInRange(parsed, v.MinVersion, v.MaxVersion) {
		v.PatchStatus = "vulnerable"
		if fixed, ok := v.FixedIn[distro.ID]; ok {
			if compareDistroVersions(rawVer, fixed) >= 0 {
				v.PatchStatus = "likely_patched"
			}
		}
		found = append(found, v)
	}
	return found
}
