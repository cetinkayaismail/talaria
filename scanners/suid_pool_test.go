package scanners_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"talaria/scanners"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// buildSUIDBinTree creates a temp dir tree containing a copy of a real SUID
// binary from /usr/bin so we can test ScanSUID on a controlled path without
// modifying any system files.
//
// If no SUID binary can be found to copy, the tree is empty and tests that
// require SUID findings will be skipped.
func buildSUIDBinTree(t *testing.T) (root string, foundSUID bool) {
	t.Helper()
	root = t.TempDir()

	// Find a real SUID binary in /usr/bin that is NOT in the systemSUIDBinaries
	// skip list. We'll copy it into our temp tree for testing.
	// We don't NEED one for the no-duplicate/ShouldIgnore/race tests.
	candidates := []string{"/usr/bin/find", "/usr/bin/vim.basic", "/usr/bin/python3"}
	for _, c := range candidates {
		info, err := os.Stat(c)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSetuid != 0 {
			// Found a SUID binary — copy into our tree
			data, err := os.ReadFile(c)
			if err != nil {
				continue
			}
			dest := filepath.Join(root, filepath.Base(c))
			if err := os.WriteFile(dest, data, info.Mode()); err != nil {
				continue
			}
			foundSUID = true
			break
		}
	}

	// Always add a few non-SUID regular files for the ShouldIgnore / no-dup tests
	os.WriteFile(filepath.Join(root, "normalfile"), []byte("data"), 0o755)
	os.WriteFile(filepath.Join(root, "script.sh"), []byte("#!/bin/bash\necho hi\n"), 0o755)

	return root, foundSUID
}

// ── Test 3.1: ScanSUID — no duplicates ───────────────────────────────────────

func TestScanSUID_NoDuplicates(t *testing.T) {
	scanners.InitUserContext()

	// Use /usr/bin as the scan root — real system path, realistic workload.
	results, err := scanners.ScanSUID("/usr/bin")
	if err != nil {
		t.Fatalf("ScanSUID returned error: %v", err)
	}

	seen := make(map[string]int)
	for _, r := range results {
		seen[r.Path]++
	}
	for path, count := range seen {
		if count > 1 {
			t.Errorf("path %q appeared %d times in ScanSUID results (want 1)", path, count)
		}
	}
}

// ── Test 3.2: ScanSUID — all entries are files that exist on disk ─────────────

func TestScanSUID_PathsExistOnDisk(t *testing.T) {
	scanners.InitUserContext()

	results, err := scanners.ScanSUID("/usr/bin")
	if err != nil {
		t.Fatalf("ScanSUID returned error: %v", err)
	}

	for _, r := range results {
		if r.Path == "" {
			t.Error("found SUIDResult with empty Path")
			continue
		}
		if _, err := os.Lstat(r.Path); err != nil {
			t.Errorf("SUIDResult path %q does not exist: %v", r.Path, err)
		}
		// Verify path is inside the scanned root
		if !strings.HasPrefix(r.Path, "/usr/bin") {
			t.Errorf("SUIDResult path %q is outside scan root /usr/bin", r.Path)
		}
	}
}

// ── Test 3.3: ScanSUID — ShouldIgnore prevents proc/sys paths ────────────────

func TestScanSUID_IgnoresGlobalIgnoreDirs(t *testing.T) {
	scanners.InitUserContext()

	root := t.TempDir()
	// Create a subdir named "proc" (mirrors GlobalIgnoreDirs entry for /proc)
	procMock := filepath.Join(root, "proc")
	os.MkdirAll(procMock, 0o755)
	// Put a file in it that looks like a SUID binary (we can't actually set SUID
	// without root, so this just confirms the dir is excluded entirely by the pool)
	os.WriteFile(filepath.Join(procMock, "evil"), []byte("ELF"), 0o755)

	// Also put a clean file in root itself
	os.WriteFile(filepath.Join(root, "safe"), []byte("data"), 0o644)

	results, err := scanners.ScanSUID(root)
	if err != nil {
		t.Fatalf("ScanSUID error: %v", err)
	}
	for _, r := range results {
		if strings.Contains(r.Path, "/proc/") {
			t.Errorf("ShouldIgnore failed: got result inside /proc mock: %q", r.Path)
		}
	}
}

// ── Test 3.4: ScanSUID — race detector ───────────────────────────────────────
// Run with: go test -race -run TestScanSUID_Race ./scanners/...

func TestScanSUID_Race(t *testing.T) {
	scanners.InitUserContext()

	done := make(chan struct{}, 2)
	go func() {
		scanners.ScanSUID("/usr/bin")
		done <- struct{}{}
	}()
	go func() {
		scanners.ScanSUID("/usr/bin")
		done <- struct{}{}
	}()
	<-done
	<-done
}

// ── Test 3.5: ScanSUID — empty root returns empty, no panic ──────────────────

func TestScanSUID_EmptyRoot(t *testing.T) {
	scanners.InitUserContext()
	root := t.TempDir()

	results, err := scanners.ScanSUID(root)
	if err != nil {
		t.Fatalf("ScanSUID error on empty dir: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty dir, got %d", len(results))
	}
}

// ── Test 3.6: ScanSUID — non-existent root, no panic ────────────────────────

func TestScanSUID_NonExistentRoot(t *testing.T) {
	scanners.InitUserContext()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ScanSUID panicked on non-existent root: %v", r)
		}
	}()

	results, err := scanners.ScanSUID("/nonexistent/path/xyz")
	if err != nil {
		t.Fatalf("ScanSUID returned unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for non-existent root, got %d", len(results))
	}
}

// ── Test 3.7: ScanSGID — no duplicates ───────────────────────────────────────

func TestScanSGID_NoDuplicates(t *testing.T) {
	scanners.InitUserContext()

	results, err := scanners.ScanSGID("/usr/bin")
	if err != nil {
		t.Fatalf("ScanSGID returned error: %v", err)
	}

	seen := make(map[string]int)
	for _, r := range results {
		seen[r.Path]++
	}
	for path, count := range seen {
		if count > 1 {
			t.Errorf("path %q appeared %d times in ScanSGID results (want 1)", path, count)
		}
	}
}

// ── Test 3.8: ScanSGID — all entries are files that exist ────────────────────

func TestScanSGID_PathsExistOnDisk(t *testing.T) {
	scanners.InitUserContext()

	results, err := scanners.ScanSGID("/usr/bin")
	if err != nil {
		t.Fatalf("ScanSGID returned error: %v", err)
	}
	for _, r := range results {
		if r.Path == "" {
			t.Error("SGIDResult has empty Path")
			continue
		}
		if _, err := os.Lstat(r.Path); err != nil {
			t.Errorf("SGIDResult path %q does not exist: %v", r.Path, err)
		}
	}
}

// ── Test 3.9: ScanSGID — race detector ───────────────────────────────────────

func TestScanSGID_Race(t *testing.T) {
	scanners.InitUserContext()

	done := make(chan struct{}, 2)
	go func() {
		scanners.ScanSGID("/usr/bin")
		done <- struct{}{}
	}()
	go func() {
		scanners.ScanSGID("/usr/bin")
		done <- struct{}{}
	}()
	<-done
	<-done
}

// ── Test 3.10: ScanSGID — empty root, no panic ───────────────────────────────

func TestScanSGID_EmptyRoot(t *testing.T) {
	scanners.InitUserContext()
	root := t.TempDir()

	results, err := scanners.ScanSGID(root)
	if err != nil {
		t.Fatalf("ScanSGID error on empty dir: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty dir, got %d", len(results))
	}
}

// ── Test 3.11: ScanSUID — system binaries are skipped (no noise) ─────────────

func TestScanSUID_SkipsSystemBinaries(t *testing.T) {
	scanners.InitUserContext()

	// These are in the systemSUIDBinaries skip list — they must never appear
	// in ScanSUID results regardless of their SUID bit.
	skipList := []string{"su", "sudo", "passwd", "mount", "umount", "ping", "newgrp"}

	results, err := scanners.ScanSUID("/usr/bin")
	if err != nil {
		t.Fatalf("ScanSUID error: %v", err)
	}
	for _, r := range results {
		base := strings.ToLower(filepath.Base(r.Path))
		for _, skip := range skipList {
			if base == skip {
				t.Errorf("system binary %q should be skipped but appeared in results: %q", skip, r.Path)
			}
		}
	}
}

// ── Test 3.12: Both scanners return correctly typed results ───────────────────

func TestScanSUID_ResultFields(t *testing.T) {
	scanners.InitUserContext()

	results, _ := scanners.ScanSUID("/usr/bin")
	for _, r := range results {
		if r.Path == "" {
			t.Error("SUIDResult.Path is empty")
		}
		// IsDangerous true implies reason is non-empty
		if r.IsDangerous && r.Reason == "" {
			t.Errorf("SUIDResult %q: IsDangerous=true but Reason is empty", r.Path)
		}
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

// BenchmarkScanSUID_Pool measures the pool-based ScanSUID on /usr/bin.
func BenchmarkScanSUID_Pool(b *testing.B) {
	scanners.InitUserContext()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanners.ScanSUID("/usr/bin")
	}
}

// BenchmarkScanSGID_Pool measures the pool-based ScanSGID on /usr/bin.
func BenchmarkScanSGID_Pool(b *testing.B) {
	scanners.InitUserContext()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanners.ScanSGID("/usr/bin")
	}
}
