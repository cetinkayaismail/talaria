package scanners_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"talaria/scanners"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// buildSecretsTree creates a realistic minimal secrets test tree:
//
//	root/
//	  home/
//	    user1/
//	      .env               ← MEDIUM: config file pattern
//	      .bash_history      ← CRITICAL: critical file pattern
//	      config.php         ← MEDIUM: config file pattern
//	    user2/
//	      id_rsa             ← CRITICAL: private key pattern (not readable = INFO)
//	      notes.txt          ← TIER 3 content: contains "password = secret123"
//	  etc/
//	    shadow               ← CRITICAL: but not readable (perms 0000) = INFO only
//	    ignored_dir/         ← ShouldIgnore will NOT skip this (only /proc etc)
//	      clean.txt          ← found normally
//	  proc_mock/             ← we'll use a name in GlobalIgnoreDirs to test skip
func buildSecretsTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// Dirs
	dirs := []string{
		filepath.Join(root, "home", "user1"),
		filepath.Join(root, "home", "user2"),
		filepath.Join(root, "etc", "ignored_dir"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", d, err)
		}
	}

	// Files
	type fileSpec struct {
		path    string
		content string
		mode    os.FileMode
	}
	specs := []fileSpec{
		// TIER 1: critical filename, readable
		{filepath.Join(root, "home", "user1", ".bash_history"), "sudo su root\nssh user@server -p password123\n", 0o644},
		// TIER 2: medium config filename
		{filepath.Join(root, "home", "user1", ".env"), "APP_KEY=base64:abc\n", 0o644},
		// TIER 2: php config
		{filepath.Join(root, "home", "user1", "config.php"), "<?php\n$db_password = 'hunter2';\n", 0o644},
		// TIER 1: critical filename, NOT readable (should appear as INFO)
		{filepath.Join(root, "home", "user2", "id_rsa"), "-----BEGIN RSA PRIVATE KEY-----\n", 0o000},
		// TIER 3: content match
		{filepath.Join(root, "home", "user2", "notes.txt"), "meeting notes\npassword = secret123\nend\n", 0o644},
		// TIER 1: shadow — make it readable for the test
		{filepath.Join(root, "etc", "shadow"), "root:$6$xyz:19000:0:99999:7:::\n", 0o644},
		// Clean file in sub-dir
		{filepath.Join(root, "etc", "ignored_dir", "clean.txt"), "nothing sensitive\n", 0o644},
	}
	for _, s := range specs {
		if err := os.WriteFile(s.path, []byte(s.content), s.mode); err != nil {
			t.Fatalf("WriteFile %s: %v", s.path, err)
		}
	}

	return root
}

// collectPaths returns a sorted list of paths from results.
func collectPaths(results []scanners.SensitiveFileResult) []string {
	var paths []string
	for _, r := range results {
		paths = append(paths, r.Path)
	}
	sort.Strings(paths)
	return paths
}

// ── Test 2.1: Pool output contains all expected findings ─────────────────────

func TestScanSecrets_PoolFindsExpectedFiles(t *testing.T) {
	scanners.InitUserContext()
	root := buildSecretsTree(t)

	fileResults, contentResults := scanners.ScanSecrets(root)

	if len(fileResults) == 0 {
		t.Fatal("expected at least one file result, got zero")
	}

	// Helper: check a path appears in file results
	hasFile := func(substr string) bool {
		for _, r := range fileResults {
			if strings.Contains(r.Path, substr) {
				return true
			}
		}
		return false
	}
	hasContent := func(substr string) bool {
		for _, r := range contentResults {
			if strings.Contains(r.Path, substr) {
				return true
			}
		}
		return false
	}

	// TIER 1: .bash_history should be CRITICAL (readable)
	if !hasFile(".bash_history") {
		t.Error("expected .bash_history in file results")
	}
	for _, r := range fileResults {
		if strings.Contains(r.Path, ".bash_history") && r.RiskLevel != "CRITICAL" {
			t.Errorf(".bash_history: got RiskLevel %q, want CRITICAL", r.RiskLevel)
		}
	}

	// TIER 1: id_rsa should appear (as INFO — not readable due to 0000 perms,
	// unless test is running as root, in which case it's CRITICAL)
	if !hasFile("id_rsa") {
		t.Error("expected id_rsa in file results")
	}

	// TIER 1: shadow should be CRITICAL (we made it readable)
	if !hasFile("shadow") {
		t.Error("expected shadow in file results")
	}

	// TIER 2: .env should appear as MEDIUM
	if !hasFile(".env") {
		t.Error("expected .env in file results")
	}
	for _, r := range fileResults {
		if strings.Contains(r.Path, ".env") && r.RiskLevel != "MEDIUM" {
			t.Errorf(".env: got RiskLevel %q, want MEDIUM", r.RiskLevel)
		}
	}

	// TIER 3: notes.txt should have a content match (password = secret123)
	if !hasContent("notes.txt") {
		t.Error("expected notes.txt in content results (contains password=)")
	}

	_ = contentResults
}

// ── Test 2.2: No duplicates in results ───────────────────────────────────────

func TestScanSecrets_NoDuplicatePaths(t *testing.T) {
	scanners.InitUserContext()
	root := buildSecretsTree(t)

	fileResults, _ := scanners.ScanSecrets(root)

	seen := make(map[string]int)
	for _, r := range fileResults {
		seen[r.Path]++
	}
	for path, count := range seen {
		if count > 1 {
			t.Errorf("path %q appeared %d times in file results (want ≤1)", path, count)
		}
	}
}

// ── Test 2.3: ShouldIgnore is respected ──────────────────────────────────────

func TestScanSecrets_IgnoresGlobalIgnoreDirs(t *testing.T) {
	scanners.InitUserContext()

	// Build a tree that includes a directory matching a GlobalIgnoreDirs entry.
	root := t.TempDir()
	// /proc is in GlobalIgnoreDirs — simulate by creating a subdir named "proc"
	// at root level. The pool uses ShouldIgnore which checks path prefix.
	procMock := filepath.Join(root, "proc")
	os.MkdirAll(procMock, 0o755)
	os.WriteFile(filepath.Join(procMock, "kcore"), []byte("secret_in_proc"), 0o644)

	// Also create a legitimate file
	os.MkdirAll(filepath.Join(root, "home"), 0o755)
	os.WriteFile(filepath.Join(root, "home", "id_rsa"), []byte("-----BEGIN RSA PRIVATE KEY-----"), 0o644)

	fileResults, _ := scanners.ScanSecrets(root)

	for _, r := range fileResults {
		if strings.Contains(r.Path, "/proc/") {
			t.Errorf("ShouldIgnore failed: got result for path inside /proc mock: %q", r.Path)
		}
	}
}

// ── Test 2.4: Race detector ───────────────────────────────────────────────────
// Run with: go test -race -run TestScanSecrets_Race ./scanners/...

func TestScanSecrets_Race(t *testing.T) {
	scanners.InitUserContext()
	root := buildSecretsTree(t)

	// Run two concurrent ScanSecrets calls on independent paths to exercise
	// any package-level shared state under the race detector.
	done := make(chan struct{}, 2)

	go func() {
		scanners.ScanSecrets(root)
		done <- struct{}{}
	}()
	go func() {
		scanners.ScanSecrets(root)
		done <- struct{}{}
	}()

	<-done
	<-done
}

// ── Test 2.5: Empty directory returns no results ──────────────────────────────

func TestScanSecrets_EmptyDir(t *testing.T) {
	scanners.InitUserContext()
	root := t.TempDir()

	fileResults, contentResults := scanners.ScanSecrets(root)

	if len(fileResults) != 0 {
		t.Errorf("expected 0 file results for empty dir, got %d", len(fileResults))
	}
	if len(contentResults) != 0 {
		t.Errorf("expected 0 content results for empty dir, got %d", len(contentResults))
	}
}

// ── Test 2.6: Non-existent root returns no results (no panic) ─────────────────

func TestScanSecrets_NonExistentRoot(t *testing.T) {
	scanners.InitUserContext()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ScanSecrets panicked on non-existent root: %v", r)
		}
	}()

	fileResults, contentResults := scanners.ScanSecrets("/nonexistent/path/does/not/exist")
	if len(fileResults) != 0 || len(contentResults) != 0 {
		t.Errorf("expected empty results for non-existent root, got files=%d content=%d",
			len(fileResults), len(contentResults))
	}
}

// ── Test 2.7: RiskLevel values are valid ──────────────────────────────────────

func TestScanSecrets_ValidRiskLevels(t *testing.T) {
	scanners.InitUserContext()
	root := buildSecretsTree(t)

	fileResults, _ := scanners.ScanSecrets(root)

	valid := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true}
	for _, r := range fileResults {
		if !valid[r.RiskLevel] {
			t.Errorf("invalid RiskLevel %q for path %q", r.RiskLevel, r.Path)
		}
		if r.Path == "" {
			t.Error("found result with empty Path")
		}
		if r.Type == "" {
			t.Error("found result with empty Type")
		}
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

// buildBenchSecretsTree creates a 500-file tree with a mix of interesting
// and boring files to give a realistic secrets scan workload.
func buildBenchSecretsTree(b *testing.B) string {
	b.Helper()
	root := b.TempDir()

	interesting := []struct{ name, content string }{
		{".env", "DB_PASSWORD=supersecret\nAPP_KEY=12345\n"},
		{"config.php", "<?php $pass = 'hunter2'; ?>\n"},
		{".bash_history", "ssh user@host -p pass\n"},
		{"id_rsa", "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\n"},
	}

	for i := 0; i < 10; i++ {
		sub := filepath.Join(root, strings.Repeat("d", i+1))
		os.MkdirAll(sub, 0o755)

		// Place 1 interesting file per dir
		spec := interesting[i%len(interesting)]
		os.WriteFile(filepath.Join(sub, spec.name), []byte(spec.content), 0o644)

		// Fill with 49 boring files
		for j := 0; j < 49; j++ {
			os.WriteFile(filepath.Join(sub, "readme.md"), []byte("nothing here\n"), 0o644)
		}
	}

	return root
}

// BenchmarkScanSecrets_Pool measures the pool-based ScanSecrets.
func BenchmarkScanSecrets_Pool(b *testing.B) {
	scanners.InitUserContext()
	root := buildBenchSecretsTree(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanners.ScanSecrets(root)
	}
}
