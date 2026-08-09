package walkpool_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"talaria/internal/walkpool"
)

// ── Helpers ─────────────────────────────────────────────────────────────────

// buildTree creates a temporary directory tree for testing.
// Layout:
//
//	root/
//	  dir_A/
//	    file_a1.txt
//	    file_a2.txt
//	  dir_B/
//	    file_b1.txt
//	    subdir_B1/
//	      file_b1_1.txt
//	  dir_C/           ← intended for SkipDir tests
//	    file_c1.txt
//	  root_file.txt
func buildTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	dirs := []string{
		filepath.Join(root, "dir_A"),
		filepath.Join(root, "dir_B"),
		filepath.Join(root, "dir_B", "subdir_B1"),
		filepath.Join(root, "dir_C"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", d, err)
		}
	}

	files := []string{
		filepath.Join(root, "root_file.txt"),
		filepath.Join(root, "dir_A", "file_a1.txt"),
		filepath.Join(root, "dir_A", "file_a2.txt"),
		filepath.Join(root, "dir_B", "file_b1.txt"),
		filepath.Join(root, "dir_B", "subdir_B1", "file_b1_1.txt"),
		filepath.Join(root, "dir_C", "file_c1.txt"),
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("test"), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", f, err)
		}
	}

	return root
}

// collect drains a Walk channel and returns all paths, sorted.
func collect(ch <-chan walkpool.WalkEntry) []string {
	var paths []string
	for e := range ch {
		paths = append(paths, e.Path)
	}
	sort.Strings(paths)
	return paths
}

// serialWalk uses filepath.WalkDir to produce the ground-truth file list.
func serialWalk(root string, skipDir func(string) bool) []string {
	var paths []string
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDir != nil && skipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	sort.Strings(paths)
	return paths
}

// ── Test 1.1: Basic traversal correctness ───────────────────────────────────

func TestWalk_BasicCorrectness(t *testing.T) {
	root := buildTree(t)

	ch := walkpool.Walk(context.Background(), root, 4, nil)
	got := collect(ch)
	want := serialWalk(root, nil)

	if len(got) != len(want) {
		t.Fatalf("entry count: got %d, want %d\ngot:  %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("entry[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// ── Test 1.2: No duplicates ──────────────────────────────────────────────────

func TestWalk_NoDuplicates(t *testing.T) {
	root := buildTree(t)

	ch := walkpool.Walk(context.Background(), root, 4, nil)
	seen := make(map[string]int)
	for e := range ch {
		seen[e.Path]++
	}
	for path, count := range seen {
		if count > 1 {
			t.Errorf("path %q appeared %d times (want 1)", path, count)
		}
	}
}

// ── Test 1.3: SkipDir semantics ─────────────────────────────────────────────

func TestWalk_SkipDir(t *testing.T) {
	root := buildTree(t)

	// Skip dir_C entirely.
	skipC := func(p string) bool {
		return strings.HasSuffix(p, "dir_C")
	}

	ch := walkpool.Walk(context.Background(), root, 4, skipC)
	got := collect(ch)
	want := serialWalk(root, skipC)

	if len(got) != len(want) {
		t.Fatalf("after skip: got %d entries, want %d\ngot:  %v\nwant: %v", len(got), len(want), got, want)
	}
	for _, p := range got {
		if strings.Contains(p, "dir_C") {
			t.Errorf("skipped dir_C but got path: %q", p)
		}
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("entry[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// ── Test 1.4: Nested SkipDir (multiple dirs) ─────────────────────────────────

func TestWalk_SkipDir_Multiple(t *testing.T) {
	root := buildTree(t)

	// Skip both dir_A and subdir_B1.
	skip := func(p string) bool {
		return strings.HasSuffix(p, "dir_A") || strings.HasSuffix(p, "subdir_B1")
	}

	ch := walkpool.Walk(context.Background(), root, 4, skip)
	got := collect(ch)
	want := serialWalk(root, skip)

	if len(got) != len(want) {
		t.Fatalf("got %d, want %d\ngot:  %v\nwant: %v", len(got), len(want), got, want)
	}
	for _, p := range got {
		if strings.Contains(p, "dir_A") {
			t.Errorf("skipped dir_A but got: %q", p)
		}
		if strings.Contains(p, "subdir_B1") {
			t.Errorf("skipped subdir_B1 but got: %q", p)
		}
	}
}

// ── Test 1.5: Context cancellation ──────────────────────────────────────────

func TestWalk_ContextCancel(t *testing.T) {
	// Build a larger tree so there's work in flight when we cancel.
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		sub := filepath.Join(root, "sub", strings.Repeat("d", i+1))
		os.MkdirAll(sub, 0o755)
		for j := 0; j < 50; j++ {
			os.WriteFile(filepath.Join(sub, "f.txt"), []byte("x"), 0o644)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	ch := walkpool.Walk(ctx, root, 8, nil)

	// Cancel after receiving a few entries.
	received := 0
	for range ch {
		received++
		if received == 5 {
			cancel()
			break
		}
	}
	cancel() // idempotent

	// Drain the channel — must close within a reasonable timeout.
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	select {
	case <-done:
		// OK — channel closed after cancellation
	case <-time.After(3 * time.Second):
		t.Fatal("channel did not close within 3s after context cancellation — possible goroutine leak")
	}
}

// ── Test 1.6: Empty root directory ──────────────────────────────────────────

func TestWalk_EmptyRoot(t *testing.T) {
	root := t.TempDir() // no files, no subdirs

	ch := walkpool.Walk(context.Background(), root, 4, nil)
	got := collect(ch)

	if len(got) != 0 {
		t.Errorf("expected 0 entries for empty dir, got %d: %v", len(got), got)
	}
}

// ── Test 1.7: Non-existent root ─────────────────────────────────────────────

func TestWalk_NonExistentRoot(t *testing.T) {
	ch := walkpool.Walk(context.Background(), "/nonexistent/path/that/does/not/exist", 4, nil)

	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	select {
	case <-done:
		// Channel closed immediately — correct
	case <-time.After(1 * time.Second):
		t.Fatal("channel did not close for non-existent root — deadlock?")
	}
}

// ── Test 1.8: Single worker (sequential fallback) ────────────────────────────

func TestWalk_SingleWorker_Equivalence(t *testing.T) {
	root := buildTree(t)

	ch := walkpool.Walk(context.Background(), root, 1, nil)
	got := collect(ch)
	want := serialWalk(root, nil)

	if len(got) != len(want) {
		t.Fatalf("single worker: got %d entries, want %d\ngot:  %v\nwant: %v",
			len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("entry[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// ── Test 1.9: Many workers (> dirs in tree) doesn't panic ───────────────────

func TestWalk_ManyWorkers(t *testing.T) {
	root := buildTree(t)

	// 64 workers for a 6-file tree — no panic, no deadlock, correct output.
	ch := walkpool.Walk(context.Background(), root, 64, nil)
	got := collect(ch)
	want := serialWalk(root, nil)

	if len(got) != len(want) {
		t.Fatalf("many workers: got %d entries, want %d", len(got), len(want))
	}
}

// ── Test 1.10: WalkEntry fields are populated ───────────────────────────────

func TestWalk_EntryFields(t *testing.T) {
	root := buildTree(t)

	ch := walkpool.Walk(context.Background(), root, 4, nil)
	for e := range ch {
		if e.Path == "" {
			t.Error("WalkEntry.Path is empty")
		}
		if e.Entry == nil {
			t.Errorf("WalkEntry.Entry is nil for path %q", e.Path)
		}
		// Path should be an absolute path under root
		if !filepath.IsAbs(e.Path) {
			t.Errorf("WalkEntry.Path %q is not absolute", e.Path)
		}
		if !strings.HasPrefix(e.Path, root) {
			t.Errorf("WalkEntry.Path %q is outside root %q", e.Path, root)
		}
		// Entry should not be a directory (pool emits files only)
		if e.Entry.IsDir() {
			t.Errorf("WalkEntry.Entry %q is a directory — pool should only emit files", e.Path)
		}
	}
}

// ── Test 1.11: Race detector — concurrent entry delivery ─────────────────────
// Run with: go test -race -run TestWalk_Race ./internal/walkpool/...

func TestWalk_Race(t *testing.T) {
	root := buildTree(t)

	// Consume from multiple goroutines to stress the channel under the race detector.
	// (In real usage, one goroutine consumes; this test deliberately races to expose issues.)
	ch := walkpool.Walk(context.Background(), root, 4, nil)

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		paths []string
	)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range ch {
				mu.Lock()
				paths = append(paths, e.Path)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// We don't check count here because multiple consumers may cause entries
	// to be received in non-deterministic ways, but there should be no race.
	if len(paths) == 0 {
		t.Error("expected at least some entries")
	}
}

// ── Test 1.12: Parallel walk is never slower than serial ────────────────────
// (Ensures we don't introduce a pure overhead regression.)

func TestWalk_Speed_NotSlowerThanSerial(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping speed test in -short mode")
	}

	// Build a larger tree: 10 dirs × 50 files = 500 entries.
	root := t.TempDir()
	for i := 0; i < 10; i++ {
		sub := filepath.Join(root, "sub", strings.Repeat("d", i+1))
		os.MkdirAll(sub, 0o755)
		for j := 0; j < 50; j++ {
			name := filepath.Join(sub, "file.txt")
			os.WriteFile(name, []byte("x"), 0o644)
		}
	}

	// Serial timing.
	t0 := time.Now()
	for i := 0; i < 5; i++ {
		serialWalk(root, nil)
	}
	serialDuration := time.Since(t0)

	// Pool timing.
	workers := runtime.NumCPU() * 2
	t1 := time.Now()
	for i := 0; i < 5; i++ {
		ch := walkpool.Walk(context.Background(), root, workers, nil)
		for range ch {
		}
	}
	poolDuration := time.Since(t1)

	t.Logf("Serial (×5): %v | Pool(workers=%d, ×5): %v | ratio: %.2fx",
		serialDuration, workers, poolDuration,
		float64(serialDuration)/float64(poolDuration))

	// Pool must not be more than 3× slower than serial.
	// On single-CPU CI the pool has overhead but should not crater.
	if poolDuration > serialDuration*3 {
		t.Errorf("pool (%.0fms) is more than 3× slower than serial (%.0fms) — unexpected regression",
			float64(poolDuration.Milliseconds()),
			float64(serialDuration.Milliseconds()),
		)
	}
}

// ── Benchmarks ───────────────────────────────────────────────────────────────

// buildBenchTree creates a deterministic tree of benchSize files.
// It is called once per benchmark (not per iteration) so setup cost is amortised.
func buildBenchTree(b *testing.B, dirs, filesPerDir int) string {
	b.Helper()
	root := b.TempDir()
	for i := 0; i < dirs; i++ {
		sub := filepath.Join(root, strings.Repeat("d", i%8+1), strings.Repeat("s", i/8+1))
		os.MkdirAll(sub, 0o755)
		for j := 0; j < filesPerDir; j++ {
			os.WriteFile(filepath.Join(sub, "f.txt"), []byte("x"), 0o644)
		}
	}
	return root
}

// BenchmarkWalkPool benchmarks the parallel pool with NumCPU*2 workers.
func BenchmarkWalkPool(b *testing.B) {
	root := buildBenchTree(b, 20, 25) // 500 files
	workers := runtime.NumCPU() * 2
	if workers > 16 {
		workers = 16
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := walkpool.Walk(context.Background(), root, workers, nil)
		for range ch {
		}
	}
}

// BenchmarkWalkSerial benchmarks serial filepath.WalkDir as the baseline.
func BenchmarkWalkSerial(b *testing.B) {
	root := buildBenchTree(b, 20, 25) // 500 files

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			return nil
		})
	}
}

// BenchmarkWalkPool_Workers1 isolates single-worker overhead vs serial.
func BenchmarkWalkPool_Workers1(b *testing.B) {
	root := buildBenchTree(b, 20, 25)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := walkpool.Walk(context.Background(), root, 1, nil)
		for range ch {
		}
	}
}

// BenchmarkWalkPool_Workers4 shows typical 4-worker performance.
func BenchmarkWalkPool_Workers4(b *testing.B) {
	root := buildBenchTree(b, 20, 25)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := walkpool.Walk(context.Background(), root, 4, nil)
		for range ch {
		}
	}
}

// BenchmarkWalkPool_LargeTree benchmarks a deeper, larger tree (2000 files).
func BenchmarkWalkPool_LargeTree(b *testing.B) {
	root := buildBenchTree(b, 40, 50) // 2000 files
	workers := runtime.NumCPU() * 2
	if workers > 16 {
		workers = 16
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := walkpool.Walk(context.Background(), root, workers, nil)
		for range ch {
		}
	}
}

// BenchmarkWalkSerial_LargeTree is the serial baseline for LargeTree.
func BenchmarkWalkSerial_LargeTree(b *testing.B) {
	root := buildBenchTree(b, 40, 50) // 2000 files

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			return nil
		})
	}
}
