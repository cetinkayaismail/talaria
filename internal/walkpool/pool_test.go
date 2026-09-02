package walkpool

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWalkTraversal(t *testing.T) {
	tempDir := t.TempDir()

	// Create test directory tree:
	// tempDir/
	//   file1.txt
	//   sub1/
	//     file2.txt
	//   sub2/
	//     skip_me/
	//       file3.txt
	//     file4.txt

	if err := os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	sub1 := filepath.Join(tempDir, "sub1")
	if err := os.Mkdir(sub1, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub1, "file2.txt"), []byte("2"), 0600); err != nil {
		t.Fatal(err)
	}

	sub2 := filepath.Join(tempDir, "sub2")
	if err := os.Mkdir(sub2, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub2, "file4.txt"), []byte("4"), 0600); err != nil {
		t.Fatal(err)
	}

	skipDir := filepath.Join(sub2, "skip_me")
	if err := os.Mkdir(skipDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipDir, "file3.txt"), []byte("3"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	skipFn := func(p string) bool {
		return filepath.Base(p) == "skip_me"
	}

	ch := Walk(ctx, tempDir, 2, skipFn)

	foundFiles := make(map[string]bool)
	for entry := range ch {
		foundFiles[entry.Entry.Name()] = true
	}

	if !foundFiles["file1.txt"] {
		t.Error("file1.txt not found")
	}
	if !foundFiles["file2.txt"] {
		t.Error("file2.txt not found")
	}
	if !foundFiles["file4.txt"] {
		t.Error("file4.txt not found")
	}
	if foundFiles["file3.txt"] {
		t.Error("file3.txt was found but should have been skipped by skipDir")
	}
}

func TestWalkContextCancellation(t *testing.T) {
	tempDir := t.TempDir()

	for i := 0; i < 20; i++ {
		p := filepath.Join(tempDir, filepath.Join("dir", "subdir"))
		_ = os.MkdirAll(p, 0750)
		_ = os.WriteFile(filepath.Join(p, "f.txt"), []byte("a"), 0600)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
	defer cancel()

	ch := Walk(ctx, tempDir, 4, nil)
	for range ch {
		// drain
	}
	// Channel should close cleanly without deadlock or hanging
}

func TestWalkNonExistentRoot(t *testing.T) {
	ctx := context.Background()
	ch := Walk(ctx, "/non/existent/path/talaria_test", 2, nil)

	count := 0
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("Expected 0 entries for non-existent root, got %d", count)
	}
}
