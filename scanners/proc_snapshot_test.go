package scanners

import (
	"os"
	"sync"
	"testing"
)

func TestProcSnapshotCapture(t *testing.T) {
	InvalidateProcSnapshot()

	snap, err := GetProcSnapshot()
	if err != nil {
		t.Fatalf("GetProcSnapshot failed: %v", err)
	}
	if snap == nil {
		t.Fatal("Expected non-nil ProcSnapshot")
	}

	if len(snap.Processes) == 0 {
		t.Fatal("Expected snap.Processes to contain at least 1 process")
	}

	currentPID := os.Getpid()
	entry, found := snap.ByPID[currentPID]
	if !found {
		t.Fatalf("Expected current process PID %d to be in snap.ByPID", currentPID)
	}

	if entry.PID != currentPID {
		t.Errorf("Expected entry.PID %d, got %d", currentPID, entry.PID)
	}

	expectedUID := os.Getuid()
	if entry.UID != expectedUID {
		t.Errorf("Expected entry.UID %d, got %d", expectedUID, entry.UID)
	}

	if entry.Comm == "" && entry.Cmdline == "" {
		t.Errorf("Expected non-empty Comm or Cmdline for PID %d", currentPID)
	}
}

func TestProcSnapshotCacheTTL(t *testing.T) {
	InvalidateProcSnapshot()

	snap1, err1 := GetProcSnapshot()
	if err1 != nil {
		t.Fatalf("First GetProcSnapshot failed: %v", err1)
	}

	snap2, err2 := GetProcSnapshot()
	if err2 != nil {
		t.Fatalf("Second GetProcSnapshot failed: %v", err2)
	}

	if snap1 != snap2 {
		t.Errorf("Expected snap1 and snap2 to be identical pointer due to TTL cache, got %p vs %p", snap1, snap2)
	}
}

func TestProcSnapshotInvalidate(t *testing.T) {
	InvalidateProcSnapshot()

	snap1, err := GetProcSnapshot()
	if err != nil {
		t.Fatalf("GetProcSnapshot failed: %v", err)
	}

	InvalidateProcSnapshot()

	snap2, err := GetProcSnapshot()
	if err != nil {
		t.Fatalf("GetProcSnapshot after invalidate failed: %v", err)
	}

	if snap1 == snap2 {
		t.Errorf("Expected fresh snapshot pointer after InvalidateProcSnapshot, but got identical pointer %p", snap1)
	}
}

func TestProcSnapshotConcurrency(t *testing.T) {
	InvalidateProcSnapshot()

	const workers = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap, err := GetProcSnapshot()
			if err != nil {
				errs <- err
				return
			}
			if snap == nil || len(snap.Processes) == 0 {
				t.Errorf("Received empty or nil snapshot in worker")
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("Concurrent worker encountered error: %v", err)
	}
}

func TestProcSnapshotSocketResolver(t *testing.T) {
	snap, err := GetProcSnapshot()
	if err != nil {
		t.Fatalf("GetProcSnapshot failed: %v", err)
	}

	// Non-existent inode must return false
	_, found := snap.GetSocketProcessInfo("99999999999999")
	if found {
		t.Errorf("Expected non-existent inode to return false, but returned true")
	}

	// If there are any socket inodes captured, verify lookup
	for inode, info := range snap.InodeMap {
		resolved, ok := snap.GetSocketProcessInfo(inode)
		if !ok {
			t.Errorf("Failed to resolve existing inode %s", inode)
		}
		if resolved.PID != info.PID || resolved.Name != info.Name {
			t.Errorf("Mismatched resolution for inode %s: expected %+v, got %+v", inode, info, resolved)
		}
		break
	}
}

func TestScanProcessesAndProcEnvIntegration(t *testing.T) {
	// Verify that ScanProcesses works with the snapshot
	procResults, err := ScanProcesses()
	if err != nil {
		t.Fatalf("ScanProcesses failed: %v", err)
	}

	// Verify that ScanProcEnvAuditor works with the snapshot and procResults
	envResults, err := ScanProcEnvAuditor(procResults)
	if err != nil {
		t.Fatalf("ScanProcEnvAuditor failed: %v", err)
	}

	// Should not panic, results can be 0 or more depending on environment
	t.Logf("ScanProcesses discovered %d processes, ScanProcEnvAuditor discovered %d findings", len(procResults), len(envResults))
}
