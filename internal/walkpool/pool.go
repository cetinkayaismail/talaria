// Package walkpool provides a parallel filesystem walker that replaces serial
// filepath.WalkDir callsites with a shared goroutine worker-pool for improved
// I/O throughput.
//
// # Design
//
// One dispatcher goroutine maintains an unbounded in-memory queue of directories.
// N worker goroutines read directories from a bounded channel, call os.ReadDir,
// emit file entries on the output channel, and report discovered subdirectories
// back to the dispatcher.
//
// This avoids the deadlock inherent in a simple bounded-queue design where
// workers try to enqueue subdirs into a full channel while holding their own
// processing slot. Instead:
//
//   - Workers send results (subdirs + "I'm done") to a result channel of size N
//     before picking up new work, so they never block on the result send.
//   - The dispatcher owns the queue and is the only writer to toWorker.
//   - toWorker capacity = N so the dispatcher can stay one cycle ahead of workers.
//
// # SkipDir semantics
//
// skipDir is enforced at the dispatcher: rejected directories are never added to
// the queue and never seen by workers. This mirrors filepath.SkipDir behaviour
// without requiring workers to return sentinel errors.
//
// # Thread safety
//
// The returned channel is safe to consume from a single goroutine (typical usage).
// The pool itself is entirely internal; callers interact only via the output channel
// and context cancellation.
package walkpool

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
)

// WalkEntry is one filesystem entry delivered by [Walk].
type WalkEntry struct {
	Path  string     // absolute path to the entry
	Entry fs.DirEntry // lightweight stat (already resolved by os.ReadDir)
}

// Walk traverses root in parallel using workers goroutines and returns a channel
// that receives every non-directory entry found during traversal.
//
// The channel is closed when the traversal completes or ctx is cancelled.
//
// skipDir, if non-nil, is called with the absolute path of every discovered
// sub-directory before it is enqueued. If skipDir returns true, the directory
// and all its descendants are skipped entirely — equivalent to returning
// filepath.SkipDir from a serial WalkDir callback.
//
// Symlinks are emitted as-is (not followed); callers may inspect Entry.Type()
// to detect them.
//
// If workers is ≤ 0 it defaults to 4.
// If root does not exist, the returned channel is closed immediately.
func Walk(ctx context.Context, root string, workers int, skipDir func(string) bool) <-chan WalkEntry {
	if workers <= 0 {
		workers = 4
	}

	// Buffer = workers × 16 so workers rarely block on emit.
	out := make(chan WalkEntry, workers*16)

	go func() {
		defer close(out)

		// Confirm root is accessible before starting workers.
		if _, err := os.Lstat(root); err != nil {
			return
		}

		// workResult is the message a worker sends to the dispatcher after
		// it finishes processing one directory.
		type workResult struct {
			subdirs []string // subdirectories to enqueue (already filtered by skipDir)
		}

		// toWorker: the dispatcher sends directory paths here.
		// Capacity N so dispatcher can queue up to N dirs without blocking.
		toWorker := make(chan string, workers)

		// toResult: workers send their workResult here.
		// Capacity N so a worker's result send never blocks even if dispatcher
		// is momentarily busy sending on toWorker.
		toResult := make(chan workResult, workers)

		// Launch N stateless worker goroutines.
		// Each worker: reads a dir, emits file entries, collects subdirs, reports back.
		for i := 0; i < workers; i++ {
			go func() {
				for dir := range toWorker {
					subdirs := readDir(ctx, dir, out, skipDir)
					toResult <- workResult{subdirs: subdirs}
				}
			}()
		}

		// ── Dispatcher ───────────────────────────────────────────────────────
		// queue: in-memory list of directories pending processing.
		// pending: count of directories currently held by workers.
		queue := []string{root}
		pending := 0

		for len(queue) > 0 || pending > 0 {
			// Only offer a directory to a worker when the queue is non-empty.
			var (
				sendCh  chan string
				nextDir string
			)
			if len(queue) > 0 {
				sendCh = toWorker
				nextDir = queue[0]
			}

			select {
			case <-ctx.Done():
				// Context cancelled: drain any in-flight workers so their
				// goroutines can exit cleanly, then shut down.
				for ; pending > 0; pending-- {
					<-toResult
				}
				close(toWorker)
				return

			case sendCh <- nextDir:
				// Successfully dispatched a directory to a worker.
				queue = queue[1:]
				pending++

			case res := <-toResult:
				// A worker finished a directory.
				pending--
				// Append its discovered subdirectories to our queue.
				// These have already been filtered by skipDir inside readDir.
				queue = append(queue, res.subdirs...)
			}
		}

		// All directories processed. Signal workers to exit.
		close(toWorker)
	}()

	return out
}

// readDir processes a single directory: it calls os.ReadDir, emits non-directory
// entries on out, and returns the list of sub-directories to enqueue next.
//
// Directories are filtered by skipDir before being added to the returned list.
// On context cancellation, readDir stops early and returns whatever subdirs it
// has collected so far (the dispatcher will drain and shut down cleanly).
func readDir(
	ctx context.Context,
	dir string,
	out chan<- WalkEntry,
	skipDir func(string) bool,
) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Permission denied or I/O error — silently skip, matching
		// the nil-error return convention of filepath.WalkDir callbacks.
		return nil
	}

	var subdirs []string
	for _, e := range entries {
		// Fast context check on every entry (not just dirs) to keep
		// cancellation latency low in dense directories.
		select {
		case <-ctx.Done():
			return subdirs
		default:
		}

		path := filepath.Join(dir, e.Name())

		if e.IsDir() {
			// Apply the SkipDir predicate before enqueuing.
			if skipDir == nil || !skipDir(path) {
				subdirs = append(subdirs, path)
			}
			continue
		}

		// Emit the entry (including symlinks — callers filter if needed).
		select {
		case out <- WalkEntry{Path: path, Entry: e}:
		case <-ctx.Done():
			return subdirs
		}
	}

	return subdirs
}
