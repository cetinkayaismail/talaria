package scanners

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// LogrotateResult holds findings from the logrotate configuration scanner (A3).
type LogrotateResult struct {
	ConfigPath     string   // e.g. /etc/logrotate.d/nginx
	IsWritable     bool     // current user can write to the config
	PostrotatePaths []string // script paths found in postrotate/prerotate blocks
	RiskLevel      string
	Reason         string
}

// ScanLogrotate scans /etc/logrotate.d/ for writable configs and dangerous
// postrotate/prerotate script paths (A3).
//
// Design decisions to keep FP low and avoid missing vectors:
//   - Only flags configs that are writable by the current user OR contain a
//     postrotate/prerotate script that is writable.
//   - Both /etc/logrotate.conf and /etc/logrotate.d/* are checked.
//   - We do NOT blindly walk subdirectories — logrotate.d is always flat.
//   - Speed: single ReadDir + per-file line scan. Typically <5ms on real systems.
func ScanLogrotate() ([]LogrotateResult, error) {
	ctx := GetUserContext()
	var results []LogrotateResult

	// Collect all config files: top-level conf + every file under logrotate.d/
	configFiles := []string{}
	if _, err := os.Stat("/etc/logrotate.conf"); err == nil {
		configFiles = append(configFiles, "/etc/logrotate.conf")
	}
	entries, err := os.ReadDir("/etc/logrotate.d")
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				configFiles = append(configFiles, "/etc/logrotate.d/"+e.Name())
			}
		}
	}

	for _, cfgPath := range configFiles {
		info, err := os.Stat(cfgPath)
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		isWritable := ctx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode)
		postrotatePaths := extractPostrotateScripts(cfgPath)

		// Only report if this config is writable OR has a writable postrotate script.
		// A writable logrotate config is always dangerous because logrotate runs as root.
		if !isWritable && len(postrotatePaths) == 0 {
			continue
		}

		// Build a result for writable configs
		if isWritable {
			reason := fmt.Sprintf(
				"Logrotate config '%s' is writable. Injecting 'postrotate' commands causes them to execute as root during the next log rotation.",
				cfgPath,
			)
			if len(postrotatePaths) > 0 {
				reason += fmt.Sprintf(" Existing postrotate scripts: %s", strings.Join(postrotatePaths, ", "))
			}
			results = append(results, LogrotateResult{
				ConfigPath:      cfgPath,
				IsWritable:      true,
				PostrotatePaths: postrotatePaths,
				RiskLevel:       "CRITICAL",
				Reason:          reason,
			})
			continue
		}

		// Config is NOT writable but has postrotate scripts — check if any script is writable
		var writableScripts []string
		for _, scriptPath := range postrotatePaths {
			si, err := os.Stat(scriptPath)
			if err != nil {
				continue
			}
			ss, ok := si.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			if ctx.CanWrite(int(ss.Uid), int(ss.Gid), ss.Mode) {
				writableScripts = append(writableScripts, scriptPath)
			}
		}
		if len(writableScripts) == 0 {
			continue
		}
		results = append(results, LogrotateResult{
			ConfigPath:      cfgPath,
			IsWritable:      false,
			PostrotatePaths: postrotatePaths,
			RiskLevel:       "HIGH",
			Reason: fmt.Sprintf(
				"Logrotate config '%s' references writable postrotate script(s): %s — modifying them causes code execution as root during log rotation.",
				cfgPath, strings.Join(writableScripts, ", "),
			),
		})
	}

	return results, nil
}

// extractPostrotateScripts parses a single logrotate config file and returns
// any external script paths found inside postrotate/prerotate ... endscript blocks.
//
// Logrotate syntax for inline scripts:
//
//	postrotate
//	    /path/to/script.sh
//	endscript
//
// We only extract lines that look like an absolute path (starts with '/') and
// are not shell builtins or variable expansions. Inline shell snippets like
// "kill -HUP $(cat /run/foo.pid)" are skipped since they are not writable files.
func extractPostrotateScripts(cfgPath string) []string {
	f, err := os.Open(cfgPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var scripts []string
	inBlock := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lower := strings.ToLower(line)

		// Enter a postrotate/prerotate block
		if lower == "postrotate" || lower == "prerotate" ||
			lower == "firstaction" || lower == "lastaction" {
			inBlock = true
			continue
		}
		// Exit the block
		if lower == "endscript" {
			inBlock = false
			continue
		}

		if inBlock {
			// Extract only simple absolute paths (no shell operators, no $(...))
			// This intentionally misses inline commands — those aren't writable files.
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.HasPrefix(fields[0], "/") &&
				!strings.ContainsAny(line, "$|&;<>`") {
				scripts = append(scripts, fields[0])
			}
		}
	}
	return scripts
}
