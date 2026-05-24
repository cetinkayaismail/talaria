package scanners

import (
	"bufio"
	"bytes"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// SensitiveFileResult represents a file that matches sensitive patterns
type SensitiveFileResult struct {
	Path      string
	Type      string
	RiskLevel string
}

// SensitiveContentResult represents a specific credential found inside a file
type SensitiveContentResult struct {
	Path    string
	Snippet string // What was found: "Password: p@ssw0rd", "OpenVPN user: admin"
}

// --- Pattern definitions ---

// criticalFilePatterns: filenames that are ALWAYS critical regardless of content
var criticalFilePatterns = []string{
	"id_rsa", "id_dsa", "id_ed25519", "id_ecdsa",
	".p12", ".pfx", ".kdbx",
	".bash_history", ".zsh_history", ".sh_history", ".history",
	".netrc", ".aws/credentials", ".kube/config",
	"logins.json", "Cookies", "Login Data", "Web Data", // Browser secrets
	"shadow", "gshadow", "sudoers", // Critical system files
}

// mediumFilePatterns: filenames that warrant content inspection
var mediumFilePatterns = []string{
	".env", "config.php", "settings.py", "database.yml", "database.yaml",
	".tfvars", "terraform.tfvars", "docker-compose.yml", "docker-compose.yaml",
	".ovpn",                                    // OpenVPN config
	"auth.txt", "credentials.txt", "creds.txt", // Plaintext cred files
	"my.cnf", ".my.cnf",                        // MySQL credentials
	"wp-config.php",                             // WordPress
	".htpasswd",                                 // Apache passwords
	"filezilla.xml",                             // FTP credentials
	"recentservers.xml",                         // FileZilla
	"Places.sqlite", "History", "Top Sites",    // Browser history
	"fstab",                                     // Mount table (cifs passwords)
}

// ignoreDirs: never descend into these — they cause freezes and noise
// ignoreDirs is now handled by GlobalIgnoreDirs in common.go

// Regexes compiled once at package init
var (
	// High-confidence specific patterns
	awsKeyRegex       = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	googleApiKeyRegex = regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)
	privateKeyRegex   = regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----`)
	dockerAuthRegex   = regexp.MustCompile(`"auth"\s*:\s*"([A-Za-z0-9+/]{20,}={0,2})"`)
	gitCredRegex      = regexp.MustCompile(`https?://[^:]+:([^@\s]+)@`)
	netrcPassRegex    = regexp.MustCompile(`(?i)password\s+(\S{6,})`)

	// Assignment regex — supports BOTH quoted and unquoted values
	// Matches: password = "secret", password = secret, password: secret;
	assignmentRegex = regexp.MustCompile(
		`(?i)(?:password|passwd|pass|pwd|secret|api[_-]?key|token|credential|auth)[^a-z0-9]{0,5}` +
			`(?:[=:]\s*)` +
			`(?:"([^"]{6,})"|'([^']{6,})'|([^\s;#"']{6,}))`,
	)

	// OpenVPN auth-user-pass points to a credentials file
	ovpnAuthRegex = regexp.MustCompile(`(?i)^\s*auth-user-pass\s*(\S+)?`)

	// IRSSI connect_password (tırnaksız, noktalı virgülle biter)
	irssiPassRegex = regexp.MustCompile(`(?i)(?:connect_)?password\s*=\s*"?([^";\s]+)"?;?`)
)

// ScanSecrets walks the given root path searching for credentials and sensitive files.
// It uses tiered detection: critical filenames → known config filenames → content analysis.
func ScanSecrets(rootPath string) ([]SensitiveFileResult, []SensitiveContentResult) {
	var fileResults []SensitiveFileResult
	var contentResults []SensitiveContentResult

	filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Skip noise directories
		if d.IsDir() {
			if ShouldIgnore(path) {
				return filepath.SkipDir
			}
			return nil
		}

		// Don't follow symlinks
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		fileName := strings.ToLower(d.Name())
		isInteresting := false

		// --- TIER 1: Critical filenames — always flag, skip content scan ---
		for _, pattern := range criticalFilePatterns {
			if strings.Contains(fileName, pattern) {
				fileResults = append(fileResults, SensitiveFileResult{
					Path:      path,
					Type:      "Critical File (" + pattern + ")",
					RiskLevel: "CRITICAL",
				})
				// Also try to grab the first line as a preview (confirms readability)
				if snippet := previewFirstLine(path); snippet != "" {
					contentResults = append(contentResults, SensitiveContentResult{
						Path:    path,
						Snippet: "Preview: " + snippet,
					})
				}
				return nil
			}
		}

		// --- TIER 2: Medium-risk filenames — flag + do content scan ---
		for _, pattern := range mediumFilePatterns {
			if strings.Contains(fileName, pattern) {
				fileResults = append(fileResults, SensitiveFileResult{
					Path:      path,
					Type:      "Config File (" + pattern + ")",
					RiskLevel: "MEDIUM",
				})
				isInteresting = true
				break
			}
		}

		// --- TIER 3: Content scan ---
		info, err := d.Info()
		if err != nil {
			return nil
		}
		// Skip large files and binaries
		if info.Size() > 500000 || isBinary(fileName) {
			return nil
		}

		snippet := analyzeFileContent(path, fileName)
		if snippet != "" {
			contentResults = append(contentResults, SensitiveContentResult{
				Path:    path,
				Snippet: snippet,
			})
			if !isInteresting {
				fileResults = append(fileResults, SensitiveFileResult{
					Path:      path,
					Type:      "Content Match",
					RiskLevel: "HIGH",
				})
			}
		}

		return nil
	})

	return fileResults, contentResults
}

// ScanRootSecrets performs a targeted, non-recursive scan of high-risk hidden directories in /.
// This catches unusual misconfigurations like /.ssh/root_key without walking the entire / filesystem.
func ScanRootSecrets() ([]SensitiveFileResult, []SensitiveContentResult) {
	var fileResults []SensitiveFileResult
	var contentResults []SensitiveContentResult

	targetDirs := []string{"/.ssh", "/.aws", "/.kube", "/.docker", "/.backup", "/.backups", "/.config", "/.secret", "/.secrets"}

	for _, dir := range targetDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // Skip if directory doesn't exist or isn't readable
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue // Targeted scan is non-recursive to maintain speed
			}

			path := filepath.Join(dir, entry.Name())
			fileName := strings.ToLower(entry.Name())

			// Check if filename matches critical patterns
			isCritical := false
			for _, pattern := range criticalFilePatterns {
				if strings.Contains(fileName, pattern) {
					fileResults = append(fileResults, SensitiveFileResult{
						Path:      path,
						Type:      "Root Hidden Secret (" + pattern + ")",
						RiskLevel: "CRITICAL",
					})
					isCritical = true
					break
				}
			}

			// If not critical filename, check content
			snippet := analyzeFileContent(path, fileName)
			if snippet != "" {
				contentResults = append(contentResults, SensitiveContentResult{
					Path:    path,
					Snippet: snippet,
				})
				if !isCritical {
					fileResults = append(fileResults, SensitiveFileResult{
						Path:      path,
						Type:      "Root Hidden Content Match",
						RiskLevel: "HIGH",
					})
				}
			}
		}
	}

	return fileResults, contentResults
}

// analyzeFileContent performs deep content analysis on a single file.
// Returns a human-readable snippet describing what was found, or "".
func analyzeFileContent(path, fileName string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Binary check via file header (Magic Bytes + Null Bytes)
	header := make([]byte, 512)
	n, err := f.Read(header)
	if err == nil && n > 0 && isBinaryContent(header[:n]) {
		return ""
	}
	f.Seek(0, 0)

	// --- Special-case parsers for specific file types ---
	// OpenVPN .ovpn files
	if strings.HasSuffix(fileName, ".ovpn") {
		return analyzeOVPN(f, path)
	}

	// IRSSI config
	if strings.Contains(path, ".irssi") || fileName == "config" {
		if result := analyzeIRSSI(f); result != "" {
			return result
		}
		f.Seek(0, 0)
	}

	// MySQL .my.cnf
	if strings.Contains(fileName, "my.cnf") {
		if result := analyzeMySQL(f); result != "" {
			return result
		}
		f.Seek(0, 0)
	}

	// auth.txt (OpenVPN-style: line1=user, line2=pass)
	if strings.Contains(fileName, "auth") && strings.HasSuffix(fileName, ".txt") {
		if result := analyzeAuthTxt(f); result != "" {
			return result
		}
		f.Seek(0, 0)
	}

	// Docker config.json (base64 encoded auth)
	if fileName == "config.json" && strings.Contains(path, ".docker") {
		if result := analyzeDockerConfig(f); result != "" {
			return result
		}
		f.Seek(0, 0)
	}

	// Git config (embedded credentials in URL)
	if fileName == "config" && strings.Contains(path, ".git") {
		if result := analyzeGitConfig(f); result != "" {
			return result
		}
		f.Seek(0, 0)
	}

	// --- Generic content scan (max 300 lines) ---
	return genericContentScan(f, path)
}

// analyzeOVPN reads an OpenVPN config and checks for auth-user-pass directive.
// If it points to a file, it tries to read that file to get credentials.
func analyzeOVPN(f *os.File, ovpnPath string) string {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := ovpnAuthRegex.FindStringSubmatch(line); len(m) > 0 {
			credFile := strings.TrimSpace(m[1])
			if credFile == "" {
				return "OpenVPN: auth-user-pass directive found (inline credentials)"
			}
			// Resolve relative paths
			if !filepath.IsAbs(credFile) {
				credFile = filepath.Join(filepath.Dir(ovpnPath), credFile)
			}
			// Read credential file stealthily (restores atime if --atime-restore)
			if creds, err := ReadFileStealthy(credFile); err == nil {
				lines := strings.Split(strings.TrimSpace(string(creds)), "\n")
				if len(lines) >= 2 {
					user := strings.TrimSpace(lines[0])
					pass := strings.TrimSpace(lines[1])
					return "OpenVPN Credentials → User: " + user + " | Password: " + pass + " (from " + credFile + ")"
				}
			}
			return "OpenVPN: auth-user-pass → " + credFile + " (could not read credential file)"
		}
	}
	return ""
}

// analyzeIRSSI extracts passwords from IRSSI config format
func analyzeIRSSI(f *os.File) string {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := irssiPassRegex.FindStringSubmatch(line); len(m) > 1 {
			pass := strings.TrimSpace(m[1])
			if !isFalsePositive(pass) {
				return "IRSSI Password: " + pass
			}
		}
	}
	return ""
}

// analyzeMySQL extracts passwords from .my.cnf format
func analyzeMySQL(f *os.File) string {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(strings.ToLower(line), "password") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				pass := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
				if pass != "" && !isFalsePositive(pass) {
					return "MySQL Password: " + pass
				}
			}
		}
	}
	return ""
}

// analyzeAuthTxt handles OpenVPN-style auth files (line1=user, line2=pass)
func analyzeAuthTxt(f *os.File) string {
	scanner := bufio.NewScanner(f)
	lines := []string{}
	for scanner.Scan() && len(lines) < 5 {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	// OpenVPN auth format: exactly 2 non-comment lines
	if len(lines) == 2 {
		return "Plaintext Credentials → User: " + lines[0] + " | Password: " + lines[1]
	}
	// Also check if only password is listed
	if len(lines) == 1 && len(lines[0]) >= 6 {
		return "Plaintext Secret: " + lines[0]
	}
	return ""
}

// analyzeDockerConfig extracts auth from ~/.docker/config.json
func analyzeDockerConfig(f *os.File) string {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := dockerAuthRegex.FindStringSubmatch(line); len(m) > 1 {
			// The auth value is base64(user:pass) — we return it as-is
			return "Docker Registry Auth (base64): " + m[1] + " → decode with: echo " + m[1] + " | base64 -d"
		}
	}
	return ""
}

// analyzeGitConfig detects embedded credentials in git remote URLs
func analyzeGitConfig(f *os.File) string {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := gitCredRegex.FindStringSubmatch(line); len(m) > 1 {
			return "Git Embedded Credential in URL → Password: " + m[1]
		}
	}
	return ""
}

// genericContentScan is the fallback scanner for unknown file types.
// Scans up to 300 lines for high-confidence patterns and secret assignments.
func genericContentScan(f *os.File, path string) string {
	scanner := bufio.NewScanner(f)
	lineNum := 0
	fileName := strings.ToLower(filepath.Base(path))
	isScript := strings.HasSuffix(fileName, ".sh") || strings.HasSuffix(fileName, ".py") || strings.HasSuffix(fileName, ".pl")

	for scanner.Scan() && lineNum < 300 {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 1. Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// --- FP Reduction: Strip inline comments heuristically ---
		cleanLine := line
		for _, marker := range []string{"#", "//", ";"} {
			if idx := strings.Index(line, marker); idx >= 0 {
				prefix := line[:idx]
				// If quotes before the marker are even, the marker is an inline comment
				if strings.Count(prefix, "\"")%2 == 0 && strings.Count(prefix, "'")%2 == 0 {
					cleanLine = prefix
					break
				}
			}
		}

		// 2. High-confidence regex patterns
		if awsKeyRegex.MatchString(cleanLine) {
			return "AWS Access Key ID: " + awsKeyRegex.FindString(cleanLine)
		}
		if googleApiKeyRegex.MatchString(cleanLine) {
			return "Google API Key: " + googleApiKeyRegex.FindString(cleanLine)
		}
		if privateKeyRegex.MatchString(cleanLine) {
			return "Private Key Header detected"
		}
		
		// Netrc check: ONLY apply if the filename actually is a netrc file.
		if (fileName == ".netrc" || fileName == "_netrc" || fileName == "netrc") {
			if m := netrcPassRegex.FindStringSubmatch(cleanLine); len(m) > 1 && !isFalsePositive(m[1]) {
				return "Netrc Password: " + m[1]
			}
		}

		// 3. Assignment regex — all 3 capture groups (quoted double, quoted single, unquoted)
		if m := assignmentRegex.FindStringSubmatch(cleanLine); len(m) > 1 {
			value := ""
			quoted := false
			for i, candidate := range m[1:] {
				if candidate != "" {
					value = candidate
					if i < 2 { // Group 1 and 2 are quoted
						quoted = true
					}
					break
				}
			}

			if value != "" && !isFalsePositive(value) {
				keyName := extractKeyName(cleanLine)

				// 1. Skip if value is just the key name (template)
				if strings.EqualFold(value, keyName) {
					continue
				}

				// 2. Skip template variables like ${VARIABLE}, {{SECRET}}, <PASSWORD> or __PLACEHOLDER__
				valTrim := strings.TrimSpace(value)
				if strings.HasPrefix(valTrim, "${") || strings.HasPrefix(valTrim, "{{") || strings.Contains(valTrim, "$(") ||
					(strings.HasPrefix(valTrim, "<") && strings.HasSuffix(valTrim, ">")) ||
					(strings.HasPrefix(valTrim, "__") && strings.HasSuffix(valTrim, "__")) {
					continue
				}

				// 3. Skip if unquoted and contains multiple spaces (likely a description/sentence)
				if !quoted && strings.Contains(value, "  ") {
					continue
				}

				// Stricter logic for example files or scripts
				isExample := strings.Contains(path, "example") || strings.Contains(path, "sample")
				entropyThreshold := 2.8
				if (isScript || isExample) && !quoted {
					entropyThreshold = 3.5
				}

				if calculateEntropy(value) > entropyThreshold {
					return keyName + ": " + value
				}
			}
		}
	}
	return ""
}

// extractKeyName finds the variable name before the assignment operator
func extractKeyName(line string) string {
	re := regexp.MustCompile(`(?i)([\w_-]+)\s*[=:]`)
	if m := re.FindStringSubmatch(line); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return "Secret"
}

// previewFirstLine returns the first non-empty line of a file (for private key confirmation).
// Uses ReadFileStealthy so that --atime-restore applies to critical credential reads.
func previewFirstLine(path string) string {
	data, err := ReadFileStealthy(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.SplitN(string(data), "\n", 10) {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

// isFalsePositive filters out obvious placeholder values and common documentation words
func isFalsePositive(val string) bool {
	if len(val) < 4 {
		return true
	}
	valLower := strings.ToLower(val)

	// 1. Exact matches for common noise/placeholder words
	exactNoise := []string{
		"password", "passw0rd", "secret", "mypassword", "your_secret",
		"changeme", "placeholder", "dummy", "default", "test", "none",
		"null", "true", "false", "your", "sample", "template", "example",
		"changes", "updating", "without", "expires", "cracker", "authentication",
		"generic", "nothing", "undefined", "required", "hashes", "binary",
		"version", "installed", "disabled", "enabled", "checked", "modified",
	}
	for _, w := range exactNoise {
		if valLower == w || valLower == w+"." || valLower == w+"," {
			return true
		}
	}

	// 2. "Contains" matches for obvious placeholders and script variables/colors
	placeholderPatterns := []string{
		"your_secret", "enter_pass", "password_here", "xxxxxx", "yyyyyy",
		"[success=", "[default=", "requisite", "sufficient", "required", "pam_", // PAM module noise
	}
	for _, p := range placeholderPatterns {
		if strings.Contains(valLower, p) {
			return true
		}
	}

	// 3. Bash/Shell specific noise (variables, color codes)
	// No human password will start with a bash variable indicator or color escape
	if strings.Contains(val, "$") && (strings.HasPrefix(val, "$") || strings.Contains(val, "${")) {
		return true // It's a bash variable, e.g. $readpasswd
	}
	if strings.Contains(val, `\e[`) || strings.Contains(val, `\033[`) {
		return true // It's a terminal color code
	}

	return false
}

// calculateEntropy calculates the Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	m := make(map[rune]int)
	for _, r := range s {
		m[r]++
	}
	var entropy float64
	for _, count := range m {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isLikelyConfig returns true if the file extension or name suggests it's a config
func isLikelyConfig(path string) bool {
	fileName := strings.ToLower(filepath.Base(path))
	configExts := []string{".conf", ".config", ".yaml", ".yml", ".json", ".xml", ".ini", ".inf", ".txt", ".sh", ".ovpn", ".cnf"}
	for _, ext := range configExts {
		if strings.HasSuffix(fileName, ext) {
			return true
		}
	}
	configNames := []string{"config", "settings", "credentials", "auth", "secret"}
	for _, name := range configNames {
		if strings.Contains(fileName, name) {
			return true
		}
	}
	return false
}

// isBinary checks filename extension for known binary types
func isBinary(name string) bool {
	ext := filepath.Ext(name)
	binExts := map[string]bool{
		".so": true, ".exe": true, ".bin": true, ".pyc": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".zip": true, ".gz": true, ".tar": true, ".bz2": true,
		".pdf": true, ".mp4": true, ".mp3": true, ".avi": true,
		".deb": true, ".rpm": true, ".img": true, ".iso": true,
	}
	return binExts[ext]
}

// isBinaryContent checks for common binary file signatures and null bytes
func isBinaryContent(data []byte) bool {
	// Check magic numbers
	magicSignatures := [][]byte{
		{0x7F, 'E', 'L', 'F'},     // ELF
		{'M', 'Z'},                 // PE (Windows)
		{0xCA, 0xFE, 0xBA, 0xBE},   // Mach-O (macOS)
		{0xCF, 0xFA, 0xED, 0xFE},   // Mach-O 64-bit
		{0x50, 0x4B, 0x03, 0x04},   // ZIP / JAR / APK
		{0x25, 0x50, 0x44, 0x46},   // PDF
	}
	for _, sig := range magicSignatures {
		if len(data) >= len(sig) && bytes.HasPrefix(data, sig) {
			return true
		}
	}

	// Fallback: Check for null bytes
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

// isBinaryBytes is kept for backward compatibility but calls isBinaryContent
func isBinaryBytes(data []byte) bool {
	return isBinaryContent(data)
}

// --- Unused but kept for backward compat ---
func scanFileContent(path string, keywords []string) string {
	_ = keywords
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	return genericContentScan(f, path)
}

// scanBasicLine is kept to satisfy old callers
func scanBasicLine(_ string) string { return "" }

// intStr is a tiny helper used by analyzeAuthTxt
func intStr(i int) string { return strconv.Itoa(i) }