package scanners

import (
	"bufio"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SensitiveFileResult represents a file that matches sensitive patterns looking for credentials it was taking too much time in ctf's for me
type SensitiveFileResult struct {
	Path      string
	Type      string
	RiskLevel string
}

// SensitiveContentResult represents content found in a file
type SensitiveContentResult struct {
	Path    string
	Snippet string
}

func ScanSecrets(rootPath string) ([]SensitiveFileResult, []SensitiveContentResult) {
	var fileResults []SensitiveFileResult
	var contentResults []SensitiveContentResult

	// Directories to skip to prevent freezing/useless noise this will make it much faster and less noise
	ignoreDirs := []string{
		"/etc/fonts", "/etc/X11", "/usr/share", "/var/lib/dpkg", "/lib/modules",
		"/var/cache", "/run", "/sys", "/proc", "/dev", "/snap", "/var/lib/apt",
	}

	criticalPatterns := []string{"id_rsa", "id_dsa", "id_ed25519", "id_ecdsa", ".p12", ".kdbx", ".bash_history", ".zsh_history"}
	mediumPatterns := []string{".env", "config.php", "settings.py", "database.yml", ".tfvars", "shadow", "sudoers"}
	searchKeywords := []string{"password", "api_key", "secret", "token", "private key"}

	// WalkDir is the high-performance version of Walk I prefer this one because it is faster than bash commands
	filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil 
		}

		if d.IsDir() {
			for _, ignore := range ignoreDirs {
				if strings.HasPrefix(path, ignore) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		fileName := strings.ToLower(d.Name())
		isInteresting := false

		// 1. Critical Filenames (Instant Exit)
		for _, pattern := range criticalPatterns {
			if strings.Contains(fileName, pattern) {
				fileResults = append(fileResults, SensitiveFileResult{
					Path: path, Type: "Critical File (" + pattern + ")", RiskLevel: "CRITICAL",
				})
				return nil 
			}
		}

		// 2. Medium Risk Filenames
		for _, pattern := range mediumPatterns {
			if strings.Contains(fileName, pattern) {
				fileResults = append(fileResults, SensitiveFileResult{
					Path: path, Type: "Medium Risk Config (" + pattern + ")", RiskLevel: "MEDIUM",
				})
				isInteresting = true
				break 
			}
		}

		// 3. Content Search (Fast Text Scan) looking for keywords this is also will be very usefull in some ctf engagements
		info, _ := d.Info()
		if info.Size() < 250000 && !isBinary(fileName) {
			foundKey := scanFileContent(path, searchKeywords)
			if foundKey != "" {
				contentResults = append(contentResults, SensitiveContentResult{
					Path:    path,
					Snippet: "Keyword: " + foundKey,
				})
				
				if !isInteresting {
					fileResults = append(fileResults, SensitiveFileResult{
						Path: path, Type: "Content Match", RiskLevel: "HIGH",
					})
				}
			}
		}

		return nil
	})

	return fileResults, contentResults
}

var (
	// Regex for High-Confidence Secrets
	awsKeyRegex       = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	googleApiKeyRegex = regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)
	privateKeyRegex   = regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----`)

	// Regex for Generic Assignments: key = "value", password: 'value'
	// Looks for a keyword, an assignment operator (= or :), and a value inside quotes
	assignmentRegex = regexp.MustCompile(`(?i)(?:key|api|token|secret|password|pass|pwd|credential)[^a-z0-9]{0,5}(?:[=:]|\s+)\s*["']([^"'\s]{8,})["']`)
)

func scanFileContent(path string, keywords []string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}

	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	// Check if file is truly binary by reading the first 512 bytes
	header := make([]byte, 512)
	n, err := file.Read(header)
	if err == nil && n > 0 && isBinaryBytes(header[:n]) {
		return ""
	}
	file.Seek(0, 0) // Reset to start

	scanner := bufio.NewScanner(file)
	for i := 0; scanner.Scan() && i < 150; i++ { // Increased scan depth slightly
		line := scanner.Text()

		// 1. High-Confidence Pattern Matching (No entropy check needed)
		if awsKeyRegex.MatchString(line) {
			return "AWS Access Key"
		}
		if googleApiKeyRegex.MatchString(line) {
			return "Google API Key"
		}
		if privateKeyRegex.MatchString(line) {
			return "Private Key Header"
		}

		// 2. Assignment & Entropy Check
		matches := assignmentRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			value := matches[1]
			// Filter out common false positives
			if isFalsePositive(value) {
				continue
			}
			
			entropy := calculateEntropy(value)
			// A lower threshold for passwords since they can be shorter, but must still have some complexity
			if entropy > 3.2 { 
				return "High-Entropy Secret Assignment"
			}
		}
	}
	return ""
}

func isFalsePositive(val string) bool {
	valLower := strings.ToLower(val)
	falsePositives := []string{
		"example", "password", "123456", "your_secret", "changeme",
		"placeholder", "xxxxxxxx", "dummy", "default",
	}
	for _, fp := range falsePositives {
		if strings.Contains(valLower, fp) {
			return true
		}
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

// isBinary checks filename extension
func isBinary(name string) bool {
	ext := filepath.Ext(name)
	binExts := map[string]bool{
		".so": true, ".exe": true, ".bin": true, ".pyc": true,
		".png": true, ".jpg": true, ".zip": true, ".gz": true,
		".tar": true, ".pdf": true, ".mp4": true, ".mp3": true,
	}
	return binExts[ext]
}

// isBinaryBytes checks for null bytes in the file header
func isBinaryBytes(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true // Null byte found, likely binary
		}
	}
	return false
}