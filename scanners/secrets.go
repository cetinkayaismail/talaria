package scanners

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SensitiveFileResult represents a file that matches sensitive patterns
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

	// Directories to skip to prevent freezing/useless noise
	ignoreDirs := []string{
		"/etc/fonts", "/etc/X11", "/usr/share", "/var/lib/dpkg", "/lib/modules",
		"/var/cache", "/run", "/sys", "/proc", "/dev", "/snap", "/var/lib/apt",
	}

	criticalPatterns := []string{"id_rsa", "id_dsa", "id_ed25519", "id_ecdsa", ".p12", ".kdbx", ".bash_history", ".zsh_history"}
	mediumPatterns := []string{".env", "config.php", "settings.py", "database.yml", ".tfvars", "shadow", "sudoers"}
	searchKeywords := []string{"password", "api_key", "secret", "token", "private key"}

	// WalkDir is the high-performance version of Walk
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

		// 3. Content Search (Fast Text Scan)
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

func scanFileContent(path string, keywords []string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 0; scanner.Scan() && i < 50; i++ {
		line := strings.ToLower(scanner.Text())
		for _, key := range keywords {
			if strings.Contains(line, key) {
				return key
			}
		}
	}
	return ""
}

func isBinary(name string) bool {
	ext := filepath.Ext(name)
	binExts := map[string]bool{
		".so": true, ".exe": true, ".bin": true, ".pyc": true,
		".png": true, ".jpg": true, ".zip": true, ".gz": true,
	}
	return binExts[ext]
}