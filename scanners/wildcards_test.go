package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasWildcardCall(t *testing.T) {
	cases := []struct {
		line     string
		cmd      string
		expected bool
	}{
		{"tar -czf /tmp/backup.tar.gz *", "tar", true},
		{"tar cf archive.tar /var/log/*", "tar", true},
		{"rsync -av * /opt/backup/", "rsync", true},
		{"chmod 777 *", "chmod", true},
		{"chown www-data:www-data *", "chown", true},
		{"zip -r backup.zip *", "zip", true},
		{"7z a archive.7z *", "7z", true},
		{"echo *", "tar", false},
		{"tar -czf backup.tar.gz file1 file2", "tar", false},
		{"# tar -czf backup.tar.gz *", "tar", false},
		{"echo hello; tar -czf backup.tar.gz *", "tar", true},
	}

	for _, tc := range cases {
		actual := hasWildcardCall(tc.line, tc.cmd)
		if actual != tc.expected {
			t.Errorf("hasWildcardCall(%q, %q) = %v; want %v", tc.line, tc.cmd, actual, tc.expected)
		}
	}
}

func TestInspectScriptContent(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "backup.sh")
	scriptContent := `#!/bin/bash
cd /tmp
tar -czf backup.tar.gz *
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	var results []WildcardResult
	seen := make(map[string]bool)
	inspectScriptContent("/etc/crontab", scriptPath, "", GetUserContext(), &results, seen)

	if len(results) != 1 {
		t.Fatalf("Expected 1 wildcard result, got %d", len(results))
	}

	res := results[0]
	if res.VulnerableCmd != "tar" {
		t.Errorf("Expected VulnerableCmd 'tar', got %q", res.VulnerableCmd)
	}
	if res.WorkingDir != "/tmp" {
		t.Errorf("Expected WorkingDir '/tmp', got %q", res.WorkingDir)
	}
	if res.RiskLevel != "CRITICAL" && res.RiskLevel != "HIGH" {
		t.Errorf("Expected CRITICAL or HIGH risk level, got %q", res.RiskLevel)
	}
}

func TestExtractScriptPath(t *testing.T) {
	cases := []struct {
		cmd      string
		expected string
	}{
		{"/bin/bash /opt/scripts/backup.sh", "/opt/scripts/backup.sh"},
		{"sh /root/backup.sh", "/root/backup.sh"},
		{"/usr/local/bin/run_job.sh", "/usr/local/bin/run_job.sh"},
		{"ls -la /tmp", ""},
	}

	for _, tc := range cases {
		actual := extractScriptPath(tc.cmd)
		if actual != tc.expected {
			t.Errorf("extractScriptPath(%q) = %q; want %q", tc.cmd, actual, tc.expected)
		}
	}
}
