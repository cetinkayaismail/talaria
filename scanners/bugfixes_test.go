package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretsExactAndSuffixMatching(t *testing.T) {
	// False positives that must NOT match
	fps := []struct {
		name string
		path string
	}{
		{"box-shadow.css", "/var/www/html/css/box-shadow.css"},
		{"shadow.png", "/var/www/html/img/shadow.png"},
		{"libshadow.so", "/usr/lib/libshadow.so"},
		{"shadowsocks.json", "/etc/shadowsocks.json"},
		{"commit_history.txt", "/home/user/commit_history.txt"},
	}

	for _, tc := range fps {
		isCrit, pat := matchCriticalPattern(tc.name, tc.path)
		if isCrit {
			t.Errorf("False positive detected: %s (path: %s) matched pattern '%s'", tc.name, tc.path, pat)
		}
	}

	// True positives that MUST match
	tps := []struct {
		name string
		path string
	}{
		{"shadow", "/etc/shadow"},
		{"gshadow", "/etc/gshadow"},
		{"sudoers", "/etc/sudoers"},
		{"credentials", "/home/user/.aws/credentials"},
		{"config", "/home/user/.kube/config"},
		{"id_rsa", "/home/user/.ssh/id_rsa"},
		{"id_ed25519", "/home/user/.ssh/id_ed25519"},
		{"id_rsa.backup", "/tmp/id_rsa.backup"},
		{".bash_history", "/home/user/.bash_history"},
		{"key.kdbx", "/home/user/keepass/key.kdbx"},
	}

	for _, tc := range tps {
		isCrit, _ := matchCriticalPattern(tc.name, tc.path)
		if !isCrit {
			t.Errorf("Expected true positive to match: %s (path: %s)", tc.name, tc.path)
		}
	}
}

func TestSecretsMediumMatching(t *testing.T) {
	if isMed, _ := matchMediumPattern("box-shadow.css"); isMed {
		t.Error("box-shadow.css should not match medium pattern")
	}

	validMedium := []string{".env", ".env.local", "config.php", "client.ovpn", "database.yml"}
	for _, f := range validMedium {
		if isMed, _ := matchMediumPattern(f); !isMed {
			t.Errorf("Expected %s to match medium pattern", f)
		}
	}
}

func TestCronjobInterpretedScriptAnalysis(t *testing.T) {
	// Initialize user context
	InitUserContext()
	userCtx := GetUserContext()
	if userCtx == nil {
		t.Skip("User context unavailable")
	}

	// Create a temporary script writable by current user
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "backup.py")
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env python3\nprint('hello')\n"), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	// Analyze a root cron line running python3 with the writable script
	line := "* * * * * root /usr/bin/python3 " + scriptPath
	res := analyzeCronLine(line, "/etc/cron.d/test_backup", userCtx.UID)
	if res == nil {
		t.Fatal("Expected non-nil result from analyzeCronLine")
	}

	if !res.IsDangerous {
		t.Errorf("Expected interpreted script %s to be flagged as dangerous/writable", scriptPath)
	}
}
