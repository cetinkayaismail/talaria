package scanners

import (
	"strings"
	"testing"
)

func TestAuditHistoryLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		expectFlag  bool
		expectMask  bool
		secretValue string
	}{
		{
			name:        "Harmless command",
			line:        "ls -la /etc/profile.d",
			expectFlag:  false,
			expectMask:  false,
			secretValue: "",
		},
		{
			name:        "Environment password assignment",
			line:        "export DB_PASSWORD=mySuperSecretDBPass123",
			expectFlag:  true,
			expectMask:  true,
			secretValue: "mySuperSecretDBPass123",
		},
		{
			name:        "CLI flag with single quotes",
			line:        "mysql -u admin -p'db_pass_123!'",
			expectFlag:  true,
			expectMask:  true,
			secretValue: "db_pass_123!",
		},
		{
			name:        "Database connection string",
			line:        "psql postgresql://postgres:postgrespw123@localhost:5432/mydb",
			expectFlag:  true,
			expectMask:  true,
			secretValue: "postgrespw123",
		},
		{
			name:        "Harmless environment variable",
			line:        "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin",
			expectFlag:  false,
			expectMask:  false,
			secretValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := auditHistoryLine(tt.line, "testuser", "/home/testuser/.bash_history", 42)

			if tt.expectFlag {
				if res == nil {
					t.Fatalf("expected command line to be flagged but got nil")
				}
				if res.RiskLevel != "CRITICAL" {
					t.Errorf("expected risk level to be CRITICAL, got %s", res.RiskLevel)
				}

				if tt.expectMask {
					if !strings.Contains(res.Command, "***") {
						t.Errorf("expected command line to be masked, got: %s", res.Command)
					}
					// Verify that the cleartext secret value does NOT appear in the masked command
					if strings.Contains(res.Command, tt.secretValue) {
						t.Errorf("expected cleartext secret %q to be masked out, but it was found in: %s", tt.secretValue, res.Command)
					}
				}
			} else {
				if res != nil {
					t.Fatalf("expected command line to be skipped but got result: %+v", res)
				}
			}
		})
	}
}

func TestGetSystemUsers(t *testing.T) {
	// Verify that /etc/passwd parsing runs without error
	users, err := getSystemUsers()
	if err != nil {
		t.Fatalf("getSystemUsers failed: %v", err)
	}

	// We expect at least the root user to be returned
	hasRoot := false
	for _, u := range users {
		if u.Username == "root" && u.HomeDir == "/root" {
			hasRoot = true
			break
		}
	}

	if !hasRoot {
		t.Error("expected system users to contain root with /root home dir")
	}
}
