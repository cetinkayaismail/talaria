package scanners

import (
	"strings"
	"testing"
)

func TestParseEnviron(t *testing.T) {
	mockEnv := []string{
		"PATH=/usr/bin:/bin",
		"AWS_SECRET_ACCESS_KEY=supersecretkey123",
		"DB_PASSWORD=my_secure_db_pass",
		"NOISE_VAR=someplaceholder", // Should be ignored
		"TEST_API_KEY=dummy",         // Dummy is a false positive and should be skipped
		"VALID_API_KEY=ghp_12345678901234567890",
	}
	data := []byte(strings.Join(mockEnv, "\x00") + "\x00")

	secrets := parseEnviron(data)

	// We expect AWS_SECRET_ACCESS_KEY, DB_PASSWORD, and VALID_API_KEY
	expectedMatches := map[string]string{
		"AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY=supe********",
		"DB_PASSWORD":           "DB_PASSWORD=my_s********",
		"VALID_API_KEY":         "VALID_API_KEY=ghp_********",
	}

	for _, s := range secrets {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			t.Errorf("unexpected secret format: %s", s)
			continue
		}
		key := parts[0]
		expectedVal, exists := expectedMatches[key]
		if !exists {
			t.Errorf("unexpected key parsed as secret: %s", key)
			continue
		}
		if s != expectedVal {
			t.Errorf("expected secret string %q, got %q", expectedVal, s)
		}
	}

	// Make sure we matched exactly 3 secrets
	if len(secrets) != 3 {
		t.Errorf("expected exactly 3 secrets, got %d: %v", len(secrets), secrets)
	}
}

func TestMaskSecretValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"123", "****"},
		{"1234", "****"},
		{"12345", "1234********"},
		{"password", "pass********"},
	}

	for _, tc := range tests {
		got := maskSecretValue(tc.input)
		if got != tc.expected {
			t.Errorf("maskSecretValue(%q) = %q; expected %q", tc.input, got, tc.expected)
		}
	}
}
