package core

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	originalData := []byte("CONFIDENTIAL_BANK_REPORT: root finding: /etc/shadow read vulnerability")
	passphrase := "InstitutionalGradePassphrase2026!#"

	encrypted, err := EncryptReport(originalData, passphrase)
	if err != nil {
		t.Fatalf("EncryptReport failed: %v", err)
	}

	if len(encrypted) == 0 {
		t.Fatal("Encrypted output is empty")
	}

	decrypted, err := DecryptReport(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptReport failed: %v", err)
	}

	if !bytes.Equal(originalData, decrypted) {
		t.Fatalf("Decrypted data mismatch: expected %q, got %q", originalData, decrypted)
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	originalData := []byte("Sensitive audit trail")
	passphrase := "CorrectPassphrase123"
	wrongPassphrase := "IncorrectPassphrase456"

	encrypted, err := EncryptReport(originalData, passphrase)
	if err != nil {
		t.Fatalf("EncryptReport failed: %v", err)
	}

	_, err = DecryptReport(encrypted, wrongPassphrase)
	if err == nil {
		t.Fatal("Expected error when decrypting with wrong passphrase, but got nil")
	}
}

func TestDecryptCorruptData(t *testing.T) {
	passphrase := "TestPassphrase"

	// Invalid Base64
	_, err := DecryptReport([]byte("NotBase64!@#$"), passphrase)
	if err == nil {
		t.Fatal("Expected error for non-base64 input, got nil")
	}

	// Base64 too short for GCM nonce
	_, err = DecryptReport([]byte("AAAA"), passphrase)
	if err == nil {
		t.Fatal("Expected error for undersized nonce payload, got nil")
	}
}

func TestEncryptEmptyPayload(t *testing.T) {
	passphrase := "EmptyTestKey"
	emptyData := []byte{}

	encrypted, err := EncryptReport(emptyData, passphrase)
	if err != nil {
		t.Fatalf("EncryptReport on empty data failed: %v", err)
	}

	decrypted, err := DecryptReport(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptReport on empty data failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("Expected empty slice, got len %d", len(decrypted))
	}
}
