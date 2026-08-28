package core

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

// EncryptReport encrypts plaintext report data using AES-256-GCM.
// The passphrase is stretched to a 256-bit key via SHA-256.
// Output format: base64(nonce || ciphertext || GCM tag)
func EncryptReport(data []byte, passphrase string) ([]byte, error) {
	keyHash := sha256.Sum256([]byte(passphrase))

	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	out := []byte(base64.StdEncoding.EncodeToString(encrypted))
	return out, nil
}

// DecryptReport is the inverse of EncryptReport.
func DecryptReport(b64data []byte, passphrase string) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(string(b64data))
	if err != nil {
		return nil, err
	}

	keyHash := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, io.ErrUnexpectedEOF
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
