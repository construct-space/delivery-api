package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// GenerateDKIMKeyPair creates a 2048-bit RSA key pair for DKIM signing.
// Returns PEM-encoded private key and base64-encoded public key (for DNS TXT record).
func GenerateDKIMKeyPair() (privateKeyPEM string, publicKeyBase64 string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	// Private key PEM
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	privateKeyPEM = string(pem.EncodeToMemory(privBlock))

	// Public key for DNS TXT record (base64 of DER)
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}
	publicKeyBase64 = base64.StdEncoding.EncodeToString(pubBytes)

	return
}

// ParsePrivateKey parses a PEM-encoded RSA private key.
func ParsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
