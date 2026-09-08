package smtp

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"sync"

	cdkeys "construct/delivery/internal/crypto"
	"github.com/emersion/go-msgauth/dkim"
)

// DKIMSigner manages per-domain DKIM signing.
type DKIMSigner struct {
	mu   sync.RWMutex
	keys map[string]*domainKey // domain -> key
}

type domainKey struct {
	privateKey *rsa.PrivateKey
	selector   string
	domain     string
}

func NewDKIMSigner() *DKIMSigner {
	return &DKIMSigner{keys: make(map[string]*domainKey)}
}

// LoadKey loads a DKIM private key for a domain.
func (s *DKIMSigner) LoadKey(domain, selector, privateKeyPEM string) error {
	pk, err := cdkeys.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("parse key for %s: %w", domain, err)
	}

	s.mu.Lock()
	s.keys[strings.ToLower(domain)] = &domainKey{
		privateKey: pk,
		selector:   selector,
		domain:     domain,
	}
	s.mu.Unlock()
	return nil
}

// Sign takes a raw email message and returns a DKIM-signed version.
func (s *DKIMSigner) Sign(domain string, msg []byte) ([]byte, error) {
	s.mu.RLock()
	dk, ok := s.keys[strings.ToLower(domain)]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no DKIM key loaded for domain %s", domain)
	}

	opts := &dkim.SignOptions{
		Domain:                 dk.domain,
		Selector:               dk.selector,
		Signer:                 dk.privateKey,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys: []string{
			"From", "To", "Subject", "Date", "Message-ID",
			"Content-Type", "MIME-Version",
		},
	}

	var signed bytes.Buffer
	if err := dkim.Sign(&signed, bytes.NewReader(msg), opts); err != nil {
		return nil, fmt.Errorf("dkim sign: %w", err)
	}

	return signed.Bytes(), nil
}

// HasKey checks if a domain has a loaded DKIM key.
func (s *DKIMSigner) HasKey(domain string) bool {
	s.mu.RLock()
	_, ok := s.keys[strings.ToLower(domain)]
	s.mu.RUnlock()
	return ok
}

// Verify verifies a DKIM signature (for testing).
func Verify(msg io.Reader) ([]*dkim.Verification, error) {
	return dkim.Verify(msg)
}
