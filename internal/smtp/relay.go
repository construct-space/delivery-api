package smtp

import (
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/google/uuid"
)

// RelayServer accepts emails via SMTP (port 587) and queues them for delivery.
// Auth: username="apikey", password=cd_live_xxx
//
// Security model:
//   - Every session starts unauthenticated; Mail/Rcpt/Data reject with
//     ErrAuthRequired until AUTH PLAIN succeeds.
//   - Auth requires a valid, non-expired API key. Successful auth pins the
//     session to that user (s.userID + s.apiKeyID).
//   - Data scopes the sending-domain lookup to the authenticated user, so a
//     tenant's key can only send from a domain that tenant owns — even if a
//     different tenant has the same domain verified.
type RelayServer struct {
	server  *gosmtp.Server
	enqueue func(uint)
}

func NewRelayServer(addr string, enqueue func(uint)) *RelayServer {
	rs := &RelayServer{enqueue: enqueue}

	s := gosmtp.NewServer(rs)
	s.Addr = addr
	s.Domain = "mail.lisaos.dev"
	// AllowInsecureAuth permits AUTH PLAIN without STARTTLS. Left enabled
	// so local docker-compose dev works against an unencrypted relay;
	// production deploys must terminate TLS (STARTTLS + cert) at this
	// server to satisfy RFC 4954 §4 — check your deployment config before
	// toggling off.
	s.AllowInsecureAuth = true
	rs.server = s

	return rs
}

func (rs *RelayServer) Start() {
	log.Printf("[smtp-relay] Listening on %s", rs.server.Addr)
	go func() {
		if err := rs.server.ListenAndServe(); err != nil {
			log.Printf("[smtp-relay] Error: %v", err)
		}
	}()
}

// NewSession implements gosmtp.Backend
func (rs *RelayServer) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &relaySession{relay: rs}, nil
}

// relaySession implements go-smtp's AuthSession (Session + AuthMechanisms +
// Auth). The authenticated flag is read on every state-changing verb so the
// empty-slate starting state stays hostile to unauth'd senders.
type relaySession struct {
	relay         *RelayServer
	authenticated bool
	userID        string
	apiKeyID      uint
	from          string
	to            []string
}

// AuthMechanisms advertises SASL mechanisms this session accepts.
// PLAIN is sufficient for password-over-TLS; adding CRAM-MD5 etc. is
// unnecessary when the transport layer is secured.
func (s *relaySession) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

// Auth returns a SASL server for the requested mechanism. The callback
// validates the username/password pair as an api-key credential and only
// flips s.authenticated on success.
func (s *relaySession) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		return nil, fmt.Errorf("unsupported SASL mechanism: %s", mech)
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		// Relay convention: username="apikey" (or "api") with password
		// holding the key. Accept either position if someone wires the
		// key as the username for simpler client config.
		key := password
		if strings.ToLower(username) != "apikey" && strings.ToLower(username) != "api" {
			key = username
		}
		if key == "" {
			return errors.New("missing API key")
		}

		hash := models.HashAPIKey(key)
		var apiKey models.APIKey
		if err := database.DB.Where("key_hash = ?", hash).First(&apiKey).Error; err != nil {
			return &gosmtp.SMTPError{Code: 535, Message: "Invalid API key"}
		}

		// Reject expired keys — they still exist in the DB but must not
		// grant send privilege.
		if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
			return &gosmtp.SMTPError{Code: 535, Message: "API key expired"}
		}

		s.authenticated = true
		s.userID = apiKey.UserID
		s.apiKeyID = apiKey.ID

		// Best-effort last-used update; don't fail the auth if it errors.
		now := time.Now()
		database.DB.Model(&apiKey).Update("last_used_at", &now)
		return nil
	}), nil
}

func (s *relaySession) Mail(from string, opts *gosmtp.MailOptions) error {
	if !s.authenticated {
		return gosmtp.ErrAuthRequired
	}
	s.from = from
	return nil
}

func (s *relaySession) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	if !s.authenticated {
		return gosmtp.ErrAuthRequired
	}
	s.to = append(s.to, to)
	return nil
}

func (s *relaySession) Data(r io.Reader) error {
	if !s.authenticated {
		return gosmtp.ErrAuthRequired
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	subject := extractHeader(data, "Subject")
	fromDomain := s.from
	if idx := strings.LastIndex(fromDomain, "@"); idx >= 0 {
		fromDomain = fromDomain[idx+1:]
	}

	// Scope by user_id so tenant A cannot send as tenant B's verified
	// domain even if both have the same domain entry.
	var domain models.SendingDomain
	err = database.DB.
		Where("domain = ? AND user_id = ? AND status = ?", fromDomain, s.userID, "verified").
		First(&domain).Error
	if err != nil {
		return &gosmtp.SMTPError{Code: 550, Message: "Sending domain not verified for this account: " + fromDomain}
	}

	rawStr := string(data)
	for _, to := range s.to {
		msg := models.Message{
			ExternalID: uuid.New().String(),
			UserID:     s.userID,
			DomainID:   domain.ID,
			APIKeyID:   s.apiKeyID,
			FromEmail:  s.from,
			ToEmail:    to,
			Subject:    subject,
			HTMLBody:   &rawStr,
			Status:     "queued",
		}

		if err := database.DB.Create(&msg).Error; err != nil {
			return &gosmtp.SMTPError{Code: 451, Message: "Failed to queue"}
		}

		database.DB.Create(&models.MessageEvent{MessageID: msg.ID, Type: "queued"})
		s.relay.enqueue(msg.ID)
		log.Printf("[smtp-relay] Queued %s → %s (%s)", s.from, to, subject)
	}

	return nil
}

func (s *relaySession) Reset() {
	s.from = ""
	s.to = nil
	// Intentionally leave authenticated / userID / apiKeyID intact —
	// RFC 5321 RSET only clears the mail transaction, not the session
	// credential. Clearing them here would force re-AUTH after every
	// RSET, which real clients don't do.
}

func (s *relaySession) Logout() error {
	return nil
}

func extractHeader(data []byte, name string) string {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)+":") {
			return strings.TrimSpace(line[len(name)+1:])
		}
		if line == "\r" || line == "" {
			break
		}
	}
	return ""
}
