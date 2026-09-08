package smtp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Sender handles outbound SMTP delivery.
type Sender struct {
	hostname string // EHLO hostname
	signer   *DKIMSigner
}

func NewSender(hostname string, signer *DKIMSigner) *Sender {
	return &Sender{hostname: hostname, signer: signer}
}

// Send delivers an email message to the recipient's MX server.
// The message should be a fully-formed RFC 5322 email (headers + body).
func (s *Sender) Send(from, to string, rawMsg []byte) error {
	// Extract domain from recipient
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient: %s", to)
	}
	rcptDomain := parts[1]

	// DKIM sign the message
	fromDomain := from
	if idx := strings.Index(from, "@"); idx >= 0 {
		fromDomain = from[idx+1:]
	}

	signed, err := s.signer.Sign(fromDomain, rawMsg)
	if err != nil {
		log.Printf("[smtp] DKIM sign warning for %s: %v (sending unsigned)", fromDomain, err)
		signed = rawMsg // send unsigned if no key
	}

	// Resolve MX records
	mxRecords, err := net.LookupMX(rcptDomain)
	if err != nil || len(mxRecords) == 0 {
		// Fallback to A record
		mxRecords = []*net.MX{{Host: rcptDomain, Pref: 10}}
	}

	// Try each MX in priority order
	var lastErr error
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		addr := host + ":25"

		err := s.sendToMX(addr, from, to, signed)
		if err == nil {
			return nil
		}
		lastErr = err
		log.Printf("[smtp] Failed to send via %s: %v", addr, err)
	}

	return fmt.Errorf("all MX servers failed for %s: %v", rcptDomain, lastErr)
}

func (s *Sender) sendToMX(addr, from, to string, msg []byte) error {
	// Connect with timeout — force IPv4 (IPv6 requires separate PTR records)
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := dialer.Dial("tcp4", addr)
	if err != nil {
		return fmt.Errorf("connect %s: %w", addr, err)
	}

	mxHost := strings.Split(addr, ":")[0]
	client, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	// EHLO
	if err := client.Hello(s.hostname); err != nil {
		return fmt.Errorf("ehlo: %w", err)
	}

	// STARTTLS if supported
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{ServerName: mxHost}
		if err := client.StartTLS(tlsConfig); err != nil {
			log.Printf("[smtp] STARTTLS failed for %s (continuing without): %v", addr, err)
		}
	}

	// MAIL FROM
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}

	// RCPT TO
	if err := client.Rcpt(to); err != nil {
		return &SMTPError{Code: parseCode(err), Msg: err.Error(), Permanent: isPermanent(err)}
	}

	// DATA
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}

	if _, err := bytes.NewReader(msg).WriteTo(w); err != nil {
		w.Close()
		return fmt.Errorf("write: %w", err)
	}

	if err := w.Close(); err != nil {
		return &SMTPError{Code: parseCode(err), Msg: err.Error(), Permanent: isPermanent(err)}
	}

	return client.Quit()
}

// SMTPError represents an SMTP error with status code.
type SMTPError struct {
	Code      int
	Msg       string
	Permanent bool // true = 5xx, false = 4xx
}

func (e *SMTPError) Error() string {
	return fmt.Sprintf("SMTP %d: %s", e.Code, e.Msg)
}

func parseCode(err error) int {
	msg := err.Error()
	if len(msg) >= 3 {
		code := 0
		for i := 0; i < 3; i++ {
			if msg[i] >= '0' && msg[i] <= '9' {
				code = code*10 + int(msg[i]-'0')
			} else {
				return 0
			}
		}
		return code
	}
	return 0
}

func isPermanent(err error) bool {
	code := parseCode(err)
	return code >= 500 && code < 600
}
