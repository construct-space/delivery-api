package smtp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

// Attachment is one file attached to an outgoing message. Content holds
// the raw bytes (already base64-decoded by the caller); BuildMessage
// re-encodes for transport.
type Attachment struct {
	Filename    string
	ContentType string
	Content     []byte
}

// BuildMessage constructs an RFC 5322 email from the given parameters.
// When attachments is non-empty, the body is wrapped in multipart/mixed
// with the original alternative body as the first part and each
// attachment as a base64-encoded subsequent part.
func BuildMessage(from, fromName, to, subject, htmlBody, textBody string, extraHeaders map[string]string, attachments []Attachment) []byte {
	var b strings.Builder

	// SECURITY: strip CR/LF (and NUL) from every value that lands in a
	// header. Header values are single-line; an unstripped "\r\n" lets a
	// caller inject arbitrary headers (Bcc exfiltration, forged Reply-To)
	// or split into the body — and since From is forced to the trusted,
	// DKIM-signed Construct domain, injected mail would ship signed.
	from = stripHeaderInjection(from)
	fromName = stripHeaderInjection(fromName)
	to = stripHeaderInjection(to)
	subject = stripHeaderInjection(subject)

	// Message-ID
	msgID := generateMessageID(extractDomain(from))

	// From
	if fromName != "" {
		b.WriteString(fmt.Sprintf("From: %s\r\n", mime.QEncoding.Encode("utf-8", fromName)+" <"+from+">"))
	} else {
		b.WriteString(fmt.Sprintf("From: %s\r\n", from))
	}

	// To
	b.WriteString(fmt.Sprintf("To: %s\r\n", to))

	// Subject
	b.WriteString(fmt.Sprintf("Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject)))

	// Date
	b.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))

	// Message-ID
	b.WriteString(fmt.Sprintf("Message-ID: <%s>\r\n", msgID))

	// MIME
	b.WriteString("MIME-Version: 1.0\r\n")

	// List-Unsubscribe (Gmail rewards this)
	b.WriteString(fmt.Sprintf("List-Unsubscribe: <mailto:unsubscribe@%s?subject=unsubscribe>\r\n", extractDomain(from)))
	b.WriteString("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n")

	// Extra headers — sanitize key + value and skip malformed keys so a
	// caller-supplied map can't inject extra headers or a body break.
	for k, v := range extraHeaders {
		k = stripHeaderInjection(k)
		v = stripHeaderInjection(v)
		if k == "" || strings.ContainsAny(k, ": \t") {
			continue
		}
		b.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	// Body assembly. Three cases:
	//   1. No attachments → existing path (alt-body or plain)
	//   2. Has attachments → multipart/mixed wrapping (alt-body) + each file
	if htmlBody != "" && textBody == "" {
		textBody = htmlToPlainText(htmlBody)
	}
	bodyPart := buildBodyPart(htmlBody, textBody)

	if len(attachments) == 0 {
		b.WriteString(bodyPart)
	} else {
		mixed := generateBoundary()
		b.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", mixed))
		b.WriteString("\r\n")
		b.WriteString(fmt.Sprintf("--%s\r\n", mixed))
		b.WriteString(bodyPart)
		for _, att := range attachments {
			b.WriteString(fmt.Sprintf("\r\n--%s\r\n", mixed))
			ct := att.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			fname := mime.QEncoding.Encode("utf-8", att.Filename)
			b.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", ct, fname))
			b.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", fname))
			b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
			b.WriteString(base64Wrap(string(att.Content)))
		}
		b.WriteString(fmt.Sprintf("\r\n--%s--\r\n", mixed))
	}

	return []byte(b.String())
}

// buildBodyPart returns the headers + body for either a single text/plain
// part or a multipart/alternative (text + html). Used both standalone and
// as the first part of a multipart/mixed envelope when there are
// attachments.
func buildBodyPart(htmlBody, textBody string) string {
	var b strings.Builder
	if htmlBody != "" && textBody != "" {
		boundary := generateBoundary()
		b.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
		b.WriteString("\r\n")
		b.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(base64Wrap(textBody))
		b.WriteString(fmt.Sprintf("\r\n--%s\r\n", boundary))
		b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(base64Wrap(htmlBody))
		b.WriteString(fmt.Sprintf("\r\n--%s--\r\n", boundary))
	} else {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(base64Wrap(textBody))
	}
	return b.String()
}

// stripHeaderInjection removes CR, LF and NUL so a caller-supplied value
// can't break out of its header line. Applied to every header field built
// from external input.
func stripHeaderInjection(s string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(s)
}

func extractDomain(email string) string {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		if idx := strings.LastIndex(email, "@"); idx >= 0 {
			return email[idx+1:]
		}
		return "localhost"
	}
	if idx := strings.LastIndex(addr.Address, "@"); idx >= 0 {
		return addr.Address[idx+1:]
	}
	return "localhost"
}

func generateMessageID(domain string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x.%d@%s", b, time.Now().UnixNano(), domain)
}

func generateBoundary() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("----=_Part_%x", b)
}

// htmlToPlainText derives a text/plain version from an HTML body. Not a
// full HTML-to-text converter — strips scripts/styles, collapses tags to
// whitespace, decodes the most common entities, and squashes runs of
// whitespace. Good enough for the transactional bodies we ship (mostly
// short paragraphs) and for the spam-filter heuristic we care about
// (does the message have a text/plain alternative).
func htmlToPlainText(html string) string {
	s := html
	s = htmlScriptStyleRe.ReplaceAllString(s, "")
	s = htmlBlockEndRe.ReplaceAllString(s, "\n")
	s = htmlBrRe.ReplaceAllString(s, "\n")
	s = htmlTagRe.ReplaceAllString(s, " ")
	s = strings.NewReplacer(
		"&nbsp;", " ",
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", `"`,
		"&#39;", "'",
	).Replace(s)
	s = htmlMultiSpaceRe.ReplaceAllString(s, " ")
	s = htmlMultiNewlineRe.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

var (
	htmlScriptStyleRe  = regexp.MustCompile(`(?is)<(script|style)[^>]*>.*?</(script|style)>`)
	htmlBlockEndRe     = regexp.MustCompile(`(?i)</(p|div|tr|li|h[1-6])\s*>`)
	htmlBrRe           = regexp.MustCompile(`(?i)<br\s*/?>`)
	htmlTagRe          = regexp.MustCompile(`<[^>]*>`)
	htmlMultiSpaceRe   = regexp.MustCompile(`[ \t]+`)
	htmlMultiNewlineRe = regexp.MustCompile(`\n{3,}`)
)

// base64Wrap encodes data as base64 and wraps lines at 76 characters per RFC 2045.
func base64Wrap(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	var wrapped strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		wrapped.WriteString(encoded[i:end])
		wrapped.WriteString("\r\n")
	}
	return wrapped.String()
}
