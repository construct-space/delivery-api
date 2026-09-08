package handlers

import "strings"

// Construct-branded email layout. Mirrors the chrome accounts uses for its
// own transactional sends (login codes, security alerts, etc.) — copy lives
// here so delivery can evolve independently. Default layout for /api/emails
// when callers don't pass `layout`; the wordmark text comes from the `space`
// field on the send payload (defaults to "CONSTRUCT") so each space brands
// its own mail without a custom logo upload.

// markURL is the bare Construct mark (just the O + dash, no wordmark).
// The wordmark is rendered as HTML text next to it so every space can set
// its own. Upload this PNG to lisaos.dev/mark.png; until it lives there
// the email shows the alt text as a fallback.
const markURL = "https://lisaos.dev/mark.png"

// constructLayout wraps the caller's HTML body in a Construct-branded
// table-based email shell: mark + space wordmark, white card with the
// subject as the H1, neutral footer. Single column, max width 520px,
// Rubik with a stack fallback so Outlook/Apple Mail render acceptably
// without web fonts.
//
// `space` is the wordmark text shown next to the mark (e.g. "WEATHER",
// "NOTES"). When empty, falls back to "CONSTRUCT" so platform-sent mail
// (password resets etc.) keeps the existing chrome.
func constructLayout(space, title, content string) string {
	wordmark := strings.ToUpper(strings.TrimSpace(space))
	if wordmark == "" {
		wordmark = "CONSTRUCT"
	}
	return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<meta name="color-scheme" content="light"/>
<meta name="supported-color-schemes" content="light"/>
<title>` + title + `</title>
<!--[if !mso]><!-->
<link href="https://fonts.googleapis.com/css2?family=Rubik:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<!--<![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#f3f4f6;-webkit-font-smoothing:antialiased;font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">

<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f3f4f6">
<tr><td align="center" style="padding:48px 16px">

<table width="520" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;width:100%">

<!-- Mark + space wordmark -->
<tr><td style="padding:0 0 24px">
	<table cellpadding="0" cellspacing="0" border="0">
		<tr>
			<td style="padding-right:12px;vertical-align:middle">
				<img src="` + markURL + `" alt="Construct" width="32" height="32" style="display:block;border:0;outline:none"/>
			</td>
			<td style="vertical-align:middle">
				<span style="font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:18px;font-weight:600;color:#9ca3af;letter-spacing:1.5px">` + wordmark + `</span>
			</td>
		</tr>
	</table>
</td></tr>

<!-- Card -->
<tr><td style="background-color:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden">
<table width="100%" cellpadding="0" cellspacing="0" border="0">

<tr><td style="padding:40px 40px 0">
	<h1 style="margin:0 0 24px;font-size:24px;font-weight:600;color:#111827;font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">` + title + `</h1>
</td></tr>

<tr><td style="padding:0 40px 40px">
	` + content + `
</td></tr>

</table>
</td></tr>

<!-- Footer -->
<tr><td style="padding:28px 0 0" align="center">
	<p style="margin:0 0 8px;font-size:12px;color:#9ca3af;font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.5">
		Sent through Construct Delivery on behalf of the application that owns the sending domain.<br/>
		Reply directly to this address only if the sender's space supports replies.
	</p>
	<p style="margin:0;font-size:12px;color:#d1d5db;font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
		<a href="https://lisaos.dev" style="color:#d1d5db;text-decoration:none">lisaos.dev</a>
	</p>
</td></tr>

</table>

</td></tr>
</table>

</body>
</html>`
}

// Layout dispatcher — returns the wrapped html for the named layout. Empty
// `name` defaults to "construct" (so spaces ship branded mail without
// thinking about it); explicit `none` bypasses for callers shipping their
// own pre-styled HTML (Ghost campaigns, Mailchimp templates, etc.). `space`
// is the wordmark text rendered next to the Construct mark. Subject doubles
// as the page <title> and the H1 inside the card.
func applyLayout(name, space, subject, html string) string {
	switch name {
	case "", "construct":
		return constructLayout(space, subject, html)
	case "none":
		return html
	default:
		return html
	}
}

// sharedSendingDomain returns the Construct-owned domain that any
// authenticated caller is permitted to send From without per-user
// verification (e.g. "delivery.lisaos.dev"). Empty disables the shared path.
func sharedSendingDomain() string {
	if Cfg == nil {
		return ""
	}
	return Cfg.SharedSendingDomain
}
