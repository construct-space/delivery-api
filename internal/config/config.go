package config

import (
	"bufio"
	"os"
	"strings"
)

type Config struct {
	Port             string
	AppURL           string
	AllowedOrigins   []string
	DBDriver         string
	DBHost           string
	DBPort           string
	DBName           string
	DBUser           string
	DBPass           string
	OAuthURL         string
	OAuthClientID    string
	OAuthClientSecret string
	OAuthRedirectURI string
	// AccountsURL is the base URL of the accounts service that delivery
	// calls to validate cat_* identity bearers (POST /internal/validate-token).
	// Defaults to the public hostname so cross-VPS deploys work without
	// extra wiring; override with ACCOUNTS_URL env in environments where
	// accounts is reachable on a private network address.
	AccountsURL      string
	ServiceAPIKey    string
	// InternalSharedSecret is the shared secret injected by the
	// my.lisaos.dev gateway on every proxied request (as X-Internal-Secret).
	// When set and matching on the request header, delivery trusts the
	// gateway-provided X-Auth-User-ID headers. Accepts either the unified
	// INTERNAL_SHARED_SECRET env or the legacy SERVICE_API_KEY for
	// backwards compat with older deploys.
	InternalSharedSecret string
	// SharedSendingDomain — for v1 every authenticated caller can send From a
	// single Construct-owned domain (e.g. "delivery.lisaos.dev") without
	// verifying their own. Per-user verified domains stay supported and
	// always win when they match the From address. Set to "" to disable
	// the shared path.
	SharedSendingDomain string
	SMTPRelayPort    string
	DKIMSelector     string
	WarmupMaxPerHour int
	ServerIP         string
	Hostname         string
	CloudflareToken  string
	// Web push (VAPID). All three must be set for web push to be enabled.
	// Generate keys once with `webpush-go` CLI or any VAPID generator and
	// store them in the deploy secrets. VAPIDSubject is a mailto: contact.
	VAPIDPublicKey   string
	VAPIDPrivateKey  string
	VAPIDSubject     string
	// Mobile push via FCM. The credentials JSON is the service-account file
	// downloaded from the Firebase console. Either pass the raw JSON via
	// FCM_CREDENTIALS_JSON or a path via FCM_CREDENTIALS_FILE.
	FCMCredentialsJSON string
}

func Load() *Config {
	loadEnvFile(".env")

	// SDK callers (the desktop app + any space using useDelivery()) hit
	// delivery.lisaos.dev directly with a `cat_*` Bearer instead of going
	// through the my.lisaos.dev gateway. Allow their origins so the
	// browser releases the response body. ALLOWED_ORIGINS env still wins
	// when set; otherwise these defaults apply.
	defaultOrigins := []string{
		"https://my.lisaos.dev",
		"http://localhost:60200",   // construct-app dev (Vite)
		"http://localhost:3000",    // my-web dev
		"http://localhost:1420",    // alternate Tauri dev port
		"tauri://localhost",        // Tauri WKWebView (macOS)
		"http://tauri.localhost",   // Tauri WebView2 (Windows)
		"https://tauri.localhost",  // Tauri WKWebView fallback
	}
	originsRaw := env("ALLOWED_ORIGINS", strings.Join(defaultOrigins, ","))
	origins := strings.Split(originsRaw, ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	warmup := 50
	if v := env("WARMUP_MAX_PER_HOUR", ""); v != "" {
		var n int
		for _, c := range v {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 {
			warmup = n
		}
	}

	return &Config{
		Port:              env("PORT", "8005"),
		AppURL:            env("APP_URL", "http://localhost:8005"),
		AllowedOrigins:    origins,
		DBDriver:          env("DB_DRIVER", "postgres"),
		DBHost:            env("DB_HOST", "localhost"),
		DBPort:            env("DB_PORT", "5432"),
		DBName:            env("DB_NAME", "construct_delivery"),
		DBUser:            env("DB_USER", "postgres"),
		DBPass:            env("DB_PASS", ""),
		OAuthURL:          env("OAUTH_URL", "https://api.lisaos.dev"),
		OAuthClientID:     env("OAUTH_CLIENT_ID", "construct_delivery"),
		OAuthClientSecret: env("OAUTH_CLIENT_SECRET", ""),
		OAuthRedirectURI:  env("OAUTH_REDIRECT_URI", "http://localhost:8005/api/auth/callback"),
		// AccountsURL points at the my.lisaos.dev gateway by default
		// because that's the only public surface that hits the accounts DB
		// where SDK-issued cat_* tokens actually live. api.lisaos.dev
		// is a separate accounts deployment with a different DB and won't
		// recognize tokens minted via the gateway's OAuth flow.
		AccountsURL:       env("ACCOUNTS_URL", "https://my.lisaos.dev"),
		ServiceAPIKey:     env("SERVICE_API_KEY", ""),
		InternalSharedSecret: env("INTERNAL_SHARED_SECRET", env("SERVICE_API_KEY", "")),
		SharedSendingDomain: env("SHARED_SENDING_DOMAIN", "delivery.lisaos.dev"),
		SMTPRelayPort:     env("SMTP_RELAY_PORT", "587"),
		DKIMSelector:      env("DKIM_SELECTOR", "cd"),
		WarmupMaxPerHour:  warmup,
		ServerIP:          env("SERVER_IP", ""),
		Hostname:          env("HOSTNAME", "mail.lisaos.dev"),
		CloudflareToken:   env("CLOUDFLARE_API_TOKEN", ""),
		VAPIDPublicKey:    env("VAPID_PUBLIC_KEY", ""),
		VAPIDPrivateKey:   env("VAPID_PRIVATE_KEY", ""),
		VAPIDSubject:      env("VAPID_SUBJECT", ""),
		FCMCredentialsJSON: loadFCMCredentials(),
	}
}

// loadFCMCredentials prefers FCM_CREDENTIALS_JSON (raw JSON), falling back
// to FCM_CREDENTIALS_FILE (path on disk). Returns "" if neither is set so
// the FCM driver stays disabled.
func loadFCMCredentials() string {
	if v := os.Getenv("FCM_CREDENTIALS_JSON"); v != "" {
		return v
	}
	if path := os.Getenv("FCM_CREDENTIALS_FILE"); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			return string(b)
		}
	}
	return ""
}

func (c *Config) IsSecure() bool {
	return strings.HasPrefix(c.AppURL, "https")
}

func (c *Config) CookieDomain() string {
	host := c.AppURL
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	if host == "localhost" || host == "127.0.0.1" {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return "." + strings.Join(parts[len(parts)-2:], ".")
	}
	return ""
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
}
