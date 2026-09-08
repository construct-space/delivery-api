package main

import (
	"log"
	"net/http"
	"slices"
	"time"

	"construct/delivery/internal/config"
	"construct/delivery/internal/database"
	"construct/delivery/internal/dns"
	"construct/delivery/internal/handlers"
	"construct/delivery/internal/middleware"
	"construct/delivery/internal/push"
	"construct/delivery/internal/queue"
	smtpPkg "construct/delivery/internal/smtp"
	"construct/delivery/internal/sse"
)

func main() {
	cfg := config.Load()
	handlers.Cfg = cfg

	// Database
	database.Init(cfg)

	// Load DKIM keys for all verified domains
	signer := smtpPkg.NewDKIMSigner()
	loadDKIMKeys(signer)

	// SMTP sender
	sender := smtpPkg.NewSender(cfg.Hostname, signer)

	// Message queue
	q := queue.New(sender, cfg.WarmupMaxPerHour)
	q.Start(5)
	handlers.MessageQueue = q

	// Notifications: in-process SSE hub + push dispatcher (web + mobile).
	// Each push driver is a no-op if its env config is missing, so this is
	// safe to wire unconditionally.
	handlers.NotifHub = sse.NewHub()
	webPush := push.NewWebPush(cfg.VAPIDPublicKey, cfg.VAPIDPrivateKey, cfg.VAPIDSubject)
	fcm := push.NewFCM(cfg.FCMCredentialsJSON)
	handlers.NotifWebPush = webPush
	handlers.NotifDispatcher = push.New(webPush, fcm)

	// Cloudflare DNS integration
	if cfg.CloudflareToken != "" {
		handlers.CloudflareClient = dns.NewCloudflareClient(cfg.CloudflareToken)
		log.Println("[dns] Cloudflare auto-DNS enabled")
	}

	// Routes
	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		handlers.WriteJSON(w, 200, map[string]any{"status": "ok", "queue": q.Stats()})
	})

	// OAuth auth (login with Construct)
	mux.HandleFunc("GET /api/auth/login", handlers.LoginRedirect)
	mux.HandleFunc("GET /api/auth/callback", handlers.AuthCallback)
	mux.HandleFunc("GET /api/auth/me", handlers.AuthMe)
	mux.HandleFunc("GET /api/auth/logout", handlers.AuthLogout)

	// Send + status. WithAuth covers all three identity paths: my.lisaos.dev
	// gateway (X-Internal-Secret + X-Auth-User-ID) so spaces can call from the
	// browser via /api/delivery/*; legacy session cookie; and tenant API keys
	// (Bearer cd_live_…) for programmatic callers (Ghost, server-side).
	mux.HandleFunc("POST /api/emails", handlers.WithAuth(handlers.SendEmail))
	mux.HandleFunc("GET /api/emails/{id}", handlers.WithAuth(handlers.GetMessage))

	// Service-to-service (for accounts, billing, etc.)
	if cfg.ServiceAPIKey != "" {
		svcAuth := middleware.ServiceAuth(cfg.ServiceAPIKey)
		mux.Handle("POST /api/service/send", svcAuth(http.HandlerFunc(handlers.ServiceSend)))
	}

	// Domain management (session auth for dashboard, API key for programmatic)
	mux.HandleFunc("GET /api/domains", handlers.WithAuth(handlers.ListDomains))
	mux.HandleFunc("POST /api/domains", handlers.WithAuth(handlers.CreateDomain))
	mux.HandleFunc("GET /api/domains/{id}", handlers.WithAuth(handlers.GetDomain))
	mux.HandleFunc("DELETE /api/domains/{id}", handlers.WithAuth(handlers.DeleteDomain))
	mux.HandleFunc("GET /api/domains/{id}/messages", handlers.WithAuth(handlers.DomainMessages))
	mux.HandleFunc("POST /api/domains/{id}/verify", handlers.WithAuth(handlers.VerifyDomain))
	mux.HandleFunc("GET /api/domains/{id}/dns-records", handlers.WithAuth(handlers.GetDNSRecords))
	mux.HandleFunc("GET /api/domains/{id}/dns-provider", handlers.WithAuth(handlers.CheckDNSProvider))
	mux.HandleFunc("POST /api/domains/{id}/auto-dns", handlers.WithAuth(handlers.AutoSetupDNS))

	// API key management
	mux.HandleFunc("GET /api/keys", handlers.WithAuth(handlers.ListAPIKeys))
	mux.HandleFunc("POST /api/keys", handlers.WithAuth(handlers.CreateAPIKey))

	// Messages (dashboard)
	mux.HandleFunc("GET /api/messages", handlers.WithAuth(handlers.ListMessages))

	// Admin routes (shared-secret auth via X-Internal-Secret)
	adminAuth := middleware.AdminAuth
	mux.Handle("GET /api/admin/stats", adminAuth(http.HandlerFunc(handlers.AdminStats)))
	mux.Handle("GET /api/admin/messages", adminAuth(http.HandlerFunc(handlers.AdminListMessages)))
	mux.Handle("GET /api/admin/domains", adminAuth(http.HandlerFunc(handlers.AdminListDomains)))
	mux.Handle("GET /api/admin/domains/{id}", adminAuth(http.HandlerFunc(handlers.AdminGetDomain)))
	mux.Handle("GET /api/admin/domains/{id}/dns-records", adminAuth(http.HandlerFunc(handlers.AdminGetDomainDNS)))
	mux.Handle("GET /api/admin/domains/{id}/messages", adminAuth(http.HandlerFunc(handlers.AdminGetDomainMessages)))
	mux.Handle("POST /api/admin/domains/{id}/verify", adminAuth(http.HandlerFunc(handlers.AdminVerifyDomain)))
	mux.Handle("GET /api/admin/keys", adminAuth(http.HandlerFunc(handlers.AdminListKeys)))
	mux.Handle("GET /api/admin/tenants", adminAuth(http.HandlerFunc(handlers.AdminListTenants)))
	mux.Handle("GET /api/admin/notifications", adminAuth(http.HandlerFunc(handlers.AdminListNotifications)))
	mux.Handle("GET /api/admin/notifications/stats", adminAuth(http.HandlerFunc(handlers.AdminNotificationStats)))
	mux.Handle("POST /api/admin/notifications/test", adminAuth(http.HandlerFunc(handlers.AdminSendTestNotification)))

	// Tenant enrollment — reachable via the my.lisaos.dev gateway
	// (POST/DELETE /api/delivery/enroll). Uses WithAuth so the caller's
	// identity comes from gateway injection (X-Auth-User-ID) or a legacy
	// session cookie.
	mux.HandleFunc("POST /api/enroll", handlers.WithAuth(handlers.EnrollDelivery))
	mux.HandleFunc("DELETE /api/enroll", handlers.WithAuth(handlers.UnenrollDelivery))

	// Internal server-to-server — gated by X-Internal-Secret inside the
	// handler. Never forwarded through the gateway (no /internal/ route).
	mux.HandleFunc("GET /internal/tenant-status", handlers.InternalTenantStatus)

	// Notifications — internal callers (other Construct services) emit
	// events through ServiceNotify with X-Internal-Secret. End users read,
	// stream, and configure via /api/notifications/* with WithAuth.
	mux.HandleFunc("POST /internal/notify", handlers.ServiceNotify)

	mux.HandleFunc("GET /api/notifications", handlers.WithAuth(handlers.ListNotifications))
	mux.HandleFunc("GET /api/notifications/unread-count", handlers.WithAuth(handlers.UnreadCount))
	mux.HandleFunc("GET /api/notifications/stream", handlers.WithAuth(handlers.StreamNotifications))
	mux.HandleFunc("GET /api/notifications/ws", handlers.WithAuthOrQueryToken(handlers.WSStreamNotifications))
	// /api/devices/relay and /api/operator/status moved to source-api on
	// 2026-05-20 — the device bus lives in source now (delivery keeps
	// notifications + email only). Clients hit /api/device-bus/* via the
	// my.lisaos.dev gateway.
	mux.HandleFunc("POST /api/notifications/self", handlers.WithAuth(handlers.SelfNotify))
	mux.HandleFunc("POST /api/notifications/read-all", handlers.WithAuth(handlers.MarkAllRead))
	mux.HandleFunc("POST /api/notifications/{id}/read", handlers.WithAuth(handlers.MarkRead))
	mux.HandleFunc("DELETE /api/notifications/{id}", handlers.WithAuth(handlers.DeleteNotification))

	mux.HandleFunc("GET /api/notifications/vapid-public-key", handlers.VAPIDPublicKey)
	mux.HandleFunc("POST /api/notifications/web-push", handlers.WithAuth(handlers.RegisterWebPush))
	mux.HandleFunc("DELETE /api/notifications/web-push", handlers.WithAuth(handlers.UnregisterWebPush))

	mux.HandleFunc("POST /api/notifications/devices", handlers.WithAuth(handlers.RegisterDevice))
	mux.HandleFunc("DELETE /api/notifications/devices", handlers.WithAuth(handlers.UnregisterDevice))

	mux.HandleFunc("GET /api/notifications/preferences", handlers.WithAuth(handlers.GetPreferences))
	mux.HandleFunc("PUT /api/notifications/preferences", handlers.WithAuth(handlers.UpdatePreferences))

	// Minimal root handler — JSON identity. The SPA used to live here; it's
	// now shipped as the construct-space/delivery repo and deployed at
	// https://delivery.lisaos.dev. API-only service from here on.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		handlers.WriteJSON(w, 200, map[string]any{"service": "delivery-api", "status": "ok"})
	})

	// CORS middleware
	handler := corsMiddleware(cfg, mux)

	// SMTP Relay (port 587 for Ghost, etc.)
	relay := smtpPkg.NewRelayServer(":"+cfg.SMTPRelayPort, q.Enqueue)
	relay.Start()

	log.Printf("[delivery] ConstructDelivery starting on :%s", cfg.Port)
	log.Printf("[delivery] Hostname: %s | DKIM selector: %s", cfg.Hostname, cfg.DKIMSelector)
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func loadDKIMKeys(signer *smtpPkg.DKIMSigner) {
	type domainRow struct {
		Domain         string
		DKIMSelector   string
		DKIMPrivateKey string
	}
	var domains []domainRow
	database.DB.Table("sending_domains").Where("status = ? AND dkim_private_key != ''", "verified").Find(&domains)

	for _, d := range domains {
		if err := signer.LoadKey(d.Domain, d.DKIMSelector, d.DKIMPrivateKey); err != nil {
			log.Printf("[dkim] Failed to load key for %s: %v", d.Domain, err)
		} else {
			log.Printf("[dkim] Loaded key for %s", d.Domain)
		}
	}
}

func corsMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if slices.Contains(cfg.AllowedOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}
