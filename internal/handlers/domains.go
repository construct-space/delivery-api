package handlers

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"construct/delivery/internal/crypto"
	"construct/delivery/internal/database"
	"construct/delivery/internal/dns"
	"construct/delivery/internal/models"
)

var CloudflareClient *dns.CloudflareClient

// CreateDomain handles POST /api/domains
func CreateDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := parseBody(r, &req); err != nil || req.Domain == "" {
		WriteJSON(w, 400, map[string]string{"error": "domain is required"})
		return
	}

	userID := GetUserIDFromContext(r)
	domain := strings.ToLower(strings.TrimSpace(req.Domain))

	// Check if already exists
	var count int64
	database.DB.Model(&models.SendingDomain{}).Where("domain = ?", domain).Count(&count)
	if count > 0 {
		WriteJSON(w, 409, map[string]string{"error": "domain already registered"})
		return
	}

	// Generate DKIM key pair
	privPEM, pubBase64, err := crypto.GenerateDKIMKeyPair()
	if err != nil {
		WriteJSON(w, 500, map[string]string{"error": "failed to generate DKIM keys"})
		return
	}

	d := models.SendingDomain{
		UserID:         userID,
		Domain:         domain,
		Status:         "pending",
		DKIMPrivateKey: privPEM,
		DKIMPublicKey:  pubBase64,
		DKIMSelector:   Cfg.DKIMSelector,
	}

	if err := database.DB.Create(&d).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "failed to create domain"})
		return
	}

	WriteJSON(w, 201, map[string]any{
		"domain":      d,
		"dns_records": dnsRecords(d),
	})
}

// ListDomains handles GET /api/domains
func ListDomains(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	var domains []models.SendingDomain
	database.DB.Where("user_id = ?", userID).Order("created_at desc").Find(&domains)
	WriteJSON(w, 200, map[string]any{"domains": domains})
}

// GetDomain handles GET /api/domains/{id}
func GetDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := GetUserIDFromContext(r)

	var d models.SendingDomain
	if err := database.DB.Where("id = ? AND user_id = ?", id, userID).First(&d).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}

	WriteJSON(w, 200, map[string]any{
		"domain":      d,
		"dns_records": dnsRecords(d),
	})
}

// VerifyDomain handles POST /api/domains/{id}/verify
func VerifyDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := GetUserIDFromContext(r)

	var d models.SendingDomain
	if err := database.DB.Where("id = ? AND user_id = ?", id, userID).First(&d).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}

	// Check DKIM
	dkimHost := d.DKIMSelector + "._domainkey." + d.Domain
	txtRecords, _ := net.LookupTXT(dkimHost)
	d.DKIMVerified = false
	for _, txt := range txtRecords {
		if strings.Contains(txt, d.DKIMPublicKey[:40]) {
			d.DKIMVerified = true
			break
		}
	}

	// Check SPF
	txtRecords, _ = net.LookupTXT(d.Domain)
	d.SPFVerified = false
	for _, txt := range txtRecords {
		if strings.Contains(txt, "v=spf1") && (strings.Contains(txt, Cfg.ServerIP) || strings.Contains(txt, Cfg.Hostname)) {
			d.SPFVerified = true
			break
		}
	}

	// Check DMARC
	txtRecords, _ = net.LookupTXT("_dmarc." + d.Domain)
	d.DMARCVerified = false
	for _, txt := range txtRecords {
		if strings.Contains(txt, "v=DMARC1") {
			d.DMARCVerified = true
			break
		}
	}

	// Update status
	if d.DKIMVerified && d.SPFVerified {
		d.Status = "verified"
	} else {
		d.Status = "pending"
	}

	database.DB.Save(&d)

	WriteJSON(w, 200, map[string]any{
		"domain":      d,
		"dns_records": dnsRecords(d),
	})
}

// GetDNSRecords handles GET /api/domains/{id}/dns-records
func GetDNSRecords(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := GetUserIDFromContext(r)

	var d models.SendingDomain
	if err := database.DB.Where("id = ? AND user_id = ?", id, userID).First(&d).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}

	WriteJSON(w, 200, map[string]any{"dns_records": dnsRecords(d)})
}

// CheckDNSProvider handles GET /api/domains/{id}/dns-provider
// Returns whether the domain uses Cloudflare, Porkbun, or other NS.
func CheckDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := GetUserIDFromContext(r)

	var d models.SendingDomain
	if err := database.DB.Where("id = ? AND user_id = ?", id, userID).First(&d).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}

	ns, _ := net.LookupNS(d.Domain)
	provider := "unknown"
	cloudflare := false
	var nameservers []string

	for _, n := range ns {
		nameservers = append(nameservers, n.Host)
		host := strings.ToLower(n.Host)
		if strings.Contains(host, "cloudflare") {
			provider = "cloudflare"
			cloudflare = true
		} else if strings.Contains(host, "porkbun") {
			provider = "porkbun"
		} else if strings.Contains(host, "google") {
			provider = "google"
		} else if strings.Contains(host, "awsdns") {
			provider = "aws"
		}
	}

	WriteJSON(w, 200, map[string]any{
		"domain":      d.Domain,
		"provider":    provider,
		"cloudflare":  cloudflare,
		"nameservers": nameservers,
		"auto_dns":    cloudflare && CloudflareClient != nil,
	})
}

// AutoSetupDNS handles POST /api/domains/{id}/auto-dns
// One-click Cloudflare DNS setup — creates all required records automatically.
func AutoSetupDNS(w http.ResponseWriter, r *http.Request) {
	if CloudflareClient == nil {
		WriteJSON(w, 400, map[string]string{"error": "Cloudflare integration not configured"})
		return
	}

	id := r.PathValue("id")
	userID := GetUserIDFromContext(r)

	var d models.SendingDomain
	if err := database.DB.Where("id = ? AND user_id = ?", id, userID).First(&d).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}

	created, errors := CloudflareClient.SetupDomainRecords(
		d.Domain,
		d.DKIMSelector,
		d.DKIMPublicKey,
		Cfg.ServerIP,
	)

	// Auto-verify after setup
	var errMsgs []string
	for _, e := range errors {
		errMsgs = append(errMsgs, e.Error())
	}

	if len(errors) == 0 {
		// All records created, verify
		d.DKIMVerified = true
		d.SPFVerified = true
		d.DMARCVerified = true
		d.Status = "verified"
		database.DB.Save(&d)
	}

	WriteJSON(w, 200, map[string]any{
		"domain":  d,
		"created": created,
		"errors":  errMsgs,
	})
}

// DomainMessages handles GET /api/domains/{id}/messages
func DomainMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := GetUserIDFromContext(r)

	var d models.SendingDomain
	if err := database.DB.Where("id = ? AND user_id = ?", id, userID).First(&d).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}

	var msgs []models.Message
	database.DB.Where("domain_id = ? AND user_id = ?", d.ID, userID).Order("created_at desc").Limit(100).Find(&msgs)
	WriteJSON(w, 200, map[string]any{"messages": msgs})
}

// DeleteDomain handles DELETE /api/domains/{id}
func DeleteDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := GetUserIDFromContext(r)

	var d models.SendingDomain
	if err := database.DB.Where("id = ? AND user_id = ?", id, userID).First(&d).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}

	database.DB.Delete(&d)
	WriteJSON(w, 200, map[string]string{"deleted": d.Domain})
}

func dnsRecords(d models.SendingDomain) []map[string]string {
	return []map[string]string{
		{
			"type":     "TXT",
			"name":     d.DKIMSelector + "._domainkey." + d.Domain,
			"value":    fmt.Sprintf("v=DKIM1; k=rsa; p=%s", d.DKIMPublicKey),
			"purpose":  "DKIM",
			"verified": fmt.Sprintf("%v", d.DKIMVerified),
		},
		{
			"type":     "TXT",
			"name":     d.Domain,
			"value":    fmt.Sprintf("v=spf1 ip4:%s ~all", Cfg.ServerIP),
			"purpose":  "SPF",
			"verified": fmt.Sprintf("%v", d.SPFVerified),
		},
		{
			"type":     "TXT",
			"name":     "_dmarc." + d.Domain,
			"value":    "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + d.Domain,
			"purpose":  "DMARC",
			"verified": fmt.Sprintf("%v", d.DMARCVerified),
		},
	}
}
