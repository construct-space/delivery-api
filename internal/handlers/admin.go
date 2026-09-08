package handlers

import (
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"
)

// GET /api/admin/stats
func AdminStats(w http.ResponseWriter, r *http.Request) {
	var totalMessages int64
	var sent, queued, failed, bounced int64
	database.DB.Model(&models.Message{}).Count(&totalMessages)
	database.DB.Model(&models.Message{}).Where("status = ?", "sent").Count(&sent)
	database.DB.Model(&models.Message{}).Where("status IN ?", []string{"queued", "sending"}).Count(&queued)
	database.DB.Model(&models.Message{}).Where("status = ?", "failed").Count(&failed)
	database.DB.Model(&models.Message{}).Where("status = ?", "bounced").Count(&bounced)

	var totalDomains int64
	var verifiedDomains int64
	database.DB.Model(&models.SendingDomain{}).Count(&totalDomains)
	database.DB.Model(&models.SendingDomain{}).Where("status = ?", "verified").Count(&verifiedDomains)

	var totalKeys int64
	database.DB.Model(&models.APIKey{}).Count(&totalKeys)

	WriteJSON(w, 200, map[string]any{
		"messages": map[string]any{
			"total":   totalMessages,
			"sent":    sent,
			"queued":  queued,
			"failed":  failed,
			"bounced": bounced,
		},
		"domains": map[string]any{
			"total":    totalDomains,
			"verified": verifiedDomains,
		},
		"keys": map[string]any{
			"total": totalKeys,
		},
	})
}

// GET /api/admin/messages
// Server-side pagination — designed for the 1M-user case. The response mirrors
// accounts' /api/admin/users shape ({data,total,page,limit}) so oracle's
// Pagination widget can drop in with zero adapter.
func AdminListMessages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	search := q.Get("search")

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 {
		limit = 25
	}
	if limit > 200 {
		limit = 200 // hard ceiling to keep the query bounded
	}

	query := database.DB.Model(&models.Message{})
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if search != "" {
		like := "%" + search + "%"
		query = query.Where("to_email LIKE ? OR subject LIKE ?", like, like)
	}

	var total int64
	query.Count(&total)

	var msgs []models.Message
	query.Order("created_at desc").Offset((page - 1) * limit).Limit(limit).Find(&msgs)

	WriteJSON(w, 200, map[string]any{
		"data":  msgs,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// GET /api/admin/domains
func AdminListDomains(w http.ResponseWriter, r *http.Request) {
	var domains []models.SendingDomain
	database.DB.Order("created_at desc").Find(&domains)
	WriteJSON(w, 200, map[string]any{"domains": domains})
}

// GET /api/admin/domains/{id}
func AdminGetDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var d models.SendingDomain
	if err := database.DB.First(&d, id).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}
	WriteJSON(w, 200, map[string]any{
		"domain":      d,
		"dns_records": dnsRecords(d),
	})
}

// GET /api/admin/domains/{id}/dns-records
func AdminGetDomainDNS(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var d models.SendingDomain
	if err := database.DB.First(&d, id).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}
	WriteJSON(w, 200, map[string]any{"dns_records": dnsRecords(d)})
}

// GET /api/admin/domains/{id}/messages
func AdminGetDomainMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var d models.SendingDomain
	if err := database.DB.First(&d, id).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}

	var msgs []models.Message
	database.DB.Where("domain_id = ?", d.ID).Order("created_at desc").Limit(100).Find(&msgs)
	WriteJSON(w, 200, map[string]any{"messages": msgs})
}

// POST /api/admin/domains/{id}/verify
func AdminVerifyDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var d models.SendingDomain
	if err := database.DB.First(&d, id).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "domain not found"})
		return
	}
	adminVerifyDomainRecord(w, &d)
}

// adminVerifyDomainRecord performs DNS checks and updates the domain record.
// Mirrors VerifyDomain logic without user-scope filtering.
func adminVerifyDomainRecord(w http.ResponseWriter, d *models.SendingDomain) {
	dkimHost := d.DKIMSelector + "._domainkey." + d.Domain
	txtRecords, _ := net.LookupTXT(dkimHost)
	d.DKIMVerified = false
	prefix := d.DKIMPublicKey
	if len(prefix) > 40 {
		prefix = prefix[:40]
	}
	for _, txt := range txtRecords {
		if strings.Contains(txt, prefix) {
			d.DKIMVerified = true
			break
		}
	}

	txtRecords, _ = net.LookupTXT(d.Domain)
	d.SPFVerified = false
	for _, txt := range txtRecords {
		if strings.Contains(txt, "v=spf1") && (strings.Contains(txt, Cfg.ServerIP) || strings.Contains(txt, Cfg.Hostname)) {
			d.SPFVerified = true
			break
		}
	}

	txtRecords, _ = net.LookupTXT("_dmarc." + d.Domain)
	d.DMARCVerified = false
	for _, txt := range txtRecords {
		if strings.Contains(txt, "v=DMARC1") {
			d.DMARCVerified = true
			break
		}
	}

	if d.DKIMVerified && d.SPFVerified {
		d.Status = "verified"
	} else {
		d.Status = "pending"
	}

	database.DB.Save(d)

	WriteJSON(w, 200, map[string]any{
		"domain":      d,
		"dns_records": dnsRecords(*d),
	})
}

// GET /api/admin/keys
func AdminListKeys(w http.ResponseWriter, r *http.Request) {
	var keys []models.APIKey
	database.DB.Order("created_at desc").Find(&keys)
	WriteJSON(w, 200, map[string]any{"keys": keys})
}

// GET /api/admin/tenants
// Per-user delivery footprint. Answers "who is using delivery and how hard?"
// for oracle. Built from three parallel aggregates over messages + domains +
// api_keys, then merged on user_id. Anyone who has ever enrolled (key row) or
// sent a message (message row) or owned a domain appears in the list.
func AdminListTenants(w http.ResponseWriter, r *http.Request) {
	type msgRow struct {
		UserID     string
		Total      int64
		Sent       int64
		Queued     int64
		Failed     int64
		Bounced    int64
		LastSendAt *time.Time
	}
	var msgRows []msgRow
	database.DB.Raw(`
		SELECT user_id,
		       COUNT(*)                                                   AS total,
		       SUM(CASE WHEN status = 'sent'                 THEN 1 ELSE 0 END) AS sent,
		       SUM(CASE WHEN status IN ('queued','sending') THEN 1 ELSE 0 END) AS queued,
		       SUM(CASE WHEN status = 'failed'               THEN 1 ELSE 0 END) AS failed,
		       SUM(CASE WHEN status = 'bounced'              THEN 1 ELSE 0 END) AS bounced,
		       MAX(sent_at)                                               AS last_send_at
		FROM   messages
		GROUP  BY user_id
	`).Scan(&msgRows)

	type countRow struct {
		UserID string
		N      int64
	}
	var domRows []countRow
	database.DB.Raw(`SELECT user_id, COUNT(*) AS n FROM sending_domains GROUP BY user_id`).Scan(&domRows)

	var keyRows []countRow
	database.DB.Raw(`SELECT user_id, COUNT(*) AS n FROM api_keys GROUP BY user_id`).Scan(&keyRows)

	type tenant struct {
		UserID     string     `json:"user_id"`
		Messages   int64      `json:"messages_total"`
		Sent       int64      `json:"messages_sent"`
		Queued     int64      `json:"messages_queued"`
		Failed     int64      `json:"messages_failed"`
		Bounced    int64      `json:"messages_bounced"`
		Domains    int64      `json:"domains"`
		Keys       int64      `json:"keys"`
		LastSendAt *time.Time `json:"last_send_at,omitempty"`
	}
	by := map[string]*tenant{}
	get := func(id string) *tenant {
		if t, ok := by[id]; ok {
			return t
		}
		t := &tenant{UserID: id}
		by[id] = t
		return t
	}
	for _, m := range msgRows {
		t := get(m.UserID)
		t.Messages, t.Sent, t.Queued = m.Total, m.Sent, m.Queued
		t.Failed, t.Bounced, t.LastSendAt = m.Failed, m.Bounced, m.LastSendAt
	}
	for _, d := range domRows {
		get(d.UserID).Domains = d.N
	}
	for _, k := range keyRows {
		get(k.UserID).Keys = k.N
	}
	out := make([]*tenant, 0, len(by))
	for _, t := range by {
		out = append(out, t)
	}
	// Most active first, then most recent send, then stable by user_id.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Messages != out[j].Messages {
			return out[i].Messages > out[j].Messages
		}
		li, lj := int64(0), int64(0)
		if out[i].LastSendAt != nil {
			li = out[i].LastSendAt.Unix()
		}
		if out[j].LastSendAt != nil {
			lj = out[j].LastSendAt.Unix()
		}
		if li != lj {
			return li > lj
		}
		return out[i].UserID < out[j].UserID
	})

	WriteJSON(w, 200, map[string]any{"tenants": out})
}
