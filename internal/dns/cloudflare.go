package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const cfAPI = "https://api.cloudflare.com/client/v4"

// CloudflareClient manages DNS records via Cloudflare API.
type CloudflareClient struct {
	apiToken string
	client   *http.Client
}

func NewCloudflareClient(apiToken string) *CloudflareClient {
	return &CloudflareClient{
		apiToken: apiToken,
		client:   &http.Client{},
	}
}

// Zone represents a Cloudflare DNS zone.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DNSRecord represents a Cloudflare DNS record.
type DNSRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
	Proxied bool   `json:"proxied"`
}

// FindZone looks up the Cloudflare zone for a domain.
func (c *CloudflareClient) FindZone(domain string) (*Zone, error) {
	// Try the domain itself, then parent domains
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		zone, err := c.getZone(candidate)
		if err == nil && zone != nil {
			return zone, nil
		}
	}
	return nil, fmt.Errorf("no Cloudflare zone found for %s", domain)
}

func (c *CloudflareClient) getZone(name string) (*Zone, error) {
	resp, err := c.do("GET", fmt.Sprintf("/zones?name=%s&status=active", name), nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Result []Zone `json:"result"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}
	if len(result.Result) == 0 {
		return nil, nil
	}
	return &result.Result[0], nil
}

// SetupDomainRecords creates all required DNS records for email sending.
// Returns the records that were created and any errors.
func (c *CloudflareClient) SetupDomainRecords(domain, dkimSelector, dkimPublicKey, serverIP string) ([]string, []error) {
	zone, err := c.FindZone(domain)
	if err != nil {
		return nil, []error{fmt.Errorf("zone lookup: %w", err)}
	}

	records := []DNSRecord{
		{
			Type:    "TXT",
			Name:    fmt.Sprintf("%s._domainkey.%s", dkimSelector, domain),
			Content: fmt.Sprintf("v=DKIM1; k=rsa; p=%s", dkimPublicKey),
			TTL:     3600,
		},
		{
			Type:    "TXT",
			Name:    domain,
			Content: fmt.Sprintf("v=spf1 ip4:%s include:delivery.lisaos.dev ~all", serverIP),
			TTL:     3600,
		},
		{
			Type:    "TXT",
			Name:    fmt.Sprintf("_dmarc.%s", domain),
			Content: fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:dmarc@%s", domain),
			TTL:     3600,
		},
	}

	var created []string
	var errors []error

	for _, rec := range records {
		// Check if record already exists
		existing, err := c.findRecord(zone.ID, rec.Type, rec.Name)
		if err != nil {
			errors = append(errors, fmt.Errorf("check %s %s: %w", rec.Type, rec.Name, err))
			continue
		}

		if existing != "" {
			// Update existing record
			err = c.updateRecord(zone.ID, existing, rec)
			if err != nil {
				errors = append(errors, fmt.Errorf("update %s %s: %w", rec.Type, rec.Name, err))
			} else {
				created = append(created, fmt.Sprintf("Updated %s %s", rec.Type, rec.Name))
			}
		} else {
			// Create new record
			err = c.createRecord(zone.ID, rec)
			if err != nil {
				errors = append(errors, fmt.Errorf("create %s %s: %w", rec.Type, rec.Name, err))
			} else {
				created = append(created, fmt.Sprintf("Created %s %s", rec.Type, rec.Name))
			}
		}
	}

	return created, errors
}

func (c *CloudflareClient) findRecord(zoneID, recordType, name string) (string, error) {
	resp, err := c.do("GET", fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, recordType, name), nil)
	if err != nil {
		return "", err
	}

	var result struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", err
	}
	if len(result.Result) > 0 {
		return result.Result[0].ID, nil
	}
	return "", nil
}

func (c *CloudflareClient) createRecord(zoneID string, rec DNSRecord) error {
	body, _ := json.Marshal(rec)
	_, err := c.do("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), body)
	return err
}

func (c *CloudflareClient) updateRecord(zoneID, recordID string, rec DNSRecord) error {
	body, _ := json.Marshal(rec)
	_, err := c.do("PUT", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), body)
	return err
}

// RemoveDomainRecords removes all email-related DNS records for a domain.
func (c *CloudflareClient) RemoveDomainRecords(domain, dkimSelector string) error {
	zone, err := c.FindZone(domain)
	if err != nil {
		return err
	}

	names := []struct{ typ, name string }{
		{"TXT", fmt.Sprintf("%s._domainkey.%s", dkimSelector, domain)},
		{"TXT", fmt.Sprintf("_dmarc.%s", domain)},
		// Don't remove SPF — user might have other entries
	}

	for _, n := range names {
		id, err := c.findRecord(zone.ID, n.typ, n.name)
		if err != nil || id == "" {
			continue
		}
		c.do("DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zone.ID, id), nil)
	}

	return nil
}

func (c *CloudflareClient) do(method, path string, body []byte) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, cfAPI+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("cloudflare API %s %s: %d %s", method, path, resp.StatusCode, string(data[:min(len(data), 200)]))
	}

	return data, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
