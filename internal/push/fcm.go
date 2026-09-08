package push

import (
	"context"
	"log"
	"strings"

	"construct/delivery/internal/models"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"google.golang.org/api/option"
)

// FCM sends to both iOS and Android via Firebase Cloud Messaging. iOS still
// goes through APNs under the hood, but Firebase brokers the connection so
// we don't manage the .p8 key directly. Android goes through FCM's HTTP v1.
type FCM struct {
	client  *messaging.Client
	enabled bool
}

func NewFCM(credentialsJSON string) *FCM {
	if credentialsJSON == "" {
		return &FCM{}
	}
	ctx := context.Background()
	opt := option.WithAuthCredentialsJSON(option.ServiceAccount, []byte(credentialsJSON))
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		log.Printf("[push:fcm] init failed: %v", err)
		return &FCM{}
	}
	client, err := app.Messaging(ctx)
	if err != nil {
		log.Printf("[push:fcm] messaging client failed: %v", err)
		return &FCM{}
	}
	return &FCM{client: client, enabled: true}
}

func (f *FCM) Name() string  { return "fcm" }
func (f *FCM) Enabled() bool { return f.enabled }

func (f *FCM) SendMobile(ctx context.Context, token models.DeviceToken, n *models.Notification) (bool, error) {
	if !f.enabled {
		return false, nil
	}
	msg := &messaging.Message{
		Token: token.Token,
		Notification: &messaging.Notification{
			Title: n.Title,
			Body:  n.Body,
		},
		Data: map[string]string{
			"id":     n.ExternalID,
			"type":   n.Type,
			"source": n.Source,
			"link":   n.Link,
		},
	}
	if _, err := f.client.Send(ctx, msg); err != nil {
		// FCM returns "registration-token-not-registered" for tokens the
		// device unregistered or that have expired. Treat as stale so we
		// drop the row.
		if strings.Contains(err.Error(), "registration-token-not-registered") ||
			strings.Contains(err.Error(), "invalid-registration-token") {
			return true, nil
		}
		return false, err
	}
	return false, nil
}
