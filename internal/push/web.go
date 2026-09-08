package push

import (
	"context"
	"net/http"

	"construct/delivery/internal/models"

	webpush "github.com/SherClockHolmes/webpush-go"
)

type WebPush struct {
	publicKey  string
	privateKey string
	subject    string
}

func NewWebPush(publicKey, privateKey, subject string) *WebPush {
	return &WebPush{publicKey: publicKey, privateKey: privateKey, subject: subject}
}

func (w *WebPush) Name() string  { return "vapid" }
func (w *WebPush) Enabled() bool { return w.publicKey != "" && w.privateKey != "" && w.subject != "" }

// PublicKey is exposed via GET /api/notifications/vapid-public-key so
// frontends can call PushManager.subscribe with the matching applicationServerKey.
func (w *WebPush) PublicKey() string { return w.publicKey }

func (w *WebPush) SendWeb(ctx context.Context, sub models.WebPushSubscription, payload []byte) (bool, error) {
	s := &webpush.Subscription{
		Endpoint: sub.Endpoint,
		Keys:     webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
	}
	resp, err := webpush.SendNotificationWithContext(ctx, payload, s, &webpush.Options{
		Subscriber:      w.subject,
		VAPIDPublicKey:  w.publicKey,
		VAPIDPrivateKey: w.privateKey,
		TTL:             60,
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	// 404/410 == subscription is dead; the browser uninstalled or expired it.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return true, nil
	}
	if resp.StatusCode >= 400 {
		return false, &webpushError{Status: resp.StatusCode}
	}
	return false, nil
}

type webpushError struct{ Status int }

func (e *webpushError) Error() string { return http.StatusText(e.Status) }
