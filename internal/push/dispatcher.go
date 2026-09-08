// Package push fans a single Notification out to a user's web push
// subscriptions and mobile device tokens. Each driver (web, fcm) is
// independently optional: if its env config is missing, the driver is a
// no-op and the dispatcher logs once at startup.
//
// The dispatcher itself is fire-and-forget — Send returns immediately and
// the actual HTTP calls run on background goroutines. Failures are logged;
// stale endpoints/tokens are pruned from the DB so they stop being retried.
package push

import (
	"context"
	"log"
	"time"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"
)

type Driver interface {
	Name() string
	Enabled() bool
}

type WebDriver interface {
	Driver
	SendWeb(ctx context.Context, sub models.WebPushSubscription, payload []byte) (stale bool, err error)
}

type MobileDriver interface {
	Driver
	SendMobile(ctx context.Context, token models.DeviceToken, n *models.Notification) (stale bool, err error)
}

type Dispatcher struct {
	Web    WebDriver
	Mobile MobileDriver
}

func New(web WebDriver, mobile MobileDriver) *Dispatcher {
	d := &Dispatcher{Web: web, Mobile: mobile}
	if web != nil && web.Enabled() {
		log.Printf("[push] web push enabled (%s)", web.Name())
	} else {
		log.Printf("[push] web push disabled — set VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY/VAPID_SUBJECT to enable")
	}
	if mobile != nil && mobile.Enabled() {
		log.Printf("[push] mobile push enabled (%s)", mobile.Name())
	} else {
		log.Printf("[push] mobile push disabled — set FCM_CREDENTIALS_JSON to enable")
	}
	return d
}

// Send dispatches the notification to every push surface the user has
// registered. Caller must already have inserted the row and respected the
// user's preferences (Dispatcher does not re-check prefs).
func (d *Dispatcher) Send(n *models.Notification, payload []byte) {
	go d.fanout(n, payload)
}

func (d *Dispatcher) fanout(n *models.Notification, payload []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if d.Web != nil && d.Web.Enabled() {
		var subs []models.WebPushSubscription
		database.DB.Where("user_id = ?", n.UserID).Find(&subs)
		for _, s := range subs {
			stale, err := d.Web.SendWeb(ctx, s, payload)
			if stale {
				database.DB.Delete(&models.WebPushSubscription{}, s.ID)
				continue
			}
			if err != nil {
				log.Printf("[push:web] send failed for sub=%d user=%s: %v", s.ID, n.UserID, err)
				continue
			}
			database.DB.Model(&models.WebPushSubscription{}).Where("id = ?", s.ID).Update("last_used", time.Now())
		}
	}

	if d.Mobile != nil && d.Mobile.Enabled() {
		var tokens []models.DeviceToken
		database.DB.Where("user_id = ?", n.UserID).Find(&tokens)
		for _, t := range tokens {
			stale, err := d.Mobile.SendMobile(ctx, t, n)
			if stale {
				database.DB.Delete(&models.DeviceToken{}, t.ID)
				continue
			}
			if err != nil {
				log.Printf("[push:mobile] send failed for token=%d user=%s: %v", t.ID, n.UserID, err)
				continue
			}
			database.DB.Model(&models.DeviceToken{}).Where("id = ?", t.ID).Update("last_used", time.Now())
		}
	}
}
