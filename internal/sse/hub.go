// Package sse is a tiny in-process pub/sub hub keyed by user_id. Each open
// SSE stream registers a buffered channel; Publish fans out to every channel
// for that user. Single-container only — when delivery scales horizontally,
// swap Publish to also broadcast over Postgres LISTEN/NOTIFY (the public
// API of this package would not change).
package sse

import (
	"fmt"
	"sync"

	"construct/delivery/internal/models"
)

// Event is a notification-channel envelope. The cross-device relay
// (DeviceCommand) and operator-presence concept moved to source-api's
// /api/device-bus/* on 2026-05-20; delivery's hub now serves
// notifications + unread counts only.
type Event struct {
	Notification *models.Notification `json:"notification,omitempty"`
	UnreadCount  *int64               `json:"unread_count,omitempty"`
	Type         string               `json:"type"`
}

type subscriber struct {
	id string // monotonic per-process ID, exposed to handlers as connID
	ch chan Event
}

type Hub struct {
	mu     sync.RWMutex
	subs   map[string]map[*subscriber]struct{}
	nextID uint64
}

func NewHub() *Hub {
	return &Hub{subs: make(map[string]map[*subscriber]struct{})}
}

// Subscribe returns the subscription's connection id, a buffered event
// channel, and an unsubscribe func. The channel is buffered (16) so a
// slow client doesn't block other subscribers or the publisher; if the
// buffer fills, events are dropped for that one subscriber and it
// should reconnect to refetch state.
//
// connID is what the WS handler echoes back to the calling client (e.g.
// in a "hello" frame) — clients who plan to publish via the REST relay
// pass it in `X-Sender-Conn-Id` so PublishExcept can skip them. Without
// it, sending a message would fan back to yourself and you'd render
// your own asks as if they came from another device.
func (h *Hub) Subscribe(userID string) (string, <-chan Event, func()) {
	h.mu.Lock()
	h.nextID++
	s := &subscriber{
		id: fmt.Sprintf("c%d", h.nextID),
		ch: make(chan Event, 16),
	}
	if h.subs[userID] == nil {
		h.subs[userID] = make(map[*subscriber]struct{})
	}
	h.subs[userID][s] = struct{}{}
	h.mu.Unlock()

	unsub := func() {
		h.mu.Lock()
		if m, ok := h.subs[userID]; ok {
			delete(m, s)
			if len(m) == 0 {
				delete(h.subs, userID)
			}
		}
		h.mu.Unlock()
		close(s.ch)
	}
	return s.id, s.ch, unsub
}

func (h *Hub) Publish(userID string, evt Event) {
	h.PublishExcept(userID, evt, "")
}

// PublishExcept fans out to every subscriber of userID *except* the one
// matching exceptConnID. Used when the publisher is also one of the
// subscribers (e.g. operator publishing assistant.chunk over the REST
// relay while keeping its own WS open) and we don't want to echo back
// the sender's own messages.
func (h *Hub) PublishExcept(userID string, evt Event, exceptConnID string) {
	h.mu.RLock()
	subs := h.subs[userID]
	targets := make([]*subscriber, 0, len(subs))
	for s := range subs {
		if exceptConnID != "" && s.id == exceptConnID {
			continue
		}
		targets = append(targets, s)
	}
	h.mu.RUnlock()

	for _, s := range targets {
		select {
		case s.ch <- evt:
		default:
			// Buffer full — drop. Client will resync on reconnect.
		}
	}
}

