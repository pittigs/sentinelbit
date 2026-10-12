package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SyncBroker manages real-time Server-Sent Events (SSE) connections for vault synchronization
type SyncBroker struct {
	mu      sync.RWMutex
	clients map[string]map[chan []byte]struct{} // userID -> set of client channels
}

var Broker = &SyncBroker{
	clients: make(map[string]map[chan []byte]struct{}),
}

// Subscribe registers a new SSE client for a specific user
func (b *SyncBroker) Subscribe(userID string) (chan []byte, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan []byte, 16)
	if _, exists := b.clients[userID]; !exists {
		b.clients[userID] = make(map[chan []byte]struct{})
	}
	b.clients[userID][ch] = struct{}{}

	unsubscribe := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if clientSet, exists := b.clients[userID]; exists {
			delete(clientSet, ch)
			close(ch)
			if len(clientSet) == 0 {
				delete(b.clients, userID)
			}
		}
	}

	return ch, unsubscribe
}

// Broadcast sends an SSE event to all connected clients of a specific user
func (b *SyncBroker) Broadcast(userID string, eventType string, payload interface{}) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	clientSet, exists := b.clients[userID]
	if !exists || len(clientSet) == 0 {
		return
	}

	msgData := map[string]interface{}{
		"type":      eventType,
		"payload":   payload,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	dataBytes, err := json.Marshal(msgData)
	if err != nil {
		return
	}

	for ch := range clientSet {
		select {
		case ch <- dataBytes:
		default:
			// Non-blocking drop if client buffer is full
		}
	}
}

// HandleSyncEvents handles SSE stream connections: GET /api/sync/events
func HandleSyncEvents(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate via Authorization header or ?token= query parameter (for native EventSource)
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("Authorization")
			if len(token) > 7 && token[:7] == "Bearer " {
				token = token[7:]
			}
		}

		if token == "" {
			http.Error(w, "Unauthorized: missing token", http.StatusUnauthorized)
			return
		}

		SessionMu.RLock()
		sess, exists := Sessions[token]
		SessionMu.RUnlock()

		if !exists || time.Now().After(sess.ExpiresAt) {
			http.Error(w, "Unauthorized: invalid or expired session", http.StatusUnauthorized)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		// Initial connection confirmation
		_, _ = fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"ok\",\"user\":\"%s\"}\n\n", sess.Username)
		flusher.Flush()

		ch, unsubscribe := Broker.Subscribe(sess.UserId)
		defer unsubscribe()

		keepAliveTicker := time.NewTicker(25 * time.Second)
		defer keepAliveTicker.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-keepAliveTicker.C:
				_, err := fmt.Fprintf(w, ": keepalive %d\n\n", time.Now().Unix())
				if err != nil {
					return
				}
				flusher.Flush()
			case msg, ok := <-ch:
				if !ok {
					return
				}
				_, err := fmt.Fprintf(w, "event: vault_sync\ndata: %s\n\n", string(msg))
				if err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}
