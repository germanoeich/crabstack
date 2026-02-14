package chanmap

import (
	"strings"
	"sync"
)

type ChannelRegistry struct {
	mu    sync.RWMutex
	store map[string]string
}

func NewChannelRegistry() *ChannelRegistry {
	return &ChannelRegistry{
		store: make(map[string]string),
	}
}

func (r *ChannelRegistry) Register(sessionID, channelID string) {
	if r == nil {
		return
	}

	sessionID = strings.TrimSpace(sessionID)
	channelID = strings.TrimSpace(channelID)
	if sessionID == "" || channelID == "" {
		return
	}

	r.mu.Lock()
	if r.store == nil {
		r.store = make(map[string]string)
	}
	r.store[sessionID] = channelID
	r.mu.Unlock()
}

func (r *ChannelRegistry) Lookup(sessionID string) (string, bool) {
	if r == nil {
		return "", false
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "", false
	}

	r.mu.RLock()
	channelID, ok := r.store[sessionID]
	r.mu.RUnlock()
	return channelID, ok
}
