package chanmap

import (
	"fmt"
	"sync"
	"testing"
)

func TestChannelRegistryRegisterLookup(t *testing.T) {
	registry := NewChannelRegistry()

	registry.Register("session-1", "channel-1")

	channelID, ok := registry.Lookup("session-1")
	if !ok {
		t.Fatalf("expected lookup hit")
	}
	if channelID != "channel-1" {
		t.Fatalf("expected channel-1, got %q", channelID)
	}
}

func TestChannelRegistryLookupMissing(t *testing.T) {
	registry := NewChannelRegistry()

	_, ok := registry.Lookup("missing")
	if ok {
		t.Fatalf("expected missing lookup to return false")
	}
}

func TestChannelRegistryConcurrentAccess(t *testing.T) {
	registry := NewChannelRegistry()

	const workers = 16
	const iterations = 500

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sessionID := fmt.Sprintf("session-%d-%d", workerID, j)
				channelID := fmt.Sprintf("channel-%d-%d", workerID, j)
				registry.Register(sessionID, channelID)

				if _, ok := registry.Lookup(sessionID); !ok {
					t.Errorf("expected lookup hit for %s", sessionID)
				}
				_, _ = registry.Lookup("missing")
			}
		}()
	}

	wg.Wait()

	if _, ok := registry.Lookup("session-0-0"); !ok {
		t.Fatalf("expected final lookup hit for session-0-0")
	}
}
