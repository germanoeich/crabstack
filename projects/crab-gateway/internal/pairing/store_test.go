package pairing

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"crabstack.local/lib/types"
)

func TestGormPeerStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.db")
	store, err := NewGormPeerStore("sqlite", path)
	if err != nil {
		t.Fatalf("new gorm peer store: %v", err)
	}
	defer func() { _ = store.Close() }()

	rec := types.PairedPeerRecord{
		ComponentType:       types.ComponentTypeToolHost,
		ComponentID:         "memory-east",
		Endpoint:            "ws://10.0.0.1:5225",
		PublicKeyEd25519:    "pubed",
		PublicKeyX25519:     "pubx",
		MTLSCertFingerprint: "sha256:abc",
		Status:              types.PairedPeerStatusPending,
		LastSeenAt:          time.Now().UTC(),
	}
	if err := store.UpsertPeer(context.Background(), rec); err != nil {
		t.Fatalf("upsert peer: %v", err)
	}

	loaded, err := store.GetPeerByEndpoint(context.Background(), rec.Endpoint)
	if err != nil {
		t.Fatalf("get peer: %v", err)
	}
	if loaded.ComponentID != rec.ComponentID {
		t.Fatalf("unexpected component id: %s", loaded.ComponentID)
	}

	if err := store.UpdatePeerStatus(context.Background(), rec.Endpoint, types.PairedPeerStatusActive, time.Now().UTC()); err != nil {
		t.Fatalf("update peer status: %v", err)
	}
	loaded, err = store.GetPeerByEndpoint(context.Background(), rec.Endpoint)
	if err != nil {
		t.Fatalf("get peer after status update: %v", err)
	}
	if loaded.Status != types.PairedPeerStatusActive {
		t.Fatalf("expected active status, got %s", loaded.Status)
	}
}

func TestGormPeerStore_GetPeerByEndpointNotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.db")
	store, err := NewGormPeerStore("sqlite", path)
	if err != nil {
		t.Fatalf("new gorm peer store: %v", err)
	}
	defer func() { _ = store.Close() }()

	_, err = store.GetPeerByEndpoint(context.Background(), "ws://127.0.0.1:9999")
	if err == nil {
		t.Fatalf("expected not found error")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected protocol violation, got %v", err)
	}
}
