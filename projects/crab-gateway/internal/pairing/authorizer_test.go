package pairing

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"crabstack.local/lib/types"
)

func TestPeerAuthorizer_AuthorizeActivePeer(t *testing.T) {
	store := newPeerStoreForAuthorizerTest(t)
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	rec := types.PairedPeerRecord{
		ComponentType:       types.ComponentTypeToolHost,
		ComponentID:         "memory-east",
		Endpoint:            "wss://memory.local:5225",
		PublicKeyEd25519:    "pub-ed",
		PublicKeyX25519:     "pub-x",
		MTLSCertFingerprint: "sha256:abc",
		PairedAt:            now,
		LastSeenAt:          now,
		Status:              types.PairedPeerStatusActive,
	}
	if err := store.UpsertPeer(context.Background(), rec); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	authorizer := NewPeerAuthorizer(store)
	peer, err := authorizer.Authorize(context.Background(), rec.Endpoint, types.ComponentTypeToolHost, rec.ComponentID, "sha256:abc")
	if err != nil {
		t.Fatalf("authorize peer: %v", err)
	}
	if peer.ComponentID != rec.ComponentID {
		t.Fatalf("unexpected component_id %s", peer.ComponentID)
	}
}

func TestPeerAuthorizer_RejectsInactivePeer(t *testing.T) {
	store := newPeerStoreForAuthorizerTest(t)
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	rec := types.PairedPeerRecord{
		ComponentType:       types.ComponentTypeToolHost,
		ComponentID:         "memory-east",
		Endpoint:            "wss://memory.local:5225",
		PublicKeyEd25519:    "pub-ed",
		PublicKeyX25519:     "pub-x",
		MTLSCertFingerprint: "sha256:abc",
		PairedAt:            now,
		LastSeenAt:          now,
		Status:              types.PairedPeerStatusInactive,
	}
	if err := store.UpsertPeer(context.Background(), rec); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	authorizer := NewPeerAuthorizer(store)
	_, err := authorizer.Authorize(context.Background(), rec.Endpoint, types.ComponentTypeToolHost, rec.ComponentID, "sha256:abc")
	if err == nil {
		t.Fatalf("expected inactive peer authorization failure")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected ErrProtocolViolation, got %v", err)
	}
}

func TestPeerAuthorizer_RejectsFingerprintMismatch(t *testing.T) {
	store := newPeerStoreForAuthorizerTest(t)
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	rec := types.PairedPeerRecord{
		ComponentType:       types.ComponentTypeToolHost,
		ComponentID:         "memory-east",
		Endpoint:            "wss://memory.local:5225",
		PublicKeyEd25519:    "pub-ed",
		PublicKeyX25519:     "pub-x",
		MTLSCertFingerprint: "sha256:abc",
		PairedAt:            now,
		LastSeenAt:          now,
		Status:              types.PairedPeerStatusActive,
	}
	if err := store.UpsertPeer(context.Background(), rec); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	authorizer := NewPeerAuthorizer(store)
	_, err := authorizer.Authorize(context.Background(), rec.Endpoint, types.ComponentTypeToolHost, rec.ComponentID, "sha256:def")
	if err == nil {
		t.Fatalf("expected fingerprint mismatch to fail")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected ErrProtocolViolation, got %v", err)
	}
}

func newPeerStoreForAuthorizerTest(t *testing.T) *GormPeerStore {
	t.Helper()
	store, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	return store
}
