package pairing

import (
	"context"
	"fmt"
	"strings"

	"crabstack.local/lib/types"
)

type PeerAuthorizer struct {
	store PeerStore
}

func NewPeerAuthorizer(store PeerStore) *PeerAuthorizer {
	return &PeerAuthorizer{store: store}
}

func (a *PeerAuthorizer) Authorize(ctx context.Context, endpoint string, componentType types.ComponentType, componentID, mtlsFingerprint string) (types.PairedPeerRecord, error) {
	if a == nil || a.store == nil {
		return types.PairedPeerRecord{}, fmt.Errorf("%w: peer authorizer is not configured", ErrInvalidRequest)
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return types.PairedPeerRecord{}, fmt.Errorf("%w: endpoint is required", ErrInvalidRequest)
	}

	peer, err := a.store.GetPeerByEndpoint(ctx, endpoint)
	if err != nil {
		return types.PairedPeerRecord{}, err
	}
	if peer.Status != types.PairedPeerStatusActive {
		return types.PairedPeerRecord{}, fmt.Errorf("%w: peer endpoint %s is not active", ErrProtocolViolation, endpoint)
	}
	if componentType != "" && peer.ComponentType != componentType {
		return types.PairedPeerRecord{}, fmt.Errorf("%w: unexpected component type %s", ErrProtocolViolation, componentType)
	}
	componentID = strings.TrimSpace(componentID)
	if componentID != "" && peer.ComponentID != componentID {
		return types.PairedPeerRecord{}, fmt.Errorf("%w: unexpected component id %s", ErrProtocolViolation, componentID)
	}

	expectedFingerprint := strings.TrimSpace(peer.MTLSCertFingerprint)
	if expectedFingerprint != "" && !fingerprintsEqual(expectedFingerprint, mtlsFingerprint) {
		return types.PairedPeerRecord{}, fmt.Errorf("%w: mtls certificate fingerprint mismatch", ErrProtocolViolation)
	}
	return peer, nil
}
