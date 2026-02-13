package types

import "time"

type PairingMessageType string

const (
	PairingMessageTypeInit              PairingMessageType = "pair.init"
	PairingMessageTypeIdentity          PairingMessageType = "pair.identity"
	PairingMessageTypeChallenge         PairingMessageType = "pair.challenge"
	PairingMessageTypeChallengeResponse PairingMessageType = "pair.challenge_response"
	PairingMessageTypeComplete          PairingMessageType = "pair.complete"
	PairingMessageTypeError             PairingMessageType = "pair.error"
)

type PairingStatus string

const (
	PairingStatusOK PairingStatus = "ok"
)

type PairInit struct {
	Type       PairingMessageType `json:"type"`
	Version    string             `json:"version"`
	PairingID  string             `json:"pairing_id"`
	Gateway    PairGatewayInfo    `json:"gateway"`
	SigEd25519 string             `json:"sig_ed25519"`
}

type PairGatewayInfo struct {
	GatewayID        string    `json:"gateway_id"`
	PublicKeyEd25519 string    `json:"public_key_ed25519"`
	Nonce            string    `json:"nonce"`
	IssuedAt         time.Time `json:"issued_at"`
}

type PairIdentity struct {
	Type       PairingMessageType `json:"type"`
	Version    string             `json:"version"`
	PairingID  string             `json:"pairing_id"`
	Remote     PairRemoteInfo     `json:"remote"`
	SigEd25519 string             `json:"sig_ed25519"`
}

type PairRemoteInfo struct {
	ComponentType       ComponentType `json:"component_type"`
	ComponentID         string        `json:"component_id"`
	PublicKeyEd25519    string        `json:"public_key_ed25519"`
	PublicKeyX25519     string        `json:"public_key_x25519"`
	MTLSCertFingerprint string        `json:"mtls_cert_fingerprint"`
}

type PairChallenge struct {
	Type        PairingMessageType `json:"type"`
	Version     string             `json:"version"`
	PairingID   string             `json:"pairing_id"`
	ChallengeID string             `json:"challenge_id"`
	Ciphertext  string             `json:"ciphertext"`
	AAD         string             `json:"aad,omitempty"`
}

type PairChallengeResponse struct {
	Type               PairingMessageType `json:"type"`
	Version            string             `json:"version"`
	PairingID          string             `json:"pairing_id"`
	ChallengeID        string             `json:"challenge_id"`
	ChallengePlaintext string             `json:"challenge_plaintext"`
	SigEd25519         string             `json:"sig_ed25519"`
}

type PairComplete struct {
	Type      PairingMessageType `json:"type"`
	Version   string             `json:"version"`
	PairingID string             `json:"pairing_id"`
	Status    PairingStatus      `json:"status"`
}

type PairError struct {
	Type      PairingMessageType `json:"type"`
	Version   string             `json:"version"`
	PairingID string             `json:"pairing_id"`
	Code      string             `json:"code"`
	Message   string             `json:"message"`
}

type PairedPeerStatus string

const (
	PairedPeerStatusActive   PairedPeerStatus = "active"
	PairedPeerStatusInactive PairedPeerStatus = "inactive"
	PairedPeerStatusRevoked  PairedPeerStatus = "revoked"
)

type PairedPeerRecord struct {
	ComponentType       ComponentType    `json:"component_type"`
	ComponentID         string           `json:"component_id"`
	Endpoint            string           `json:"endpoint"`
	PublicKeyEd25519    string           `json:"public_key_ed25519"`
	PublicKeyX25519     string           `json:"public_key_x25519"`
	MTLSCertFingerprint string           `json:"mtls_cert_fingerprint"`
	PairedAt            time.Time        `json:"paired_at"`
	LastSeenAt          time.Time        `json:"last_seen_at"`
	Status              PairedPeerStatus `json:"status"`
}
