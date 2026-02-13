package types

import "time"

type PairingMessageType string

const (
	PairingMessageTypeInit              PairingMessageType = "pair.init"
	PairingMessageTypeIdentity          PairingMessageType = "pair.identity"
	PairingMessageTypeChallenge         PairingMessageType = "pair.challenge"
	PairingMessageTypeChallengeResponse PairingMessageType = "pair.challenge_response"
	PairingMessageTypeCSRRequest        PairingMessageType = "pair.csr_request"
	PairingMessageTypeCSRIssued         PairingMessageType = "pair.csr_issued"
	PairingMessageTypeCSRInstalled      PairingMessageType = "pair.csr_installed"
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

type PairCSRRequest struct {
	Type       PairingMessageType `json:"type"`
	Version    string             `json:"version"`
	PairingID  string             `json:"pairing_id"`
	CSRPEM     string             `json:"csr_pem"`
	SigEd25519 string             `json:"sig_ed25519"`
}

type PairCSRIssued struct {
	Type                PairingMessageType `json:"type"`
	Version             string             `json:"version"`
	PairingID           string             `json:"pairing_id"`
	CertificatePEM      string             `json:"certificate_pem"`
	CertificateChainPEM []string           `json:"certificate_chain_pem,omitempty"`
	SerialNumber        string             `json:"serial_number"`
	MTLSCertFingerprint string             `json:"mtls_cert_fingerprint"`
	NotBefore           time.Time          `json:"not_before"`
	NotAfter            time.Time          `json:"not_after"`
	SigEd25519          string             `json:"sig_ed25519"`
}

type PairCSRInstalled struct {
	Type                PairingMessageType `json:"type"`
	Version             string             `json:"version"`
	PairingID           string             `json:"pairing_id"`
	MTLSCertFingerprint string             `json:"mtls_cert_fingerprint"`
	SigEd25519          string             `json:"sig_ed25519"`
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
	PairedPeerStatusPending  PairedPeerStatus = "pending"
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
