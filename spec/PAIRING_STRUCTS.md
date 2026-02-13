# Pairing Struct Draft (Go)

Draft structs for the gateway-initiated pairing handshake.

```go
package protocol

import "time"

type PairingMessageType string

const (
	PairInitType              PairingMessageType = "pair.init"
	PairIdentityType          PairingMessageType = "pair.identity"
	PairChallengeType         PairingMessageType = "pair.challenge"
	PairChallengeResponseType PairingMessageType = "pair.challenge_response"
	PairCompleteType          PairingMessageType = "pair.complete"
	PairErrorType             PairingMessageType = "pair.error"
)

type ComponentType string

const (
	ComponentToolHost   ComponentType = "tool_host"
	ComponentListener   ComponentType = "listener"
	ComponentSubscriber ComponentType = "subscriber"
	ComponentProvider   ComponentType = "provider"
)

type PairInit struct {
	Type        PairingMessageType `json:"type"`
	Version     string             `json:"version"`
	PairingID   string             `json:"pairing_id"`
	Gateway     PairGatewayInfo    `json:"gateway"`
	SigEd25519  string             `json:"sig_ed25519"`
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
	Status    string             `json:"status"`
}

type PairError struct {
	Type      PairingMessageType `json:"type"`
	Version   string             `json:"version"`
	PairingID string             `json:"pairing_id"`
	Code      string             `json:"code"`
	Message   string             `json:"message"`
}

type PairedPeerRecord struct {
	ComponentType       ComponentType `json:"component_type"`
	ComponentID         string        `json:"component_id"`
	Endpoint            string        `json:"endpoint"`
	PublicKeyEd25519    string        `json:"public_key_ed25519"`
	PublicKeyX25519     string        `json:"public_key_x25519"`
	MTLSCertFingerprint string        `json:"mtls_cert_fingerprint"`
	PairedAt            time.Time     `json:"paired_at"`
	LastSeenAt          time.Time     `json:"last_seen_at"`
	Status              string        `json:"status"`
}
```

## Validation rules (implementation notes)
- `type` must match expected value per message struct.
- `version` must be `v1`.
- `pairing_id` must be non-empty and stable across one handshake.
- `sig_ed25519` verification is required on `pair.init`, `pair.identity`, and `pair.challenge_response`.
- `pair.challenge_response.challenge_plaintext` must byte-match gateway challenge plaintext.
- Pairing succeeds only after signature checks and challenge verification both pass.
