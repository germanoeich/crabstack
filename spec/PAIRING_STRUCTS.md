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
	PairCSRRequestType        PairingMessageType = "pair.csr_request"
	PairCSRIssuedType         PairingMessageType = "pair.csr_issued"
	PairCSRInstalledType      PairingMessageType = "pair.csr_installed"
	PairCompleteType          PairingMessageType = "pair.complete"
	PairErrorType             PairingMessageType = "pair.error"
)

type ComponentType string

const (
	ComponentToolHost   ComponentType = "tool_host"
	ComponentListener   ComponentType = "listener"
	ComponentSubscriber ComponentType = "subscriber"
	ComponentOperator   ComponentType = "operator"
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
- Pairing trigger is local control-plane only (gateway admin Unix socket), not public HTTP/WS ingress.
- `type` must match expected value per message struct.
- `version` must be `v1`.
- `pairing_id` must be non-empty and stable across one handshake.
- `sig_ed25519` verification is required on `pair.init`, `pair.identity`, `pair.challenge_response`, `pair.csr_request`, and `pair.csr_installed`.
- Gateway signs `pair.csr_issued`, and remote must verify it with configured gateway public key.
- `pair.challenge_response.challenge_plaintext` must byte-match gateway challenge plaintext.
- `pair.csr_request.csr_pem` must parse and pass CSR signature validation.
- `pair.csr_installed.mtls_cert_fingerprint` must equal fingerprint from `pair.csr_issued`.
- Pairing succeeds only after signature checks, challenge verification, and CSR install confirmation pass.
