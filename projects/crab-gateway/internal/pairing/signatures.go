package pairing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"crabstack.local/lib/types"
)

type signedPairInitPayload struct {
	Type      types.PairingMessageType `json:"type"`
	Version   string                   `json:"version"`
	PairingID string                   `json:"pairing_id"`
	Gateway   types.PairGatewayInfo    `json:"gateway"`
}

type signedPairIdentityPayload struct {
	Type      types.PairingMessageType `json:"type"`
	Version   string                   `json:"version"`
	PairingID string                   `json:"pairing_id"`
	Remote    types.PairRemoteInfo     `json:"remote"`
}

type signedPairChallengeResponsePayload struct {
	Type               types.PairingMessageType `json:"type"`
	Version            string                   `json:"version"`
	PairingID          string                   `json:"pairing_id"`
	ChallengeID        string                   `json:"challenge_id"`
	ChallengePlaintext string                   `json:"challenge_plaintext"`
}

type signedPairCSRRequestPayload struct {
	Type      types.PairingMessageType `json:"type"`
	Version   string                   `json:"version"`
	PairingID string                   `json:"pairing_id"`
	CSRPEM    string                   `json:"csr_pem"`
}

type signedPairCSRIssuedPayload struct {
	Type                types.PairingMessageType `json:"type"`
	Version             string                   `json:"version"`
	PairingID           string                   `json:"pairing_id"`
	CertificatePEM      string                   `json:"certificate_pem"`
	CertificateChainPEM []string                 `json:"certificate_chain_pem,omitempty"`
	SerialNumber        string                   `json:"serial_number"`
	MTLSCertFingerprint string                   `json:"mtls_cert_fingerprint"`
	NotBefore           string                   `json:"not_before"`
	NotAfter            string                   `json:"not_after"`
}

type signedPairCSRInstalledPayload struct {
	Type                types.PairingMessageType `json:"type"`
	Version             string                   `json:"version"`
	PairingID           string                   `json:"pairing_id"`
	MTLSCertFingerprint string                   `json:"mtls_cert_fingerprint"`
}

func signPairInit(privateKey ed25519.PrivateKey, msg types.PairInit) (string, error) {
	payload := signedPairInitPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		Gateway:   msg.Gateway,
	}
	return signPayload(privateKey, payload)
}

func verifyPairInit(publicKey ed25519.PublicKey, msg types.PairInit) error {
	payload := signedPairInitPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		Gateway:   msg.Gateway,
	}
	return verifyPayload(publicKey, payload, msg.SigEd25519)
}

func signPairIdentity(privateKey ed25519.PrivateKey, msg types.PairIdentity) (string, error) {
	payload := signedPairIdentityPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		Remote:    msg.Remote,
	}
	return signPayload(privateKey, payload)
}

func verifyPairIdentity(msg types.PairIdentity) (ed25519.PublicKey, error) {
	publicKey, err := decodeEd25519Public(msg.Remote.PublicKeyEd25519)
	if err != nil {
		return nil, err
	}
	payload := signedPairIdentityPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		Remote:    msg.Remote,
	}
	if err := verifyPayload(publicKey, payload, msg.SigEd25519); err != nil {
		return nil, err
	}
	return publicKey, nil
}

func signPairChallengeResponse(privateKey ed25519.PrivateKey, msg types.PairChallengeResponse) (string, error) {
	payload := signedPairChallengeResponsePayload{
		Type:               msg.Type,
		Version:            msg.Version,
		PairingID:          msg.PairingID,
		ChallengeID:        msg.ChallengeID,
		ChallengePlaintext: msg.ChallengePlaintext,
	}
	return signPayload(privateKey, payload)
}

func verifyPairChallengeResponse(publicKey ed25519.PublicKey, msg types.PairChallengeResponse) error {
	payload := signedPairChallengeResponsePayload{
		Type:               msg.Type,
		Version:            msg.Version,
		PairingID:          msg.PairingID,
		ChallengeID:        msg.ChallengeID,
		ChallengePlaintext: msg.ChallengePlaintext,
	}
	return verifyPayload(publicKey, payload, msg.SigEd25519)
}

func signPairCSRRequest(privateKey ed25519.PrivateKey, msg types.PairCSRRequest) (string, error) {
	payload := signedPairCSRRequestPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		CSRPEM:    msg.CSRPEM,
	}
	return signPayload(privateKey, payload)
}

func verifyPairCSRRequest(publicKey ed25519.PublicKey, msg types.PairCSRRequest) error {
	payload := signedPairCSRRequestPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		CSRPEM:    msg.CSRPEM,
	}
	return verifyPayload(publicKey, payload, msg.SigEd25519)
}

func signPairCSRIssued(privateKey ed25519.PrivateKey, msg types.PairCSRIssued) (string, error) {
	payload := signedPairCSRIssuedPayload{
		Type:                msg.Type,
		Version:             msg.Version,
		PairingID:           msg.PairingID,
		CertificatePEM:      msg.CertificatePEM,
		CertificateChainPEM: msg.CertificateChainPEM,
		SerialNumber:        msg.SerialNumber,
		MTLSCertFingerprint: msg.MTLSCertFingerprint,
		NotBefore:           msg.NotBefore.UTC().Format(time.RFC3339Nano),
		NotAfter:            msg.NotAfter.UTC().Format(time.RFC3339Nano),
	}
	return signPayload(privateKey, payload)
}

func verifyPairCSRIssued(publicKey ed25519.PublicKey, msg types.PairCSRIssued) error {
	payload := signedPairCSRIssuedPayload{
		Type:                msg.Type,
		Version:             msg.Version,
		PairingID:           msg.PairingID,
		CertificatePEM:      msg.CertificatePEM,
		CertificateChainPEM: msg.CertificateChainPEM,
		SerialNumber:        msg.SerialNumber,
		MTLSCertFingerprint: msg.MTLSCertFingerprint,
		NotBefore:           msg.NotBefore.UTC().Format(time.RFC3339Nano),
		NotAfter:            msg.NotAfter.UTC().Format(time.RFC3339Nano),
	}
	return verifyPayload(publicKey, payload, msg.SigEd25519)
}

func signPairCSRInstalled(privateKey ed25519.PrivateKey, msg types.PairCSRInstalled) (string, error) {
	payload := signedPairCSRInstalledPayload{
		Type:                msg.Type,
		Version:             msg.Version,
		PairingID:           msg.PairingID,
		MTLSCertFingerprint: msg.MTLSCertFingerprint,
	}
	return signPayload(privateKey, payload)
}

func verifyPairCSRInstalled(publicKey ed25519.PublicKey, msg types.PairCSRInstalled) error {
	payload := signedPairCSRInstalledPayload{
		Type:                msg.Type,
		Version:             msg.Version,
		PairingID:           msg.PairingID,
		MTLSCertFingerprint: msg.MTLSCertFingerprint,
	}
	return verifyPayload(publicKey, payload, msg.SigEd25519)
}

func signPayload(privateKey ed25519.PrivateKey, payload any) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal sign payload: %w", err)
	}
	sig := ed25519.Sign(privateKey, encoded)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func verifyPayload(publicKey ed25519.PublicKey, payload any, signatureBase64 string) error {
	sig, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal verify payload: %w", err)
	}
	if !ed25519.Verify(publicKey, encoded, sig) {
		return ErrSignatureVerification
	}
	return nil
}

func decodeEd25519Public(v string) (ed25519.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("decode public_key_ed25519: %w", err)
	}
	if len(bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public_key_ed25519 size")
	}
	return ed25519.PublicKey(bytes), nil
}
