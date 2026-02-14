package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

type PairGatewayInfoWire struct {
	GatewayID        string    `json:"gateway_id"`
	PublicKeyEd25519 string    `json:"public_key_ed25519"`
	PublicKeyX25519  string    `json:"public_key_x25519,omitempty"`
	Nonce            string    `json:"nonce"`
	IssuedAt         time.Time `json:"issued_at"`
}

type PairInitWire struct {
	Type       types.PairingMessageType `json:"type"`
	Version    string                   `json:"version"`
	PairingID  string                   `json:"pairing_id"`
	Gateway    PairGatewayInfoWire      `json:"gateway"`
	SigEd25519 string                   `json:"sig_ed25519"`
}

type challengeAAD struct {
	PairingID                string `json:"pairing_id"`
	ChallengeID              string `json:"challenge_id"`
	EphemeralPublicKeyX25519 string `json:"ephemeral_public_key_x25519"`
}

type pairInitSignedPayload struct {
	Type      types.PairingMessageType `json:"type"`
	Version   string                   `json:"version"`
	PairingID string                   `json:"pairing_id"`
	Gateway   types.PairGatewayInfo    `json:"gateway"`
}

type pairIdentitySignedPayload struct {
	Type      types.PairingMessageType `json:"type"`
	Version   string                   `json:"version"`
	PairingID string                   `json:"pairing_id"`
	Remote    types.PairRemoteInfo     `json:"remote"`
}

type pairChallengeResponseSignedPayload struct {
	Type               types.PairingMessageType `json:"type"`
	Version            string                   `json:"version"`
	PairingID          string                   `json:"pairing_id"`
	ChallengeID        string                   `json:"challenge_id"`
	ChallengePlaintext string                   `json:"challenge_plaintext"`
}

func DecodePairInit(raw []byte) (PairInitWire, error) {
	var msg PairInitWire
	if err := json.Unmarshal(raw, &msg); err != nil {
		return PairInitWire{}, fmt.Errorf("decode pair.init: %w", err)
	}
	return msg, nil
}

func VerifyPairInit(msg PairInitWire, configuredGatewayPublicKeyEd25519 string) error {
	if msg.Type != types.PairingMessageTypeInit {
		return fmt.Errorf("unexpected pairing message type %q", msg.Type)
	}
	if msg.Version != types.VersionV1 {
		return fmt.Errorf("unsupported pairing version %q", msg.Version)
	}
	if strings.TrimSpace(msg.PairingID) == "" {
		return fmt.Errorf("pairing_id is required")
	}
	if strings.TrimSpace(configuredGatewayPublicKeyEd25519) == "" {
		return fmt.Errorf("configured gateway public key is required")
	}
	if msg.Gateway.PublicKeyEd25519 != configuredGatewayPublicKeyEd25519 {
		return fmt.Errorf("gateway public key mismatch")
	}

	payload := pairInitSignedPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		Gateway: types.PairGatewayInfo{
			GatewayID:        msg.Gateway.GatewayID,
			PublicKeyEd25519: msg.Gateway.PublicKeyEd25519,
			Nonce:            msg.Gateway.Nonce,
			IssuedAt:         msg.Gateway.IssuedAt,
		},
	}
	if err := VerifySignedMessage(payload, msg.Gateway.PublicKeyEd25519, msg.SigEd25519); err != nil {
		return fmt.Errorf("verify pair.init signature: %w", err)
	}
	return nil
}

func SignPairInit(msg PairInitWire, privateKey ed25519.PrivateKey) (PairInitWire, error) {
	payload := pairInitSignedPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		Gateway: types.PairGatewayInfo{
			GatewayID:        msg.Gateway.GatewayID,
			PublicKeyEd25519: msg.Gateway.PublicKeyEd25519,
			Nonce:            msg.Gateway.Nonce,
			IssuedAt:         msg.Gateway.IssuedAt,
		},
	}
	sig, err := SignMessage(payload, privateKey)
	if err != nil {
		return PairInitWire{}, fmt.Errorf("sign pair.init: %w", err)
	}
	msg.SigEd25519 = sig
	return msg, nil
}

func SignPairIdentity(msg types.PairIdentity, privateKey ed25519.PrivateKey) (types.PairIdentity, error) {
	payload := pairIdentitySignedPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		Remote:    msg.Remote,
	}
	sig, err := SignMessage(payload, privateKey)
	if err != nil {
		return types.PairIdentity{}, fmt.Errorf("sign pair.identity: %w", err)
	}
	msg.SigEd25519 = sig
	return msg, nil
}

func VerifyPairIdentity(msg types.PairIdentity) error {
	if msg.Type != types.PairingMessageTypeIdentity {
		return fmt.Errorf("unexpected pairing message type %q", msg.Type)
	}
	if msg.Version != types.VersionV1 {
		return fmt.Errorf("unsupported pairing version %q", msg.Version)
	}
	if strings.TrimSpace(msg.PairingID) == "" {
		return fmt.Errorf("pairing_id is required")
	}
	if strings.TrimSpace(msg.Remote.PublicKeyEd25519) == "" {
		return fmt.Errorf("remote.public_key_ed25519 is required")
	}

	payload := pairIdentitySignedPayload{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		Remote:    msg.Remote,
	}
	if err := VerifySignedMessage(payload, msg.Remote.PublicKeyEd25519, msg.SigEd25519); err != nil {
		return fmt.Errorf("verify pair.identity signature: %w", err)
	}
	return nil
}

func SignPairChallengeResponse(msg types.PairChallengeResponse, privateKey ed25519.PrivateKey) (types.PairChallengeResponse, error) {
	payload := pairChallengeResponseSignedPayload{
		Type:               msg.Type,
		Version:            msg.Version,
		PairingID:          msg.PairingID,
		ChallengeID:        msg.ChallengeID,
		ChallengePlaintext: msg.ChallengePlaintext,
	}
	sig, err := SignMessage(payload, privateKey)
	if err != nil {
		return types.PairChallengeResponse{}, fmt.Errorf("sign pair.challenge_response: %w", err)
	}
	msg.SigEd25519 = sig
	return msg, nil
}

func SignPairCSRRequest(msg types.PairCSRRequest, privateKey ed25519.PrivateKey) (types.PairCSRRequest, error) {
	payload := struct {
		Type      types.PairingMessageType `json:"type"`
		Version   string                   `json:"version"`
		PairingID string                   `json:"pairing_id"`
		CSRPEM    string                   `json:"csr_pem"`
	}{
		Type:      msg.Type,
		Version:   msg.Version,
		PairingID: msg.PairingID,
		CSRPEM:    msg.CSRPEM,
	}
	sig, err := SignMessage(payload, privateKey)
	if err != nil {
		return types.PairCSRRequest{}, fmt.Errorf("sign pair.csr_request: %w", err)
	}
	msg.SigEd25519 = sig
	return msg, nil
}

func VerifyPairCSRIssued(msg types.PairCSRIssued, configuredGatewayPublicKeyEd25519 string) error {
	if msg.Type != types.PairingMessageTypeCSRIssued {
		return fmt.Errorf("unexpected pairing message type %q", msg.Type)
	}
	if msg.Version != types.VersionV1 {
		return fmt.Errorf("unsupported pairing version %q", msg.Version)
	}
	if strings.TrimSpace(msg.PairingID) == "" {
		return fmt.Errorf("pairing_id is required")
	}
	if strings.TrimSpace(configuredGatewayPublicKeyEd25519) == "" {
		return fmt.Errorf("configured gateway public key is required")
	}
	if strings.TrimSpace(msg.CertificatePEM) == "" {
		return fmt.Errorf("certificate_pem is required")
	}
	if strings.TrimSpace(msg.MTLSCertFingerprint) == "" {
		return fmt.Errorf("mtls_cert_fingerprint is required")
	}

	payload := struct {
		Type                types.PairingMessageType `json:"type"`
		Version             string                   `json:"version"`
		PairingID           string                   `json:"pairing_id"`
		CertificatePEM      string                   `json:"certificate_pem"`
		CertificateChainPEM []string                 `json:"certificate_chain_pem,omitempty"`
		SerialNumber        string                   `json:"serial_number"`
		MTLSCertFingerprint string                   `json:"mtls_cert_fingerprint"`
		NotBefore           string                   `json:"not_before"`
		NotAfter            string                   `json:"not_after"`
	}{
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
	if err := VerifySignedMessage(payload, configuredGatewayPublicKeyEd25519, msg.SigEd25519); err != nil {
		return fmt.Errorf("verify pair.csr_issued signature: %w", err)
	}
	return nil
}

func SignPairCSRInstalled(msg types.PairCSRInstalled, privateKey ed25519.PrivateKey) (types.PairCSRInstalled, error) {
	payload := struct {
		Type                types.PairingMessageType `json:"type"`
		Version             string                   `json:"version"`
		PairingID           string                   `json:"pairing_id"`
		MTLSCertFingerprint string                   `json:"mtls_cert_fingerprint"`
	}{
		Type:                msg.Type,
		Version:             msg.Version,
		PairingID:           msg.PairingID,
		MTLSCertFingerprint: msg.MTLSCertFingerprint,
	}
	sig, err := SignMessage(payload, privateKey)
	if err != nil {
		return types.PairCSRInstalled{}, fmt.Errorf("sign pair.csr_installed: %w", err)
	}
	msg.SigEd25519 = sig
	return msg, nil
}

func VerifyPairChallengeResponse(msg types.PairChallengeResponse, remotePublicKeyEd25519 string) error {
	if msg.Type != types.PairingMessageTypeChallengeResponse {
		return fmt.Errorf("unexpected pairing message type %q", msg.Type)
	}
	if msg.Version != types.VersionV1 {
		return fmt.Errorf("unsupported pairing version %q", msg.Version)
	}
	if strings.TrimSpace(msg.PairingID) == "" {
		return fmt.Errorf("pairing_id is required")
	}
	if strings.TrimSpace(msg.ChallengeID) == "" {
		return fmt.Errorf("challenge_id is required")
	}
	if strings.TrimSpace(msg.ChallengePlaintext) == "" {
		return fmt.Errorf("challenge_plaintext is required")
	}

	payload := pairChallengeResponseSignedPayload{
		Type:               msg.Type,
		Version:            msg.Version,
		PairingID:          msg.PairingID,
		ChallengeID:        msg.ChallengeID,
		ChallengePlaintext: msg.ChallengePlaintext,
	}
	if err := VerifySignedMessage(payload, remotePublicKeyEd25519, msg.SigEd25519); err != nil {
		return fmt.Errorf("verify pair.challenge_response signature: %w", err)
	}
	return nil
}

func SignMessage(v any, privateKey ed25519.PrivateKey) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal message: %w", err)
	}
	sig := ed25519.Sign(privateKey, payload)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func VerifySignedMessage(v any, publicKeyB64, signatureB64 string) error {
	if strings.TrimSpace(signatureB64) == "" {
		return fmt.Errorf("signature is required")
	}
	pub, err := decodePublicKeyEd25519(publicKeyB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func DecodePublicKeyX25519(publicKeyB64 string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode x25519 public key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse x25519 public key: %w", err)
	}
	return pub, nil
}

func GenerateX25519Keypair() (*ecdh.PrivateKey, string, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate x25519 keypair: %w", err)
	}
	return priv, base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func DecryptPairChallenge(privateKey *ecdh.PrivateKey, gatewayPublicKeyX25519 string, challenge types.PairChallenge) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("x25519 private key is required")
	}
	_ = gatewayPublicKeyX25519

	aad, err := decodeAAD(challenge.AAD)
	if err != nil {
		return nil, err
	}
	var metadata challengeAAD
	if err := json.Unmarshal(aad, &metadata); err != nil {
		return nil, fmt.Errorf("parse challenge aad: %w", err)
	}
	if metadata.PairingID != challenge.PairingID || metadata.ChallengeID != challenge.ChallengeID {
		return nil, fmt.Errorf("challenge aad mismatch")
	}
	if strings.TrimSpace(metadata.EphemeralPublicKeyX25519) == "" {
		return nil, fmt.Errorf("challenge aad missing ephemeral public key")
	}
	pub, err := DecodePublicKeyX25519(metadata.EphemeralPublicKeyX25519)
	if err != nil {
		return nil, err
	}
	shared, err := privateKey.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("derive x25519 shared secret: %w", err)
	}

	key := deriveSymmetricKey(shared, aad)

	ciphertext, err := base64.StdEncoding.DecodeString(challenge.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode challenge ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:aead.NonceSize()]
	sealed := ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt challenge: %w", err)
	}
	return plaintext, nil
}

func EncryptPairChallenge(privateKey *ecdh.PrivateKey, remotePublicKeyX25519 string, pairingID, challengeID string, plaintext, aad []byte) (types.PairChallenge, error) {
	if privateKey == nil {
		return types.PairChallenge{}, fmt.Errorf("x25519 private key is required")
	}
	if strings.TrimSpace(remotePublicKeyX25519) == "" {
		return types.PairChallenge{}, fmt.Errorf("remote public_key_x25519 is required")
	}
	pub, err := DecodePublicKeyX25519(remotePublicKeyX25519)
	if err != nil {
		return types.PairChallenge{}, err
	}
	shared, err := privateKey.ECDH(pub)
	if err != nil {
		return types.PairChallenge{}, err
	}
	_ = aad

	aadMetadata := challengeAAD{
		PairingID:                pairingID,
		ChallengeID:              challengeID,
		EphemeralPublicKeyX25519: base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
	}
	aadBytes, err := json.Marshal(aadMetadata)
	if err != nil {
		return types.PairChallenge{}, fmt.Errorf("marshal challenge aad: %w", err)
	}

	key := deriveSymmetricKey(shared, aadBytes)
	block, err := aes.NewCipher(key)
	if err != nil {
		return types.PairChallenge{}, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return types.PairChallenge{}, fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return types.PairChallenge{}, fmt.Errorf("generate nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, aadBytes)
	combined := append(nonce, sealed...)

	challenge := types.PairChallenge{
		Type:        types.PairingMessageTypeChallenge,
		Version:     types.VersionV1,
		PairingID:   pairingID,
		ChallengeID: challengeID,
		Ciphertext:  base64.StdEncoding.EncodeToString(combined),
		AAD:         base64.StdEncoding.EncodeToString(aadBytes),
	}
	return challenge, nil
}

func deriveSymmetricKey(sharedSecret, aad []byte) []byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(aad)
	sum := h.Sum(nil)
	key := make([]byte, 32)
	copy(key, sum)
	return key
}

func decodeAAD(aadB64 string) ([]byte, error) {
	if strings.TrimSpace(aadB64) == "" {
		return nil, nil
	}
	aad, err := base64.StdEncoding.DecodeString(aadB64)
	if err != nil {
		return nil, fmt.Errorf("decode challenge aad: %w", err)
	}
	return aad, nil
}

func decodePublicKeyEd25519(publicKeyB64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode ed25519 public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
