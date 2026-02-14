package protocol

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

func TestVerifyPairInit(t *testing.T) {
	gatewayPub, gatewayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate gateway keypair: %v", err)
	}
	gatewayPubB64 := base64.StdEncoding.EncodeToString(gatewayPub)

	msg := PairInitWire{
		Type:      types.PairingMessageTypeInit,
		Version:   types.VersionV1,
		PairingID: "pair_123",
		Gateway: PairGatewayInfoWire{
			GatewayID:        "gateway-core",
			PublicKeyEd25519: gatewayPubB64,
			PublicKeyX25519:  "x25519-pub",
			Nonce:            "nonce",
			IssuedAt:         time.Now().UTC(),
		},
	}

	signed, err := SignPairInit(msg, gatewayPriv)
	if err != nil {
		t.Fatalf("sign pair.init: %v", err)
	}

	if err := VerifyPairInit(signed, gatewayPubB64); err != nil {
		t.Fatalf("expected pair.init signature verification to succeed, got %v", err)
	}

	if err := VerifyPairInit(signed, "bad"); err == nil {
		t.Fatalf("expected pair.init verification to fail with mismatched configured key")
	}
}

func TestEncryptDecryptPairChallengeRoundTrip(t *testing.T) {
	gatewayPriv, gatewayPubB64, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate gateway x25519 keypair: %v", err)
	}
	remotePriv, remotePubB64, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate remote x25519 keypair: %v", err)
	}

	plaintext := []byte("challenge-bytes")
	aad := []byte("aad")

	challenge, err := EncryptPairChallenge(gatewayPriv, remotePubB64, "pair_1", "chal_1", plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt challenge: %v", err)
	}

	decrypted, err := DecryptPairChallenge(remotePriv, gatewayPubB64, challenge)
	if err != nil {
		t.Fatalf("decrypt challenge: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch got=%q want=%q", string(decrypted), string(plaintext))
	}
}

func TestVerifyPairChallengeResponse(t *testing.T) {
	remotePub, remotePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote keypair: %v", err)
	}
	remotePubB64 := base64.StdEncoding.EncodeToString(remotePub)

	msg := types.PairChallengeResponse{
		Type:               types.PairingMessageTypeChallengeResponse,
		Version:            types.VersionV1,
		PairingID:          "pair_1",
		ChallengeID:        "chal_1",
		ChallengePlaintext: base64.StdEncoding.EncodeToString([]byte("hello")),
	}
	msg, err = SignPairChallengeResponse(msg, remotePriv)
	if err != nil {
		t.Fatalf("sign pair.challenge_response: %v", err)
	}

	if err := VerifyPairChallengeResponse(msg, remotePubB64); err != nil {
		t.Fatalf("expected verification success, got %v", err)
	}

	if err := VerifyPairChallengeResponse(msg, base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))); err == nil {
		t.Fatalf("expected verification failure with wrong key")
	}
}

func TestDecodePublicKeyX25519RejectsInvalidInput(t *testing.T) {
	if _, err := DecodePublicKeyX25519("not-base64"); err == nil {
		t.Fatalf("expected decode error")
	}
	if _, err := DecodePublicKeyX25519(base64.StdEncoding.EncodeToString(make([]byte, 10))); err == nil {
		t.Fatalf("expected parse error for short public key")
	}
}

func TestSignPairCSRRequestAndInstalled(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}

	csrReq := types.PairCSRRequest{
		Type:      types.PairingMessageTypeCSRRequest,
		Version:   types.VersionV1,
		PairingID: "pair_1",
		CSRPEM:    "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
	}
	csrReq, err = SignPairCSRRequest(csrReq, privateKey)
	if err != nil {
		t.Fatalf("sign pair.csr_request: %v", err)
	}
	if csrReq.SigEd25519 == "" {
		t.Fatalf("expected pair.csr_request signature")
	}

	installed := types.PairCSRInstalled{
		Type:                types.PairingMessageTypeCSRInstalled,
		Version:             types.VersionV1,
		PairingID:           "pair_1",
		MTLSCertFingerprint: "sha256:abcd",
	}
	installed, err = SignPairCSRInstalled(installed, privateKey)
	if err != nil {
		t.Fatalf("sign pair.csr_installed: %v", err)
	}
	if installed.SigEd25519 == "" {
		t.Fatalf("expected pair.csr_installed signature")
	}
}

func TestVerifyPairCSRIssued(t *testing.T) {
	gatewayPub, gatewayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate gateway ed25519 keypair: %v", err)
	}
	gatewayPubB64 := base64.StdEncoding.EncodeToString(gatewayPub)

	certPEM, fingerprint, err := generateTestCertificatePEM()
	if err != nil {
		t.Fatalf("generate certificate pem: %v", err)
	}

	issued := types.PairCSRIssued{
		Type:                types.PairingMessageTypeCSRIssued,
		Version:             types.VersionV1,
		PairingID:           "pair_1",
		CertificatePEM:      certPEM,
		CertificateChainPEM: []string{"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"},
		SerialNumber:        "1234",
		MTLSCertFingerprint: fingerprint,
		NotBefore:           time.Now().UTC(),
		NotAfter:            time.Now().UTC().Add(24 * time.Hour),
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
		Type:                issued.Type,
		Version:             issued.Version,
		PairingID:           issued.PairingID,
		CertificatePEM:      issued.CertificatePEM,
		CertificateChainPEM: issued.CertificateChainPEM,
		SerialNumber:        issued.SerialNumber,
		MTLSCertFingerprint: issued.MTLSCertFingerprint,
		NotBefore:           issued.NotBefore.UTC().Format(time.RFC3339Nano),
		NotAfter:            issued.NotAfter.UTC().Format(time.RFC3339Nano),
	}
	sig, err := SignMessage(payload, gatewayPriv)
	if err != nil {
		t.Fatalf("sign pair.csr_issued payload: %v", err)
	}
	issued.SigEd25519 = sig

	if err := VerifyPairCSRIssued(issued, gatewayPubB64); err != nil {
		t.Fatalf("verify pair.csr_issued: %v", err)
	}
}

func generateTestCertificatePEM() (string, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	template := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "crab-cli-test"},
		NotBefore:             time.Now().UTC().Add(-1 * time.Hour),
		NotAfter:              time.Now().UTC().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(der)
	fingerprint := "sha256:" + hex.EncodeToString(sum[:])
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), fingerprint, nil
}

func newSerial() *big.Int {
	return big.NewInt(time.Now().UTC().UnixNano())
}
