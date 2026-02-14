package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

func TestSignAndVerifyPairInit(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	msg := types.PairInit{
		Type:      types.PairingMessageTypeInit,
		Version:   types.VersionV1,
		PairingID: "pair_1",
		Gateway: types.PairGatewayInfo{
			GatewayID:        "gw_1",
			PublicKeyEd25519: base64.StdEncoding.EncodeToString(pub),
			Nonce:            "nonce",
			IssuedAt:         time.Now().UTC(),
		},
	}
	sig, err := signPairInit(priv, msg)
	if err != nil {
		t.Fatalf("sign pair.init: %v", err)
	}
	msg.SigEd25519 = sig

	if err := verifyPairInit(pub, msg); err != nil {
		t.Fatalf("verify pair.init: %v", err)
	}
}

func TestSignAndVerifyPairIdentityAndChallengeResponse(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	identity := types.PairIdentity{
		Type:      types.PairingMessageTypeIdentity,
		Version:   types.VersionV1,
		PairingID: "pair_1",
		Remote: types.PairRemoteInfo{
			ComponentType:    types.ComponentTypeToolHost,
			ComponentID:      "tool_1",
			PublicKeyEd25519: base64.StdEncoding.EncodeToString(pub),
			PublicKeyX25519:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	identity.SigEd25519, err = signPairIdentity(priv, identity)
	if err != nil {
		t.Fatalf("sign pair.identity: %v", err)
	}

	verifiedPub, err := verifyPairIdentity(identity)
	if err != nil {
		t.Fatalf("verify pair.identity: %v", err)
	}

	response := types.PairChallengeResponse{
		Type:               types.PairingMessageTypeChallengeResponse,
		Version:            types.VersionV1,
		PairingID:          "pair_1",
		ChallengeID:        "challenge_1",
		ChallengePlaintext: "pt",
	}
	response.SigEd25519, err = signPairChallengeResponse(priv, response)
	if err != nil {
		t.Fatalf("sign challenge response: %v", err)
	}
	if err := verifyPairChallengeResponse(verifiedPub, response); err != nil {
		t.Fatalf("verify challenge response: %v", err)
	}
}

func TestSignAndVerifyPairCSRMessages(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	csrRequest := types.PairCSRRequest{
		Type:      types.PairingMessageTypeCSRRequest,
		Version:   types.VersionV1,
		PairingID: "pair_2",
		CSRPEM:    "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
	}
	csrRequest.SigEd25519, err = signPairCSRRequest(priv, csrRequest)
	if err != nil {
		t.Fatalf("sign pair.csr_request: %v", err)
	}
	if err := verifyPairCSRRequest(pub, csrRequest); err != nil {
		t.Fatalf("verify pair.csr_request: %v", err)
	}

	issued := types.PairCSRIssued{
		Type:                types.PairingMessageTypeCSRIssued,
		Version:             types.VersionV1,
		PairingID:           "pair_2",
		CertificatePEM:      "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
		CertificateChainPEM: []string{"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"},
		SerialNumber:        "1234abcd",
		MTLSCertFingerprint: "sha256:abcdef",
		NotBefore:           time.Now().UTC(),
		NotAfter:            time.Now().UTC().Add(24 * time.Hour),
	}
	issued.SigEd25519, err = signPairCSRIssued(priv, issued)
	if err != nil {
		t.Fatalf("sign pair.csr_issued: %v", err)
	}
	if err := verifyPairCSRIssued(pub, issued); err != nil {
		t.Fatalf("verify pair.csr_issued: %v", err)
	}

	installed := types.PairCSRInstalled{
		Type:                types.PairingMessageTypeCSRInstalled,
		Version:             types.VersionV1,
		PairingID:           "pair_2",
		MTLSCertFingerprint: "sha256:abcdef",
	}
	installed.SigEd25519, err = signPairCSRInstalled(priv, installed)
	if err != nil {
		t.Fatalf("sign pair.csr_installed: %v", err)
	}
	if err := verifyPairCSRInstalled(pub, installed); err != nil {
		t.Fatalf("verify pair.csr_installed: %v", err)
	}
}
