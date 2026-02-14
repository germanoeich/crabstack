package pairing

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"crabstack.local/lib/types"
)

func TestManagerPair_FullFlow(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}

	peerStorePath := filepath.Join(t.TempDir(), "pairing.db")
	peerStore, err := NewGormPeerStore("sqlite", peerStorePath)
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}
	csrPEM, err := newCSRPEM("memory-east")
	if err != nil {
		t.Fatalf("generate csr pem: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			t.Errorf("read pair.init: %v", err)
			return
		}
		if err := verifyPairInit(gatewayIdentity.PublicKey, initMsg); err != nil {
			t.Errorf("verify pair.init signature: %v", err)
			return
		}

		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:       types.ComponentTypeToolHost,
				ComponentID:         "memory-east",
				PublicKeyEd25519:    base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:     base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
				MTLSCertFingerprint: "sha256:remote",
			},
		}
		identityMsg.SigEd25519, err = signPairIdentity(remoteEdPriv, identityMsg)
		if err != nil {
			t.Errorf("sign pair.identity: %v", err)
			return
		}
		if err := conn.WriteJSON(identityMsg); err != nil {
			t.Errorf("write pair.identity: %v", err)
			return
		}

		var challengeMsg types.PairChallenge
		if err := conn.ReadJSON(&challengeMsg); err != nil {
			t.Errorf("read pair.challenge: %v", err)
			return
		}
		plaintext, err := decryptChallenge(remoteXPriv, challengeMsg.Ciphertext, challengeMsg.AAD)
		if err != nil {
			t.Errorf("decrypt challenge: %v", err)
			return
		}

		responseMsg := types.PairChallengeResponse{
			Type:               types.PairingMessageTypeChallengeResponse,
			Version:            types.VersionV1,
			PairingID:          challengeMsg.PairingID,
			ChallengeID:        challengeMsg.ChallengeID,
			ChallengePlaintext: plaintext,
		}
		responseMsg.SigEd25519, err = signPairChallengeResponse(remoteEdPriv, responseMsg)
		if err != nil {
			t.Errorf("sign challenge response: %v", err)
			return
		}
		if err := conn.WriteJSON(responseMsg); err != nil {
			t.Errorf("write challenge response: %v", err)
			return
		}

		csrRequest := types.PairCSRRequest{
			Type:      types.PairingMessageTypeCSRRequest,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			CSRPEM:    csrPEM,
		}
		csrRequest.SigEd25519, err = signPairCSRRequest(remoteEdPriv, csrRequest)
		if err != nil {
			t.Errorf("sign csr request: %v", err)
			return
		}
		if err := conn.WriteJSON(csrRequest); err != nil {
			t.Errorf("write csr request: %v", err)
			return
		}

		var issuedMsg types.PairCSRIssued
		if err := conn.ReadJSON(&issuedMsg); err != nil {
			t.Errorf("read pair.csr_issued: %v", err)
			return
		}
		if issuedMsg.Type != types.PairingMessageTypeCSRIssued {
			t.Errorf("unexpected type for pair.csr_issued: %s", issuedMsg.Type)
			return
		}
		if err := verifyPairCSRIssued(gatewayIdentity.PublicKey, issuedMsg); err != nil {
			t.Errorf("verify pair.csr_issued signature: %v", err)
			return
		}
		if strings.TrimSpace(issuedMsg.MTLSCertFingerprint) == "" {
			t.Errorf("expected issued certificate fingerprint")
			return
		}
		certBlock, _ := pem.Decode([]byte(issuedMsg.CertificatePEM))
		if certBlock == nil {
			t.Errorf("missing certificate pem block")
			return
		}
		if _, err := x509.ParseCertificate(certBlock.Bytes); err != nil {
			t.Errorf("parse issued certificate: %v", err)
			return
		}

		installed := types.PairCSRInstalled{
			Type:                types.PairingMessageTypeCSRInstalled,
			Version:             types.VersionV1,
			PairingID:           initMsg.PairingID,
			MTLSCertFingerprint: issuedMsg.MTLSCertFingerprint,
		}
		installed.SigEd25519, err = signPairCSRInstalled(remoteEdPriv, installed)
		if err != nil {
			t.Errorf("sign pair.csr_installed: %v", err)
			return
		}
		if err := conn.WriteJSON(installed); err != nil {
			t.Errorf("write pair.csr_installed: %v", err)
			return
		}

		var complete types.PairComplete
		if err := conn.ReadJSON(&complete); err != nil {
			t.Errorf("read pair.complete: %v", err)
			return
		}
		if complete.Type != types.PairingMessageTypeComplete || complete.Status != types.PairingStatusOK {
			t.Errorf("unexpected pair.complete: %+v", complete)
		}
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	u.Scheme = "ws"

	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	result, err := manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: u.String()})
	if err != nil {
		t.Fatalf("pair manager returned error: %v", err)
	}
	if result.PairingID == "" {
		t.Fatalf("expected pairing id")
	}
	if result.Peer.Status != types.PairedPeerStatusActive {
		t.Fatalf("expected active peer status, got %s", result.Peer.Status)
	}

	loaded, err := peerStore.GetPeerByEndpoint(context.Background(), u.String())
	if err != nil {
		t.Fatalf("load peer from store: %v", err)
	}
	if loaded.Status != types.PairedPeerStatusActive {
		t.Fatalf("expected active peer in store, got %s", loaded.Status)
	}
	if strings.TrimSpace(loaded.MTLSCertFingerprint) == "" {
		t.Fatalf("expected stored mTLS fingerprint from CSR install")
	}
}

func TestManagerPair_ComponentTypeMismatch(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}
		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeListener,
				ComponentID:      "listener-1",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		_ = conn.WriteJSON(identityMsg)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	u.Scheme = "ws"
	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: u.String()})
	if err == nil {
		t.Fatalf("expected component mismatch error")
	}
}

func TestManagerPair_RejectsIdentityWithEmptyComponentID(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}
		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeToolHost,
				ComponentID:      "",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		_ = conn.WriteJSON(identityMsg)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	u.Scheme = "ws"
	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: u.String()})
	if err == nil {
		t.Fatalf("expected empty component_id to be rejected")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected protocol violation, got %v", err)
	}
	if !strings.Contains(err.Error(), "component_id") {
		t.Fatalf("expected component_id validation error, got %v", err)
	}
}

func TestManagerPair_RejectsIdentityWithMismatchedRequestedComponentID(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}
		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeToolHost,
				ComponentID:      "tool-actual",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		_ = conn.WriteJSON(identityMsg)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	u.Scheme = "ws"
	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{
		ComponentType: types.ComponentTypeToolHost,
		ComponentID:   "tool-expected",
		Endpoint:      u.String(),
	})
	if err == nil {
		t.Fatalf("expected requested component_id mismatch error")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected protocol violation, got %v", err)
	}
	if !strings.Contains(err.Error(), "requested component_id") {
		t.Fatalf("expected requested component_id mismatch message, got %v", err)
	}
}

func TestReadPairIdentityHandlesPairError(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(types.PairError{Type: types.PairingMessageTypeError, Version: types.VersionV1, PairingID: "p1", Code: "X", Message: "boom"})
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	u.Scheme = "ws"
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer conn.Close()

	_, err = readPairIdentity(conn, time.Now().Add(2*time.Second))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrRemoteReturnedPairError) {
		t.Fatalf("expected ErrRemoteReturnedPairError, got %s", err)
	}
}

func TestManagerPair_DoesNotPersistWhenPairCompleteSendFails(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}
	csrPEM, err := newCSRPEM("new-remote")
	if err != nil {
		t.Fatalf("generate csr pem: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}

		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeToolHost,
				ComponentID:      "new-remote",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		if err := conn.WriteJSON(identityMsg); err != nil {
			return
		}

		var challengeMsg types.PairChallenge
		if err := conn.ReadJSON(&challengeMsg); err != nil {
			return
		}
		plaintext, err := decryptChallenge(remoteXPriv, challengeMsg.Ciphertext, challengeMsg.AAD)
		if err != nil {
			return
		}
		responseMsg := types.PairChallengeResponse{
			Type:               types.PairingMessageTypeChallengeResponse,
			Version:            types.VersionV1,
			PairingID:          challengeMsg.PairingID,
			ChallengeID:        challengeMsg.ChallengeID,
			ChallengePlaintext: plaintext,
		}
		responseMsg.SigEd25519, _ = signPairChallengeResponse(remoteEdPriv, responseMsg)
		if err := conn.WriteJSON(responseMsg); err != nil {
			return
		}

		csrRequest := types.PairCSRRequest{
			Type:      types.PairingMessageTypeCSRRequest,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			CSRPEM:    csrPEM,
		}
		csrRequest.SigEd25519, _ = signPairCSRRequest(remoteEdPriv, csrRequest)
		if err := conn.WriteJSON(csrRequest); err != nil {
			return
		}

		var issuedMsg types.PairCSRIssued
		if err := conn.ReadJSON(&issuedMsg); err != nil {
			return
		}

		installed := types.PairCSRInstalled{
			Type:                types.PairingMessageTypeCSRInstalled,
			Version:             types.VersionV1,
			PairingID:           initMsg.PairingID,
			MTLSCertFingerprint: issuedMsg.MTLSCertFingerprint,
		}
		installed.SigEd25519, _ = signPairCSRInstalled(remoteEdPriv, installed)
		if err := conn.WriteJSON(installed); err != nil {
			return
		}

		if tcpConn, ok := conn.UnderlyingConn().(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
			_ = tcpConn.Close()
			return
		}
		_ = conn.UnderlyingConn().Close()
	}))
	defer ts.Close()

	wsEndpoint := strings.Replace(ts.URL, "http://", "ws://", 1)
	now := time.Now().UTC()
	if err := peerStore.UpsertPeer(context.Background(), types.PairedPeerRecord{
		ComponentType:    types.ComponentTypeToolHost,
		ComponentID:      "existing-active",
		Endpoint:         wsEndpoint,
		PublicKeyEd25519: "existing-ed25519",
		PublicKeyX25519:  "existing-x25519",
		PairedAt:         now,
		LastSeenAt:       now,
		Status:           types.PairedPeerStatusActive,
	}); err != nil {
		t.Fatalf("seed existing active peer: %v", err)
	}

	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: wsEndpoint})
	if err == nil {
		t.Fatalf("expected pair.complete write to fail")
	}
	if !strings.Contains(err.Error(), "send pair.complete") {
		t.Fatalf("expected pair.complete write failure, got %v", err)
	}

	loaded, err := peerStore.GetPeerByEndpoint(context.Background(), wsEndpoint)
	if err != nil {
		t.Fatalf("load peer after failed pair.complete: %v", err)
	}
	if loaded.Status != types.PairedPeerStatusActive {
		t.Fatalf("expected active peer status to remain, got %s", loaded.Status)
	}
	if loaded.ComponentID != "existing-active" {
		t.Fatalf("expected existing active peer to remain unchanged, got component_id=%s", loaded.ComponentID)
	}
}

func TestManagerPair_DoesNotDowngradeExistingActivePeerOnFailure(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}

		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeToolHost,
				ComponentID:      "new-remote",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		_ = conn.WriteJSON(identityMsg)

		var challengeMsg types.PairChallenge
		if err := conn.ReadJSON(&challengeMsg); err != nil {
			return
		}
		plaintext, err := decryptChallenge(remoteXPriv, challengeMsg.Ciphertext, challengeMsg.AAD)
		if err != nil {
			return
		}

		responseMsg := types.PairChallengeResponse{
			Type:               types.PairingMessageTypeChallengeResponse,
			Version:            types.VersionV1,
			PairingID:          challengeMsg.PairingID,
			ChallengeID:        challengeMsg.ChallengeID,
			ChallengePlaintext: plaintext + "-tampered",
		}
		responseMsg.SigEd25519, _ = signPairChallengeResponse(remoteEdPriv, responseMsg)
		_ = conn.WriteJSON(responseMsg)
	}))
	defer ts.Close()

	wsEndpoint := strings.Replace(ts.URL, "http://", "ws://", 1)
	now := time.Now().UTC()
	if err := peerStore.UpsertPeer(context.Background(), types.PairedPeerRecord{
		ComponentType:    types.ComponentTypeToolHost,
		ComponentID:      "existing-active",
		Endpoint:         wsEndpoint,
		PublicKeyEd25519: "existing-ed25519",
		PublicKeyX25519:  "existing-x25519",
		PairedAt:         now,
		LastSeenAt:       now,
		Status:           types.PairedPeerStatusActive,
	}); err != nil {
		t.Fatalf("seed existing active peer: %v", err)
	}

	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: wsEndpoint})
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("expected challenge mismatch error, got %v", err)
	}

	loaded, err := peerStore.GetPeerByEndpoint(context.Background(), wsEndpoint)
	if err != nil {
		t.Fatalf("load peer after failed pair: %v", err)
	}
	if loaded.Status != types.PairedPeerStatusActive {
		t.Fatalf("expected active peer status to remain, got %s", loaded.Status)
	}
	if loaded.ComponentID != "existing-active" {
		t.Fatalf("expected existing active peer to remain unchanged, got component_id=%s", loaded.ComponentID)
	}
}

func TestManagerPair_RejectsChallengeResponseVersionMismatch(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}

		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeToolHost,
				ComponentID:      "remote-v2",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		_ = conn.WriteJSON(identityMsg)

		var challengeMsg types.PairChallenge
		if err := conn.ReadJSON(&challengeMsg); err != nil {
			return
		}
		plaintext, err := decryptChallenge(remoteXPriv, challengeMsg.Ciphertext, challengeMsg.AAD)
		if err != nil {
			return
		}

		responseMsg := types.PairChallengeResponse{
			Type:               types.PairingMessageTypeChallengeResponse,
			Version:            "v2",
			PairingID:          challengeMsg.PairingID,
			ChallengeID:        challengeMsg.ChallengeID,
			ChallengePlaintext: plaintext,
		}
		responseMsg.SigEd25519, _ = signPairChallengeResponse(remoteEdPriv, responseMsg)
		_ = conn.WriteJSON(responseMsg)
	}))
	defer ts.Close()

	wsEndpoint := strings.Replace(ts.URL, "http://", "ws://", 1)
	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: wsEndpoint})
	if err == nil {
		t.Fatalf("expected protocol violation error")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected protocol violation, got %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported version v2") {
		t.Fatalf("expected unsupported version error, got %v", err)
	}
}

func TestReadPairRawRejectsOversizedFrame(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		oversized := bytes.Repeat([]byte("a"), int(maxPairMessageBytes)+1)
		_ = conn.WriteMessage(websocket.TextMessage, oversized)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	u.Scheme = "ws"
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer conn.Close()

	_, err = readPairRaw(conn, time.Now().Add(2*time.Second))
	if err == nil {
		t.Fatalf("expected read limit error")
	}
	if !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("expected read limit failure, got %v", err)
	}
}

func TestManagerPair_EnforcesSingleHandshakeDeadline(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}
		time.Sleep(220 * time.Millisecond)

		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeToolHost,
				ComponentID:      "slow-remote",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		if err := conn.WriteJSON(identityMsg); err != nil {
			return
		}

		var challengeMsg types.PairChallenge
		if err := conn.ReadJSON(&challengeMsg); err != nil {
			return
		}
		plaintext, err := decryptChallenge(remoteXPriv, challengeMsg.Ciphertext, challengeMsg.AAD)
		if err != nil {
			return
		}
		time.Sleep(220 * time.Millisecond)

		responseMsg := types.PairChallengeResponse{
			Type:               types.PairingMessageTypeChallengeResponse,
			Version:            types.VersionV1,
			PairingID:          challengeMsg.PairingID,
			ChallengeID:        challengeMsg.ChallengeID,
			ChallengePlaintext: plaintext,
		}
		responseMsg.SigEd25519, _ = signPairChallengeResponse(remoteEdPriv, responseMsg)
		_ = conn.WriteJSON(responseMsg)
	}))
	defer ts.Close()

	wsEndpoint := strings.Replace(ts.URL, "http://", "ws://", 1)
	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 300*time.Millisecond, WithCertificateIssuer(certificateAuthority))

	startedAt := time.Now()
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: wsEndpoint})
	elapsed := time.Since(startedAt)

	if err == nil {
		t.Fatalf("expected handshake timeout failure")
	}
	if elapsed > 380*time.Millisecond {
		t.Fatalf("expected handshake to honor end-to-end timeout; elapsed=%s err=%v", elapsed, err)
	}
}

func TestManagerValidateRequest_RejectsRemoteWS(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{
		ComponentType: types.ComponentTypeToolHost,
		Endpoint:      "ws://10.0.0.1:5225",
	})
	if err == nil {
		t.Fatalf("expected remote ws endpoint to be rejected")
	}
	if !errors.Is(err, ErrMTLSRequired) {
		t.Fatalf("expected ErrMTLSRequired, got %v", err)
	}
}

func TestManagerValidateRequest_RejectsRemoteWSSWithoutClientCert(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{
		ComponentType: types.ComponentTypeToolHost,
		Endpoint:      "wss://10.0.0.1:5225",
	})
	if err == nil {
		t.Fatalf("expected remote wss endpoint without client cert to be rejected")
	}
	if !errors.Is(err, ErrMTLSRequired) {
		t.Fatalf("expected ErrMTLSRequired, got %v", err)
	}
}

func TestManagerPair_RejectsExistingActiveCertificateMismatch(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
	}))
	defer ts.Close()

	wsEndpoint := strings.Replace(ts.URL, "https://", "wss://", 1)
	now := time.Now().UTC()
	if err := peerStore.UpsertPeer(context.Background(), types.PairedPeerRecord{
		ComponentType:       types.ComponentTypeToolHost,
		ComponentID:         "existing-active",
		Endpoint:            wsEndpoint,
		PublicKeyEd25519:    "existing-ed25519",
		PublicKeyX25519:     "existing-x25519",
		MTLSCertFingerprint: "sha256:deadbeef",
		PairedAt:            now,
		LastSeenAt:          now,
		Status:              types.PairedPeerStatusActive,
	}); err != nil {
		t.Fatalf("seed existing active peer: %v", err)
	}

	manager := NewManager(
		log.New(os.Stdout, "", 0),
		gatewayIdentity,
		peerStore,
		5*time.Second,
		WithCertificateIssuer(certificateAuthority),
		WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}),
	)
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: wsEndpoint})
	if err == nil {
		t.Fatalf("expected cert fingerprint mismatch error")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected ErrProtocolViolation, got %v", err)
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected fingerprint mismatch message, got %v", err)
	}
}

func TestManagerPair_RejectsCSRRequestWithInvalidSignature(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	_, rogueEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate rogue ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}
	csrPEM, err := newCSRPEM("tool-invalid-signature")
	if err != nil {
		t.Fatalf("generate csr: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}
		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeToolHost,
				ComponentID:      "tool-invalid-signature",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		_ = conn.WriteJSON(identityMsg)

		var challengeMsg types.PairChallenge
		if err := conn.ReadJSON(&challengeMsg); err != nil {
			return
		}
		plaintext, err := decryptChallenge(remoteXPriv, challengeMsg.Ciphertext, challengeMsg.AAD)
		if err != nil {
			return
		}
		responseMsg := types.PairChallengeResponse{
			Type:               types.PairingMessageTypeChallengeResponse,
			Version:            types.VersionV1,
			PairingID:          challengeMsg.PairingID,
			ChallengeID:        challengeMsg.ChallengeID,
			ChallengePlaintext: plaintext,
		}
		responseMsg.SigEd25519, _ = signPairChallengeResponse(remoteEdPriv, responseMsg)
		_ = conn.WriteJSON(responseMsg)

		csrRequest := types.PairCSRRequest{
			Type:      types.PairingMessageTypeCSRRequest,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			CSRPEM:    csrPEM,
		}
		csrRequest.SigEd25519, _ = signPairCSRRequest(rogueEdPriv, csrRequest)
		_ = conn.WriteJSON(csrRequest)
	}))
	defer ts.Close()

	wsEndpoint := strings.Replace(ts.URL, "http://", "ws://", 1)
	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: wsEndpoint})
	if err == nil {
		t.Fatalf("expected csr signature verification to fail")
	}
	if !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("expected signature verification failure, got %v", err)
	}
}

func TestManagerPair_RejectsInvalidCSRPEM(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}
		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeToolHost,
				ComponentID:      "tool-invalid-csr",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		_ = conn.WriteJSON(identityMsg)

		var challengeMsg types.PairChallenge
		if err := conn.ReadJSON(&challengeMsg); err != nil {
			return
		}
		plaintext, err := decryptChallenge(remoteXPriv, challengeMsg.Ciphertext, challengeMsg.AAD)
		if err != nil {
			return
		}
		responseMsg := types.PairChallengeResponse{
			Type:               types.PairingMessageTypeChallengeResponse,
			Version:            types.VersionV1,
			PairingID:          challengeMsg.PairingID,
			ChallengeID:        challengeMsg.ChallengeID,
			ChallengePlaintext: plaintext,
		}
		responseMsg.SigEd25519, _ = signPairChallengeResponse(remoteEdPriv, responseMsg)
		_ = conn.WriteJSON(responseMsg)

		csrRequest := types.PairCSRRequest{
			Type:      types.PairingMessageTypeCSRRequest,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			CSRPEM:    "not-a-csr",
		}
		csrRequest.SigEd25519, _ = signPairCSRRequest(remoteEdPriv, csrRequest)
		_ = conn.WriteJSON(csrRequest)
	}))
	defer ts.Close()

	wsEndpoint := strings.Replace(ts.URL, "http://", "ws://", 1)
	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: wsEndpoint})
	if err == nil {
		t.Fatalf("expected invalid csr to fail")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected protocol violation, got %v", err)
	}
}

func TestManagerPair_RejectsCSRInstalledFingerprintMismatch(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	certificateAuthority, err := LoadOrCreateCertificateAuthority(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	remoteEdPub, remoteEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote ed25519: %v", err)
	}
	curve := ecdh.X25519()
	remoteXPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519: %v", err)
	}
	csrPEM, err := newCSRPEM("tool-fingerprint-mismatch")
	if err != nil {
		t.Fatalf("generate csr: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var initMsg types.PairInit
		if err := conn.ReadJSON(&initMsg); err != nil {
			return
		}
		identityMsg := types.PairIdentity{
			Type:      types.PairingMessageTypeIdentity,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			Remote: types.PairRemoteInfo{
				ComponentType:    types.ComponentTypeToolHost,
				ComponentID:      "tool-fingerprint-mismatch",
				PublicKeyEd25519: base64.StdEncoding.EncodeToString(remoteEdPub),
				PublicKeyX25519:  base64.StdEncoding.EncodeToString(remoteXPriv.PublicKey().Bytes()),
			},
		}
		identityMsg.SigEd25519, _ = signPairIdentity(remoteEdPriv, identityMsg)
		_ = conn.WriteJSON(identityMsg)

		var challengeMsg types.PairChallenge
		if err := conn.ReadJSON(&challengeMsg); err != nil {
			return
		}
		plaintext, err := decryptChallenge(remoteXPriv, challengeMsg.Ciphertext, challengeMsg.AAD)
		if err != nil {
			return
		}
		responseMsg := types.PairChallengeResponse{
			Type:               types.PairingMessageTypeChallengeResponse,
			Version:            types.VersionV1,
			PairingID:          challengeMsg.PairingID,
			ChallengeID:        challengeMsg.ChallengeID,
			ChallengePlaintext: plaintext,
		}
		responseMsg.SigEd25519, _ = signPairChallengeResponse(remoteEdPriv, responseMsg)
		_ = conn.WriteJSON(responseMsg)

		csrRequest := types.PairCSRRequest{
			Type:      types.PairingMessageTypeCSRRequest,
			Version:   types.VersionV1,
			PairingID: initMsg.PairingID,
			CSRPEM:    csrPEM,
		}
		csrRequest.SigEd25519, _ = signPairCSRRequest(remoteEdPriv, csrRequest)
		_ = conn.WriteJSON(csrRequest)

		var issuedMsg types.PairCSRIssued
		if err := conn.ReadJSON(&issuedMsg); err != nil {
			return
		}

		installed := types.PairCSRInstalled{
			Type:                types.PairingMessageTypeCSRInstalled,
			Version:             types.VersionV1,
			PairingID:           initMsg.PairingID,
			MTLSCertFingerprint: issuedMsg.MTLSCertFingerprint + "-wrong",
		}
		installed.SigEd25519, _ = signPairCSRInstalled(remoteEdPriv, installed)
		_ = conn.WriteJSON(installed)
	}))
	defer ts.Close()

	wsEndpoint := strings.Replace(ts.URL, "http://", "ws://", 1)
	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second, WithCertificateIssuer(certificateAuthority))
	_, err = manager.Pair(context.Background(), PairRequest{ComponentType: types.ComponentTypeToolHost, Endpoint: wsEndpoint})
	if err == nil {
		t.Fatalf("expected installed fingerprint mismatch to fail")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected protocol violation, got %v", err)
	}
	if !strings.Contains(err.Error(), "installed certificate fingerprint mismatch") {
		t.Fatalf("expected installed certificate mismatch error, got %v", err)
	}
}

func TestManagerPair_RequiresCertificateIssuer(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "keys")
	gatewayIdentity, err := LoadOrCreateIdentity(identityDir, "gw_test")
	if err != nil {
		t.Fatalf("load gateway identity: %v", err)
	}
	peerStore, err := NewGormPeerStore("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("new peer store: %v", err)
	}
	defer func() { _ = peerStore.Close() }()

	manager := NewManager(log.New(os.Stdout, "", 0), gatewayIdentity, peerStore, 5*time.Second)
	_, err = manager.Pair(context.Background(), PairRequest{
		ComponentType: types.ComponentTypeToolHost,
		Endpoint:      "ws://127.0.0.1:5225",
	})
	if err == nil {
		t.Fatalf("expected missing certificate issuer to fail")
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request, got %v", err)
	}
}

func newCSRPEM(commonName string) (string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: []string{"tool.local"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}
