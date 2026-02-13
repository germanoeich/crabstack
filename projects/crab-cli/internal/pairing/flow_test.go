package pairing

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"crabstack.local/lib/types"
	"crabstack.local/projects/crab-cli/internal/protocol"
)

func TestPair(t *testing.T) {
	tcpProbe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
	}
	_ = tcpProbe.Close()

	gatewayPub, gatewayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate gateway keypair: %v", err)
	}
	gatewayPubB64 := base64.StdEncoding.EncodeToString(gatewayPub)

	caCert, caKey, err := generateTestCA()
	if err != nil {
		t.Fatalf("generate test ca: %v", err)
	}

	adminSocket := filepath.Join(t.TempDir(), "gateway-admin.sock")
	if err := os.Remove(adminSocket); err != nil && !os.IsNotExist(err) {
		t.Fatalf("cleanup socket path: %v", err)
	}
	listener, err := net.Listen("unix", adminSocket)
	if err != nil {
		t.Skipf("unix socket listen not permitted in this environment: %v", err)
	}
	defer listener.Close()

	serverErrCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pairings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req gatewayPairRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Endpoint) == "" {
			http.Error(w, "endpoint is required", http.StatusBadRequest)
			return
		}

		dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
		conn, _, err := dialer.Dial(req.Endpoint, nil)
		if err != nil {
			serverErrCh <- fmt.Errorf("dial cli endpoint: %w", err)
			http.Error(w, "pair dial failed", http.StatusBadGateway)
			return
		}
		defer conn.Close()

		pairingID := "pair_test_1"
		initMsg := protocol.PairInitWire{
			Type:      types.PairingMessageTypeInit,
			Version:   types.VersionV1,
			PairingID: pairingID,
			Gateway: protocol.PairGatewayInfoWire{
				GatewayID:        "gateway-test",
				PublicKeyEd25519: gatewayPubB64,
				Nonce:            "nonce",
				IssuedAt:         time.Now().UTC(),
			},
		}
		initMsg, err = protocol.SignPairInit(initMsg, gatewayPriv)
		if err != nil {
			serverErrCh <- fmt.Errorf("sign pair.init: %w", err)
			http.Error(w, "sign init failed", http.StatusInternalServerError)
			return
		}
		if err := conn.WriteJSON(initMsg); err != nil {
			serverErrCh <- fmt.Errorf("write pair.init: %w", err)
			http.Error(w, "write init failed", http.StatusBadGateway)
			return
		}

		var identity types.PairIdentity
		if err := conn.ReadJSON(&identity); err != nil {
			serverErrCh <- fmt.Errorf("read pair.identity: %w", err)
			http.Error(w, "read identity failed", http.StatusBadGateway)
			return
		}
		if err := protocol.VerifyPairIdentity(identity); err != nil {
			serverErrCh <- fmt.Errorf("verify pair.identity: %w", err)
			http.Error(w, "verify identity failed", http.StatusBadGateway)
			return
		}

		challenge, err := protocol.EncryptPairChallenge(
			mustGenerateX25519Private(t),
			identity.Remote.PublicKeyX25519,
			pairingID,
			"challenge_1",
			[]byte("proof"),
			nil,
		)
		if err != nil {
			serverErrCh <- fmt.Errorf("encrypt challenge: %w", err)
			http.Error(w, "encrypt challenge failed", http.StatusInternalServerError)
			return
		}
		if err := conn.WriteJSON(challenge); err != nil {
			serverErrCh <- fmt.Errorf("write pair.challenge: %w", err)
			http.Error(w, "write challenge failed", http.StatusBadGateway)
			return
		}

		var challengeResp types.PairChallengeResponse
		if err := conn.ReadJSON(&challengeResp); err != nil {
			serverErrCh <- fmt.Errorf("read pair.challenge_response: %w", err)
			http.Error(w, "read challenge response failed", http.StatusBadGateway)
			return
		}
		if err := protocol.VerifyPairChallengeResponse(challengeResp, identity.Remote.PublicKeyEd25519); err != nil {
			serverErrCh <- fmt.Errorf("verify pair.challenge_response: %w", err)
			http.Error(w, "verify challenge response failed", http.StatusBadGateway)
			return
		}
		if challengeResp.ChallengePlaintext != "proof" {
			serverErrCh <- fmt.Errorf("unexpected challenge plaintext %q", challengeResp.ChallengePlaintext)
			http.Error(w, "invalid challenge proof", http.StatusBadGateway)
			return
		}

		var csrReq types.PairCSRRequest
		if err := conn.ReadJSON(&csrReq); err != nil {
			serverErrCh <- fmt.Errorf("read pair.csr_request: %w", err)
			http.Error(w, "read csr request failed", http.StatusBadGateway)
			return
		}
		if err := verifyCSRRequestSignature(csrReq, identity.Remote.PublicKeyEd25519); err != nil {
			serverErrCh <- fmt.Errorf("verify pair.csr_request signature: %w", err)
			http.Error(w, "verify csr request failed", http.StatusBadGateway)
			return
		}
		issuedCertPEM, fingerprint, notBefore, notAfter, err := issueCertificateFromCSR(csrReq.CSRPEM, caCert, caKey)
		if err != nil {
			serverErrCh <- fmt.Errorf("issue certificate: %w", err)
			http.Error(w, "issue cert failed", http.StatusInternalServerError)
			return
		}

		issued := types.PairCSRIssued{
			Type:                types.PairingMessageTypeCSRIssued,
			Version:             types.VersionV1,
			PairingID:           pairingID,
			CertificatePEM:      issuedCertPEM,
			SerialNumber:        "1",
			MTLSCertFingerprint: fingerprint,
			NotBefore:           notBefore,
			NotAfter:            notAfter,
		}
		issuedPayload := struct {
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
		issuedSig, err := protocol.SignMessage(issuedPayload, gatewayPriv)
		if err != nil {
			serverErrCh <- fmt.Errorf("sign pair.csr_issued: %w", err)
			http.Error(w, "sign issued failed", http.StatusInternalServerError)
			return
		}
		issued.SigEd25519 = issuedSig
		if err := conn.WriteJSON(issued); err != nil {
			serverErrCh <- fmt.Errorf("write pair.csr_issued: %w", err)
			http.Error(w, "write issued failed", http.StatusBadGateway)
			return
		}

		var installed types.PairCSRInstalled
		if err := conn.ReadJSON(&installed); err != nil {
			serverErrCh <- fmt.Errorf("read pair.csr_installed: %w", err)
			http.Error(w, "read installed failed", http.StatusBadGateway)
			return
		}
		if err := verifyCSRInstalledSignature(installed, identity.Remote.PublicKeyEd25519); err != nil {
			serverErrCh <- fmt.Errorf("verify pair.csr_installed signature: %w", err)
			http.Error(w, "verify installed failed", http.StatusBadGateway)
			return
		}
		if !strings.EqualFold(installed.MTLSCertFingerprint, fingerprint) {
			serverErrCh <- fmt.Errorf("installed fingerprint mismatch")
			http.Error(w, "installed fingerprint mismatch", http.StatusBadGateway)
			return
		}

		complete := types.PairComplete{
			Type:      types.PairingMessageTypeComplete,
			Version:   types.VersionV1,
			PairingID: pairingID,
			Status:    types.PairingStatusOK,
		}
		if err := conn.WriteJSON(complete); err != nil {
			serverErrCh <- fmt.Errorf("write pair.complete: %w", err)
			http.Error(w, "write complete failed", http.StatusBadGateway)
			return
		}

		_ = json.NewEncoder(w).Encode(gatewayPairResponse{
			PairingID: pairingID,
			Endpoint:  req.Endpoint,
			Peer: struct {
				ComponentID         string `json:"component_id"`
				ComponentType       string `json:"component_type"`
				MTLSCertFingerprint string `json:"mtls_cert_fingerprint"`
			}{
				ComponentID:         identity.Remote.ComponentID,
				ComponentType:       string(identity.Remote.ComponentType),
				MTLSCertFingerprint: fingerprint,
			},
		})
	})

	server := &http.Server{Handler: mux}
	defer server.Shutdown(context.Background())
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := Pair(ctx, Config{
		GatewayAdminSocketPath:        adminSocket,
		GatewayPublicKeyEd25519Base64: gatewayPubB64,
		ComponentType:                 types.ComponentTypeToolHost,
		ComponentID:                   "cli-test",
		ListenAddr:                    "127.0.0.1:0",
		ListenPath:                    "/v1/pair",
		Timeout:                       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if strings.TrimSpace(result.PairingID) == "" {
		t.Fatalf("expected pairing_id")
	}
	if strings.TrimSpace(result.MTLSCertFingerprint) == "" {
		t.Fatalf("expected mtls certificate fingerprint")
	}

	select {
	case err := <-serverErrCh:
		t.Fatalf("mock gateway error: %v", err)
	default:
	}
}

func mustGenerateX25519Private(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 private key: %v", err)
	}
	return privateKey
}

func generateTestCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crab-cli-test-ca"},
		NotBefore:             time.Now().UTC().Add(-1 * time.Hour),
		NotAfter:              time.Now().UTC().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, caKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return caCert, caKey, nil
}

func issueCertificateFromCSR(csrPEM string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (string, string, time.Time, time.Time, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("invalid csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}

	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := time.Now().UTC().Add(24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UTC().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	sum := sha256.Sum256(der)
	fingerprint := "sha256:" + hex.EncodeToString(sum[:])
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), fingerprint, notBefore, notAfter, nil
}

func verifyCSRRequestSignature(msg types.PairCSRRequest, publicKeyB64 string) error {
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
	return protocol.VerifySignedMessage(payload, publicKeyB64, msg.SigEd25519)
}

func verifyCSRInstalledSignature(msg types.PairCSRInstalled, publicKeyB64 string) error {
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
	return protocol.VerifySignedMessage(payload, publicKeyB64, msg.SigEd25519)
}
