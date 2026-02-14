package pairing

import (
	"bytes"
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
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"crabstack.local/lib/types"
	"crabstack.local/projects/crab-cli/internal/protocol"
)

const (
	defaultPairingPath = "/v1/pair"
	maxMessageBytes    = 64 * 1024
)

type Config struct {
	GatewayAdminSocketPath        string
	GatewayPublicKeyEd25519Base64 string
	ComponentType                 types.ComponentType
	ComponentID                   string
	ListenAddr                    string
	ListenPath                    string
	Timeout                       time.Duration
}

type Result struct {
	PairingID           string
	Endpoint            string
	ComponentID         string
	ComponentType       types.ComponentType
	MTLSCertFingerprint string
}

type GatewayPairConfig struct {
	GatewayAdminSocketPath string
	ComponentType          types.ComponentType
	ComponentID            string
	Endpoint               string
	Timeout                time.Duration
}

type GatewayPairResult struct {
	PairingID           string
	Endpoint            string
	ComponentID         string
	ComponentType       types.ComponentType
	MTLSCertFingerprint string
}

type gatewayPairRequest struct {
	ComponentType string `json:"component_type"`
	ComponentID   string `json:"component_id"`
	Endpoint      string `json:"endpoint"`
}

type gatewayPairResponse struct {
	PairingID string `json:"pairing_id"`
	Endpoint  string `json:"endpoint"`
	Peer      struct {
		ComponentID         string `json:"component_id"`
		ComponentType       string `json:"component_type"`
		MTLSCertFingerprint string `json:"mtls_cert_fingerprint"`
	} `json:"peer"`
}

type handshakeResult struct {
	pairingID   string
	fingerprint string
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.GatewayAdminSocketPath) == "" {
		return fmt.Errorf("gateway admin socket path is required")
	}
	if strings.TrimSpace(c.GatewayPublicKeyEd25519Base64) == "" {
		return fmt.Errorf("gateway public key is required")
	}
	if strings.TrimSpace(c.ComponentID) == "" {
		return fmt.Errorf("component_id is required")
	}
	if strings.TrimSpace(c.ListenAddr) == "" {
		return fmt.Errorf("listen addr is required")
	}
	path := strings.TrimSpace(c.ListenPath)
	if path == "" {
		path = defaultPairingPath
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("listen path must start with /")
	}
	switch c.ComponentType {
	case types.ComponentTypeToolHost, types.ComponentTypeListener, types.ComponentTypeSubscriber, types.ComponentTypeProvider:
	default:
		return fmt.Errorf("component_type must be one of tool_host, listener, subscriber, provider")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	return nil
}

func Pair(ctx context.Context, cfg Config) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	cfg.ListenPath = normalizePath(cfg.ListenPath)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Result{}, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	xPriv, xPubB64, err := protocol.GenerateX25519Keypair()
	if err != nil {
		return Result{}, err
	}

	state := &serverState{
		cfg:              cfg,
		ed25519Private:   edPriv,
		ed25519PublicB64: base64.StdEncoding.EncodeToString(edPub),
		x25519Private:    xPriv,
		x25519PublicB64:  xPubB64,
		done:             make(chan handshakeResult, 1),
		errs:             make(chan error, 1),
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return Result{}, fmt.Errorf("listen pair endpoint: %w", err)
	}
	defer listener.Close()

	endpoint := "ws://" + listener.Addr().String() + cfg.ListenPath
	server := &http.Server{
		Handler:           state.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			state.pushError(fmt.Errorf("serve pair endpoint: %w", err))
		}
	}()

	triggerCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	gwResp, err := callGatewayPair(triggerCtx, cfg.GatewayAdminSocketPath, cfg.Timeout, cfg.ComponentType, cfg.ComponentID, endpoint)
	if err != nil {
		select {
		case hsErr := <-state.errs:
			return Result{}, fmt.Errorf("%w (local endpoint error: %v)", err, hsErr)
		default:
		}
		return Result{}, err
	}

	select {
	case hsErr := <-state.errs:
		return Result{}, hsErr
	case hs := <-state.done:
		if strings.TrimSpace(gwResp.PairingID) != "" && hs.pairingID != gwResp.PairingID {
			return Result{}, fmt.Errorf("pairing_id mismatch between gateway response and handshake")
		}
		return Result{
			PairingID:           hs.pairingID,
			Endpoint:            endpoint,
			ComponentID:         cfg.ComponentID,
			ComponentType:       cfg.ComponentType,
			MTLSCertFingerprint: hs.fingerprint,
		}, nil
	case <-triggerCtx.Done():
		return Result{}, fmt.Errorf("wait for pairing completion: %w", triggerCtx.Err())
	}
}

func (c GatewayPairConfig) Validate() error {
	if strings.TrimSpace(c.GatewayAdminSocketPath) == "" {
		return fmt.Errorf("gateway admin socket path is required")
	}
	if strings.TrimSpace(c.ComponentID) == "" {
		return fmt.Errorf("component_id is required")
	}
	if strings.TrimSpace(c.Endpoint) == "" {
		return fmt.Errorf("endpoint is required")
	}
	switch c.ComponentType {
	case types.ComponentTypeToolHost, types.ComponentTypeListener, types.ComponentTypeSubscriber, types.ComponentTypeProvider:
	default:
		return fmt.Errorf("component_type must be one of tool_host, listener, subscriber, provider")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	return nil
}

func TriggerGatewayPair(ctx context.Context, cfg GatewayPairConfig) (GatewayPairResult, error) {
	if err := cfg.Validate(); err != nil {
		return GatewayPairResult{}, err
	}
	triggerCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	resp, err := callGatewayPair(
		triggerCtx,
		cfg.GatewayAdminSocketPath,
		cfg.Timeout,
		cfg.ComponentType,
		strings.TrimSpace(cfg.ComponentID),
		strings.TrimSpace(cfg.Endpoint),
	)
	if err != nil {
		return GatewayPairResult{}, err
	}

	resultComponentType := types.ComponentType(strings.TrimSpace(resp.Peer.ComponentType))
	if resultComponentType == "" {
		resultComponentType = cfg.ComponentType
	}
	return GatewayPairResult{
		PairingID:           resp.PairingID,
		Endpoint:            resp.Endpoint,
		ComponentID:         strings.TrimSpace(resp.Peer.ComponentID),
		ComponentType:       resultComponentType,
		MTLSCertFingerprint: strings.TrimSpace(resp.Peer.MTLSCertFingerprint),
	}, nil
}

type serverState struct {
	cfg              Config
	ed25519Private   ed25519.PrivateKey
	ed25519PublicB64 string
	x25519Private    *ecdh.PrivateKey
	x25519PublicB64  string

	doneOnce sync.Once
	errOnce  sync.Once
	done     chan handshakeResult
	errs     chan error
}

func (s *serverState) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.ListenPath, s.handlePair)
	return mux
}

func (s *serverState) handlePair(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.pushError(fmt.Errorf("upgrade websocket: %w", err))
		return
	}
	defer conn.Close()

	result, err := s.performHandshake(conn)
	if err != nil {
		_ = writeStep(conn, s.cfg.Timeout, types.PairError{
			Type:      types.PairingMessageTypeError,
			Version:   types.VersionV1,
			PairingID: "",
			Code:      "HANDSHAKE_FAILED",
			Message:   err.Error(),
		})
		s.pushError(err)
		return
	}
	s.doneOnce.Do(func() {
		s.done <- result
	})
}

func (s *serverState) performHandshake(conn *websocket.Conn) (handshakeResult, error) {
	initRaw, err := readStep(conn, s.cfg.Timeout)
	if err != nil {
		return handshakeResult{}, err
	}
	pairInit, err := protocol.DecodePairInit(initRaw)
	if err != nil {
		return handshakeResult{}, err
	}
	if err := protocol.VerifyPairInit(pairInit, s.cfg.GatewayPublicKeyEd25519Base64); err != nil {
		return handshakeResult{}, err
	}

	identity := types.PairIdentity{
		Type:      types.PairingMessageTypeIdentity,
		Version:   types.VersionV1,
		PairingID: pairInit.PairingID,
		Remote: types.PairRemoteInfo{
			ComponentType:    s.cfg.ComponentType,
			ComponentID:      s.cfg.ComponentID,
			PublicKeyEd25519: s.ed25519PublicB64,
			PublicKeyX25519:  s.x25519PublicB64,
		},
	}
	identity, err = protocol.SignPairIdentity(identity, s.ed25519Private)
	if err != nil {
		return handshakeResult{}, err
	}
	if err := writeStep(conn, s.cfg.Timeout, identity); err != nil {
		return handshakeResult{}, err
	}

	challengeRaw, err := readStep(conn, s.cfg.Timeout)
	if err != nil {
		return handshakeResult{}, err
	}
	var challenge types.PairChallenge
	if err := json.Unmarshal(challengeRaw, &challenge); err != nil {
		return handshakeResult{}, fmt.Errorf("decode pair.challenge: %w", err)
	}
	if challenge.Type != types.PairingMessageTypeChallenge {
		return handshakeResult{}, fmt.Errorf("unexpected pairing message type %q", challenge.Type)
	}
	if challenge.Version != types.VersionV1 {
		return handshakeResult{}, fmt.Errorf("unsupported pairing version %q", challenge.Version)
	}
	if challenge.PairingID != pairInit.PairingID {
		return handshakeResult{}, fmt.Errorf("pairing_id mismatch between pair.init and pair.challenge")
	}
	plaintext, err := protocol.DecryptPairChallenge(s.x25519Private, "", challenge)
	if err != nil {
		return handshakeResult{}, err
	}

	response := types.PairChallengeResponse{
		Type:               types.PairingMessageTypeChallengeResponse,
		Version:            types.VersionV1,
		PairingID:          challenge.PairingID,
		ChallengeID:        challenge.ChallengeID,
		ChallengePlaintext: string(plaintext),
	}
	response, err = protocol.SignPairChallengeResponse(response, s.ed25519Private)
	if err != nil {
		return handshakeResult{}, err
	}
	if err := writeStep(conn, s.cfg.Timeout, response); err != nil {
		return handshakeResult{}, err
	}

	csrPEM, err := buildCSR(s.cfg.ComponentID)
	if err != nil {
		return handshakeResult{}, err
	}
	csrReq := types.PairCSRRequest{
		Type:      types.PairingMessageTypeCSRRequest,
		Version:   types.VersionV1,
		PairingID: pairInit.PairingID,
		CSRPEM:    csrPEM,
	}
	csrReq, err = protocol.SignPairCSRRequest(csrReq, s.ed25519Private)
	if err != nil {
		return handshakeResult{}, err
	}
	if err := writeStep(conn, s.cfg.Timeout, csrReq); err != nil {
		return handshakeResult{}, err
	}

	issuedRaw, err := readStep(conn, s.cfg.Timeout)
	if err != nil {
		return handshakeResult{}, err
	}
	var issued types.PairCSRIssued
	if err := json.Unmarshal(issuedRaw, &issued); err != nil {
		return handshakeResult{}, fmt.Errorf("decode pair.csr_issued: %w", err)
	}
	if issued.Type != types.PairingMessageTypeCSRIssued {
		return handshakeResult{}, fmt.Errorf("unexpected pairing message type %q", issued.Type)
	}
	if issued.Version != types.VersionV1 {
		return handshakeResult{}, fmt.Errorf("unsupported pairing version %q", issued.Version)
	}
	if issued.PairingID != pairInit.PairingID {
		return handshakeResult{}, fmt.Errorf("pairing_id mismatch between pair.init and pair.csr_issued")
	}
	if err := protocol.VerifyPairCSRIssued(issued, s.cfg.GatewayPublicKeyEd25519Base64); err != nil {
		return handshakeResult{}, err
	}
	issuedFingerprint, err := certificateFingerprintSHA256(issued.CertificatePEM)
	if err != nil {
		return handshakeResult{}, err
	}
	if !strings.EqualFold(issuedFingerprint, issued.MTLSCertFingerprint) {
		return handshakeResult{}, fmt.Errorf("issued certificate fingerprint mismatch")
	}

	installed := types.PairCSRInstalled{
		Type:                types.PairingMessageTypeCSRInstalled,
		Version:             types.VersionV1,
		PairingID:           pairInit.PairingID,
		MTLSCertFingerprint: issued.MTLSCertFingerprint,
	}
	installed, err = protocol.SignPairCSRInstalled(installed, s.ed25519Private)
	if err != nil {
		return handshakeResult{}, err
	}
	if err := writeStep(conn, s.cfg.Timeout, installed); err != nil {
		return handshakeResult{}, err
	}

	completeRaw, err := readStep(conn, s.cfg.Timeout)
	if err != nil {
		return handshakeResult{}, err
	}
	var complete types.PairComplete
	if err := json.Unmarshal(completeRaw, &complete); err != nil {
		return handshakeResult{}, fmt.Errorf("decode pair.complete: %w", err)
	}
	if complete.Type != types.PairingMessageTypeComplete {
		return handshakeResult{}, fmt.Errorf("unexpected pairing message type %q", complete.Type)
	}
	if complete.Version != types.VersionV1 {
		return handshakeResult{}, fmt.Errorf("unsupported pairing version %q", complete.Version)
	}
	if complete.PairingID != pairInit.PairingID {
		return handshakeResult{}, fmt.Errorf("pairing_id mismatch between pair.init and pair.complete")
	}
	if complete.Status != types.PairingStatusOK {
		return handshakeResult{}, fmt.Errorf("pairing failed with status %q", complete.Status)
	}

	return handshakeResult{
		pairingID:   complete.PairingID,
		fingerprint: issued.MTLSCertFingerprint,
	}, nil
}

func (s *serverState) pushError(err error) {
	if err == nil {
		return
	}
	s.errOnce.Do(func() {
		s.errs <- err
	})
}

func callGatewayPair(ctx context.Context, adminSocketPath string, timeout time.Duration, componentType types.ComponentType, componentID, endpoint string) (gatewayPairResponse, error) {
	requestBody := gatewayPairRequest{
		ComponentType: string(componentType),
		ComponentID:   strings.TrimSpace(componentID),
		Endpoint:      endpoint,
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return gatewayPairResponse{}, fmt.Errorf("marshal pair request: %w", err)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", adminSocketPath)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/pairings", bytes.NewReader(encoded))
	if err != nil {
		return gatewayPairResponse{}, fmt.Errorf("build pair request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return gatewayPairResponse{}, fmt.Errorf("call gateway pairing endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return gatewayPairResponse{}, fmt.Errorf("read gateway pairing response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return gatewayPairResponse{}, fmt.Errorf("gateway pairing failed: %s", msg)
	}

	var result gatewayPairResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return gatewayPairResponse{}, fmt.Errorf("decode gateway pairing response: %w", err)
	}
	return result, nil
}

func readStep(conn *websocket.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadLimit(maxMessageBytes)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	_, payload, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read websocket message: %w", err)
	}

	var envelope struct {
		Type types.PairingMessageType `json:"type"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode pairing message envelope: %w", err)
	}
	if envelope.Type == types.PairingMessageTypeError {
		var msg types.PairError
		if err := json.Unmarshal(payload, &msg); err != nil {
			return nil, fmt.Errorf("decode pair.error: %w", err)
		}
		return nil, fmt.Errorf("pairing error %s: %s", msg.Code, msg.Message)
	}
	return payload, nil
}

func writeStep(conn *websocket.Conn, timeout time.Duration, msg any) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if err := conn.WriteJSON(msg); err != nil {
		return fmt.Errorf("write websocket message: %w", err)
	}
	return nil
}

func buildCSR(commonName string) (string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate csr private key: %w", err)
	}
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		commonName = "crab-cli"
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return "", fmt.Errorf("create csr: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return defaultPairingPath
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func certificateFingerprintSHA256(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("invalid certificate pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
