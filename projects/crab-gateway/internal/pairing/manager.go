package pairing

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"crabstack.local/projects/crab-gateway/internal/ids"
	"crabstack.local/projects/crab-sdk/types"
)

const defaultPairTimeout = 15 * time.Second
const maxPairMessageBytes int64 = 64 * 1024

type Service interface {
	Pair(context.Context, PairRequest) (PairResult, error)
}

type PairRequest struct {
	ComponentType types.ComponentType `json:"component_type"`
	ComponentID   string              `json:"component_id,omitempty"`
	Endpoint      string              `json:"endpoint"`
}

type PairResult struct {
	PairingID string                 `json:"pairing_id"`
	Endpoint  string                 `json:"endpoint"`
	Peer      types.PairedPeerRecord `json:"peer"`
}

type Manager struct {
	logger                *log.Logger
	identity              *GatewayIdentity
	peers                 PeerStore
	certificateIssuer     CertificateIssuer
	dialer                websocket.Dialer
	timeout               time.Duration
	tlsClientConfig       *tls.Config
	requireMTLSRemote     bool
	allowInsecureLoopback bool
}

type ManagerOption func(*Manager)

func WithTLSClientConfig(cfg *tls.Config) ManagerOption {
	return func(m *Manager) {
		if cfg == nil {
			m.tlsClientConfig = nil
			return
		}
		m.tlsClientConfig = cfg.Clone()
	}
}

func WithRequireMTLSRemote(v bool) ManagerOption {
	return func(m *Manager) {
		m.requireMTLSRemote = v
	}
}

func WithAllowInsecureLoopback(v bool) ManagerOption {
	return func(m *Manager) {
		m.allowInsecureLoopback = v
	}
}

func WithCertificateIssuer(issuer CertificateIssuer) ManagerOption {
	return func(m *Manager) {
		m.certificateIssuer = issuer
	}
}

func NewManager(logger *log.Logger, identity *GatewayIdentity, peers PeerStore, timeout time.Duration, opts ...ManagerOption) *Manager {
	if timeout <= 0 {
		timeout = defaultPairTimeout
	}
	if logger == nil {
		logger = log.Default()
	}
	m := &Manager{
		logger:                logger,
		identity:              identity,
		peers:                 peers,
		timeout:               timeout,
		requireMTLSRemote:     true,
		allowInsecureLoopback: true,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m
}

func (m *Manager) Pair(ctx context.Context, req PairRequest) (PairResult, error) {
	endpointURL, loopbackEndpoint, err := m.validateRequest(req)
	if err != nil {
		return PairResult{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	handshakeDeadline := time.Now().Add(m.timeout)
	if deadline, ok := ctx.Deadline(); ok {
		handshakeDeadline = deadline
	}

	existingPeer, hasExistingPeer, err := m.getPeerByEndpointIfExists(ctx, req.Endpoint)
	if err != nil {
		return PairResult{}, fmt.Errorf("load existing peer: %w", err)
	}

	conn, err := m.dialPairEndpoint(ctx, endpointURL)
	if err != nil {
		return PairResult{}, err
	}
	defer conn.Close()

	observedFingerprint := ""
	if endpointURL.Scheme == "wss" {
		observedFingerprint, err = peerTLSFingerprint(conn)
		if err != nil {
			return PairResult{}, err
		}
		if hasExistingPeer &&
			existingPeer.Status == types.PairedPeerStatusActive &&
			strings.TrimSpace(existingPeer.MTLSCertFingerprint) != "" &&
			!fingerprintsEqual(existingPeer.MTLSCertFingerprint, observedFingerprint) {
			return PairResult{}, fmt.Errorf("%w: peer certificate fingerprint mismatch for existing endpoint", ErrProtocolViolation)
		}
	}
	if m.requireMTLSRemote && !loopbackEndpoint && strings.TrimSpace(observedFingerprint) == "" {
		return PairResult{}, fmt.Errorf("%w: missing observed remote certificate fingerprint", ErrMTLSRequired)
	}

	pairingID := ids.New()
	initMsg, err := m.buildPairInit(pairingID)
	if err != nil {
		return PairResult{}, err
	}
	if err := writePairMessage(conn, initMsg); err != nil {
		return PairResult{}, fmt.Errorf("send pair.init: %w", err)
	}

	identityMsg, err := readPairIdentity(conn, handshakeDeadline)
	if err != nil {
		return PairResult{}, err
	}
	if identityMsg.PairingID != pairingID {
		return PairResult{}, fmt.Errorf("%w: pairing id mismatch", ErrProtocolViolation)
	}
	if identityMsg.Version != types.VersionV1 {
		return PairResult{}, fmt.Errorf("%w: unsupported version %s", ErrProtocolViolation, identityMsg.Version)
	}

	remotePubKey, err := verifyPairIdentity(identityMsg)
	if err != nil {
		return PairResult{}, fmt.Errorf("verify pair.identity: %w", err)
	}
	if req.ComponentType != identityMsg.Remote.ComponentType {
		return PairResult{}, fmt.Errorf("%w: requested component=%s remote component=%s", ErrProtocolViolation, req.ComponentType, identityMsg.Remote.ComponentType)
	}
	if strings.TrimSpace(identityMsg.Remote.ComponentID) == "" {
		return PairResult{}, fmt.Errorf("%w: remote component_id is required", ErrProtocolViolation)
	}
	if requestedID := strings.TrimSpace(req.ComponentID); requestedID != "" && requestedID != identityMsg.Remote.ComponentID {
		return PairResult{}, fmt.Errorf("%w: requested component_id=%s remote component_id=%s", ErrProtocolViolation, requestedID, identityMsg.Remote.ComponentID)
	}
	if strings.TrimSpace(observedFingerprint) != "" {
		advertisedFingerprint := strings.TrimSpace(identityMsg.Remote.MTLSCertFingerprint)
		if advertisedFingerprint == "" {
			return PairResult{}, fmt.Errorf("%w: remote identity missing mtls_cert_fingerprint", ErrProtocolViolation)
		}
		if !fingerprintsEqual(advertisedFingerprint, observedFingerprint) {
			return PairResult{}, fmt.Errorf("%w: remote identity certificate fingerprint mismatch", ErrProtocolViolation)
		}
	}

	challengeID := ids.New()
	challengePlaintext, err := randomBase64(32)
	if err != nil {
		return PairResult{}, fmt.Errorf("generate challenge: %w", err)
	}
	ciphertext, aad, err := encryptChallenge(identityMsg.Remote.PublicKeyX25519, pairingID, challengeID, challengePlaintext)
	if err != nil {
		return PairResult{}, fmt.Errorf("encrypt challenge: %w", err)
	}

	challengeMsg := types.PairChallenge{
		Type:        types.PairingMessageTypeChallenge,
		Version:     types.VersionV1,
		PairingID:   pairingID,
		ChallengeID: challengeID,
		Ciphertext:  ciphertext,
		AAD:         aad,
	}
	if err := writePairMessage(conn, challengeMsg); err != nil {
		return PairResult{}, fmt.Errorf("send pair.challenge: %w", err)
	}

	responseMsg, err := readPairChallengeResponse(conn, handshakeDeadline)
	if err != nil {
		return PairResult{}, err
	}
	if responseMsg.PairingID != pairingID || responseMsg.ChallengeID != challengeID {
		return PairResult{}, fmt.Errorf("%w: challenge identity mismatch", ErrProtocolViolation)
	}
	if responseMsg.Version != types.VersionV1 {
		return PairResult{}, fmt.Errorf("%w: unsupported version %s", ErrProtocolViolation, responseMsg.Version)
	}
	if err := verifyPairChallengeResponse(remotePubKey, responseMsg); err != nil {
		return PairResult{}, fmt.Errorf("verify challenge response signature: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(responseMsg.ChallengePlaintext), []byte(challengePlaintext)) != 1 {
		return PairResult{}, ErrChallengeMismatch
	}

	csrRequest, err := readPairCSRRequest(conn, handshakeDeadline)
	if err != nil {
		return PairResult{}, err
	}
	if csrRequest.PairingID != pairingID {
		return PairResult{}, fmt.Errorf("%w: csr request pairing id mismatch", ErrProtocolViolation)
	}
	if csrRequest.Version != types.VersionV1 {
		return PairResult{}, fmt.Errorf("%w: unsupported version %s", ErrProtocolViolation, csrRequest.Version)
	}
	if err := verifyPairCSRRequest(remotePubKey, csrRequest); err != nil {
		return PairResult{}, fmt.Errorf("verify csr request signature: %w", err)
	}

	issuedCert, err := m.certificateIssuer.IssueFromCSR(csrRequest.CSRPEM, identityMsg.Remote.ComponentID)
	if err != nil {
		return PairResult{}, fmt.Errorf("issue mtls certificate: %w", err)
	}
	if strings.TrimSpace(issuedCert.Fingerprint) == "" {
		return PairResult{}, fmt.Errorf("%w: issued certificate fingerprint is empty", ErrProtocolViolation)
	}

	csrIssued := types.PairCSRIssued{
		Type:                types.PairingMessageTypeCSRIssued,
		Version:             types.VersionV1,
		PairingID:           pairingID,
		CertificatePEM:      issuedCert.CertificatePEM,
		CertificateChainPEM: issuedCert.CertificateChainPEM,
		SerialNumber:        issuedCert.SerialNumber,
		MTLSCertFingerprint: issuedCert.Fingerprint,
		NotBefore:           issuedCert.NotBefore,
		NotAfter:            issuedCert.NotAfter,
	}
	csrIssued.SigEd25519, err = signPairCSRIssued(m.identity.PrivateKey, csrIssued)
	if err != nil {
		return PairResult{}, fmt.Errorf("sign pair.csr_issued: %w", err)
	}
	if err := writePairMessage(conn, csrIssued); err != nil {
		return PairResult{}, fmt.Errorf("send pair.csr_issued: %w", err)
	}

	csrInstalled, err := readPairCSRInstalled(conn, handshakeDeadline)
	if err != nil {
		return PairResult{}, err
	}
	if csrInstalled.PairingID != pairingID {
		return PairResult{}, fmt.Errorf("%w: csr installed pairing id mismatch", ErrProtocolViolation)
	}
	if csrInstalled.Version != types.VersionV1 {
		return PairResult{}, fmt.Errorf("%w: unsupported version %s", ErrProtocolViolation, csrInstalled.Version)
	}
	if err := verifyPairCSRInstalled(remotePubKey, csrInstalled); err != nil {
		return PairResult{}, fmt.Errorf("verify csr installed signature: %w", err)
	}
	if !fingerprintsEqual(csrInstalled.MTLSCertFingerprint, issuedCert.Fingerprint) {
		return PairResult{}, fmt.Errorf("%w: installed certificate fingerprint mismatch", ErrProtocolViolation)
	}

	now := time.Now().UTC()
	storedFingerprint := strings.TrimSpace(csrInstalled.MTLSCertFingerprint)
	active := types.PairedPeerRecord{
		ComponentType:       identityMsg.Remote.ComponentType,
		ComponentID:         identityMsg.Remote.ComponentID,
		Endpoint:            req.Endpoint,
		PublicKeyEd25519:    identityMsg.Remote.PublicKeyEd25519,
		PublicKeyX25519:     identityMsg.Remote.PublicKeyX25519,
		MTLSCertFingerprint: storedFingerprint,
		PairedAt:            now,
		LastSeenAt:          now,
		Status:              types.PairedPeerStatusActive,
	}
	completeMsg := types.PairComplete{
		Type:      types.PairingMessageTypeComplete,
		Version:   types.VersionV1,
		PairingID: pairingID,
		Status:    types.PairingStatusOK,
	}
	if err := writePairMessage(conn, completeMsg); err != nil {
		return PairResult{}, fmt.Errorf("send pair.complete: %w", err)
	}
	if err := m.peers.UpsertPeer(ctx, active); err != nil {
		return PairResult{}, fmt.Errorf("activate peer: %w", err)
	}

	peer, err := m.peers.GetPeerByEndpoint(ctx, req.Endpoint)
	if err != nil {
		return PairResult{}, fmt.Errorf("load paired peer: %w", err)
	}
	return PairResult{PairingID: pairingID, Endpoint: req.Endpoint, Peer: peer}, nil
}

func (m *Manager) dialPairEndpoint(ctx context.Context, endpointURL *url.URL) (*websocket.Conn, error) {
	dialer := m.dialer
	if endpointURL.Scheme == "wss" && m.tlsClientConfig != nil {
		cfg := m.tlsClientConfig.Clone()
		host := endpointURL.Hostname()
		if cfg.ServerName == "" && host != "" && net.ParseIP(host) == nil {
			cfg.ServerName = host
		}
		dialer.TLSClientConfig = cfg
	}

	conn, _, err := dialer.DialContext(ctx, endpointURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("dial remote endpoint: %w", err)
	}
	return conn, nil
}

func (m *Manager) getPeerByEndpointIfExists(ctx context.Context, endpoint string) (types.PairedPeerRecord, bool, error) {
	peer, err := m.peers.GetPeerByEndpoint(ctx, endpoint)
	if err != nil {
		if errors.Is(err, ErrProtocolViolation) {
			return types.PairedPeerRecord{}, false, nil
		}
		return types.PairedPeerRecord{}, false, err
	}
	return peer, true, nil
}

func peerTLSFingerprint(conn *websocket.Conn) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("%w: missing websocket connection", ErrMTLSRequired)
	}
	tlsConn, ok := conn.UnderlyingConn().(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("%w: remote endpoint is not using tls", ErrMTLSRequired)
	}
	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete {
		if err := tlsConn.Handshake(); err != nil {
			return "", fmt.Errorf("%w: tls handshake incomplete: %v", ErrMTLSRequired, err)
		}
		state = tlsConn.ConnectionState()
	}
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("%w: remote endpoint did not present a certificate", ErrMTLSRequired)
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func fingerprintsEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func hasClientCertificate(cfg *tls.Config) bool {
	if cfg == nil {
		return false
	}
	if len(cfg.Certificates) > 0 {
		return true
	}
	return cfg.GetClientCertificate != nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (m *Manager) validateRequest(req PairRequest) (*url.URL, bool, error) {
	if m.identity == nil {
		return nil, false, fmt.Errorf("%w: gateway identity is not configured", ErrInvalidRequest)
	}
	if m.peers == nil {
		return nil, false, fmt.Errorf("%w: peer store is not configured", ErrInvalidRequest)
	}
	if strings.TrimSpace(m.identity.GatewayID) == "" || len(m.identity.PrivateKey) == 0 || len(m.identity.PublicKey) == 0 {
		return nil, false, fmt.Errorf("%w: gateway identity is incomplete", ErrInvalidRequest)
	}
	if m.certificateIssuer == nil {
		return nil, false, fmt.Errorf("%w: certificate issuer is not configured", ErrInvalidRequest)
	}

	if !isSupportedPairComponentType(req.ComponentType) {
		return nil, false, fmt.Errorf("%w: %s", ErrUnsupportedComponent, req.ComponentType)
	}
	if strings.TrimSpace(req.Endpoint) == "" {
		return nil, false, fmt.Errorf("%w: endpoint is required", ErrInvalidRequest)
	}
	parsed, err := url.Parse(req.Endpoint)
	if err != nil {
		return nil, false, fmt.Errorf("%w: invalid endpoint: %v", ErrInvalidRequest, err)
	}
	if parsed.Scheme != "ws" && parsed.Scheme != "wss" {
		return nil, false, fmt.Errorf("%w: endpoint must be ws:// or wss://", ErrInvalidRequest)
	}

	loopbackEndpoint := isLoopbackHost(parsed.Hostname())
	if parsed.Scheme == "ws" && (!loopbackEndpoint || !m.allowInsecureLoopback) {
		return nil, false, fmt.Errorf("%w: remote endpoint must use wss:// with mTLS", ErrMTLSRequired)
	}
	if parsed.Scheme == "ws" && m.requireMTLSRemote && !loopbackEndpoint {
		return nil, false, fmt.Errorf("%w: remote endpoint must use wss:// with mTLS", ErrMTLSRequired)
	}
	if parsed.Scheme == "wss" && m.requireMTLSRemote && !loopbackEndpoint && !hasClientCertificate(m.tlsClientConfig) {
		return nil, false, fmt.Errorf("%w: gateway mTLS client certificate is not configured", ErrMTLSRequired)
	}
	return parsed, loopbackEndpoint, nil
}

func (m *Manager) buildPairInit(pairingID string) (types.PairInit, error) {
	nonce, err := randomBase64(24)
	if err != nil {
		return types.PairInit{}, fmt.Errorf("generate init nonce: %w", err)
	}
	msg := types.PairInit{
		Type:      types.PairingMessageTypeInit,
		Version:   types.VersionV1,
		PairingID: pairingID,
		Gateway: types.PairGatewayInfo{
			GatewayID:        m.identity.GatewayID,
			PublicKeyEd25519: m.identity.PublicKeyBase64(),
			Nonce:            nonce,
			IssuedAt:         time.Now().UTC(),
		},
	}
	sig, err := signPairInit(m.identity.PrivateKey, msg)
	if err != nil {
		return types.PairInit{}, fmt.Errorf("sign pair.init: %w", err)
	}
	msg.SigEd25519 = sig
	return msg, nil
}

func isSupportedPairComponentType(t types.ComponentType) bool {
	switch t {
	case types.ComponentTypeToolHost,
		types.ComponentTypeListener,
		types.ComponentTypeSubscriber,
		types.ComponentTypeOperator:
		return true
	default:
		return false
	}
}

type pairingMessageEnvelope struct {
	Type types.PairingMessageType `json:"type"`
}

func readPairIdentity(conn *websocket.Conn, deadline time.Time) (types.PairIdentity, error) {
	data, err := readPairRaw(conn, deadline)
	if err != nil {
		return types.PairIdentity{}, err
	}

	var envelope pairingMessageEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return types.PairIdentity{}, fmt.Errorf("decode pair message envelope: %w", err)
	}
	if envelope.Type == types.PairingMessageTypeError {
		var msg types.PairError
		if err := json.Unmarshal(data, &msg); err != nil {
			return types.PairIdentity{}, fmt.Errorf("decode pair.error: %w", err)
		}
		return types.PairIdentity{}, fmt.Errorf("%w: %s %s", ErrRemoteReturnedPairError, msg.Code, msg.Message)
	}
	if envelope.Type != types.PairingMessageTypeIdentity {
		return types.PairIdentity{}, fmt.Errorf("%w: expected pair.identity, got %s", ErrProtocolViolation, envelope.Type)
	}

	var msg types.PairIdentity
	if err := json.Unmarshal(data, &msg); err != nil {
		return types.PairIdentity{}, fmt.Errorf("decode pair.identity: %w", err)
	}
	return msg, nil
}

func readPairChallengeResponse(conn *websocket.Conn, deadline time.Time) (types.PairChallengeResponse, error) {
	data, err := readPairRaw(conn, deadline)
	if err != nil {
		return types.PairChallengeResponse{}, err
	}

	var envelope pairingMessageEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return types.PairChallengeResponse{}, fmt.Errorf("decode pair message envelope: %w", err)
	}
	if envelope.Type == types.PairingMessageTypeError {
		var msg types.PairError
		if err := json.Unmarshal(data, &msg); err != nil {
			return types.PairChallengeResponse{}, fmt.Errorf("decode pair.error: %w", err)
		}
		return types.PairChallengeResponse{}, fmt.Errorf("%w: %s %s", ErrRemoteReturnedPairError, msg.Code, msg.Message)
	}
	if envelope.Type != types.PairingMessageTypeChallengeResponse {
		return types.PairChallengeResponse{}, fmt.Errorf("%w: expected pair.challenge_response, got %s", ErrProtocolViolation, envelope.Type)
	}

	var msg types.PairChallengeResponse
	if err := json.Unmarshal(data, &msg); err != nil {
		return types.PairChallengeResponse{}, fmt.Errorf("decode pair.challenge_response: %w", err)
	}
	return msg, nil
}

func readPairCSRRequest(conn *websocket.Conn, deadline time.Time) (types.PairCSRRequest, error) {
	data, err := readPairRaw(conn, deadline)
	if err != nil {
		return types.PairCSRRequest{}, err
	}

	var envelope pairingMessageEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return types.PairCSRRequest{}, fmt.Errorf("decode pair message envelope: %w", err)
	}
	if envelope.Type == types.PairingMessageTypeError {
		var msg types.PairError
		if err := json.Unmarshal(data, &msg); err != nil {
			return types.PairCSRRequest{}, fmt.Errorf("decode pair.error: %w", err)
		}
		return types.PairCSRRequest{}, fmt.Errorf("%w: %s %s", ErrRemoteReturnedPairError, msg.Code, msg.Message)
	}
	if envelope.Type != types.PairingMessageTypeCSRRequest {
		return types.PairCSRRequest{}, fmt.Errorf("%w: expected pair.csr_request, got %s", ErrProtocolViolation, envelope.Type)
	}

	var msg types.PairCSRRequest
	if err := json.Unmarshal(data, &msg); err != nil {
		return types.PairCSRRequest{}, fmt.Errorf("decode pair.csr_request: %w", err)
	}
	return msg, nil
}

func readPairCSRInstalled(conn *websocket.Conn, deadline time.Time) (types.PairCSRInstalled, error) {
	data, err := readPairRaw(conn, deadline)
	if err != nil {
		return types.PairCSRInstalled{}, err
	}

	var envelope pairingMessageEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return types.PairCSRInstalled{}, fmt.Errorf("decode pair message envelope: %w", err)
	}
	if envelope.Type == types.PairingMessageTypeError {
		var msg types.PairError
		if err := json.Unmarshal(data, &msg); err != nil {
			return types.PairCSRInstalled{}, fmt.Errorf("decode pair.error: %w", err)
		}
		return types.PairCSRInstalled{}, fmt.Errorf("%w: %s %s", ErrRemoteReturnedPairError, msg.Code, msg.Message)
	}
	if envelope.Type != types.PairingMessageTypeCSRInstalled {
		return types.PairCSRInstalled{}, fmt.Errorf("%w: expected pair.csr_installed, got %s", ErrProtocolViolation, envelope.Type)
	}

	var msg types.PairCSRInstalled
	if err := json.Unmarshal(data, &msg); err != nil {
		return types.PairCSRInstalled{}, fmt.Errorf("decode pair.csr_installed: %w", err)
	}
	return msg, nil
}

func readPairRaw(conn *websocket.Conn, deadline time.Time) ([]byte, error) {
	conn.SetReadLimit(maxPairMessageBytes)
	if !deadline.IsZero() {
		_ = conn.SetReadDeadline(deadline)
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read pairing message: %w", err)
	}
	return data, nil
}

func writePairMessage(conn *websocket.Conn, msg any) error {
	if err := conn.WriteJSON(msg); err != nil {
		return fmt.Errorf("write pairing message: %w", err)
	}
	return nil
}

func ParseComponentType(v string) (types.ComponentType, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "tool", "tool_host", "tool-host":
		return types.ComponentTypeToolHost, nil
	case "listener":
		return types.ComponentTypeListener, nil
	case "subscriber":
		return types.ComponentTypeSubscriber, nil
	case "operator", "cli":
		return types.ComponentTypeOperator, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedComponent, v)
	}
}
