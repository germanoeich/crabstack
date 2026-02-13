package client

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"pinchy.local/lib/types"
	"pinchy.local/projects/pinchy-cli/internal/protocol"
)

const ioTimeout = 10 * time.Second

type Client struct {
	cfg Config

	ed25519Private ed25519.PrivateKey
	ed25519Public  string
	x25519Private  *ecdh.PrivateKey
	x25519Public   string

	mu      sync.RWMutex
	writeMu sync.Mutex
	conn    *websocket.Conn
	closed  bool

	events chan types.EventEnvelope
	errs   chan error
	done   chan struct{}
}

func New(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}

	xPriv, xPub, err := protocol.GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:            cfg,
		ed25519Private: priv,
		ed25519Public:  base64.StdEncoding.EncodeToString(pub),
		x25519Private:  xPriv,
		x25519Public:   xPub,
		events:         make(chan types.EventEnvelope, 64),
		errs:           make(chan error, 16),
		done:           make(chan struct{}),
	}, nil
}

func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.conn != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	dialer := websocket.Dialer{HandshakeTimeout: ioTimeout}
	conn, _, err := dialer.DialContext(ctx, c.cfg.GatewayWSURL, nil)
	if err != nil {
		return fmt.Errorf("dial gateway websocket: %w", err)
	}

	if err := c.performPairing(conn); err != nil {
		_ = conn.Close()
		return err
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	go c.readLoop()
	return nil
}

func (c *Client) Events() <-chan types.EventEnvelope {
	return c.events
}

func (c *Client) Errors() <-chan error {
	return c.errs
}

func (c *Client) Done() <-chan struct{} {
	return c.done
}

func (c *Client) SendTextMessage(ctx context.Context, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return fmt.Errorf("message text is required")
	}

	payload, err := json.Marshal(types.ChannelMessageReceivedPayload{Text: text})
	if err != nil {
		return fmt.Errorf("marshal channel.message.received payload: %w", err)
	}

	event := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    newID(),
		TraceID:    newID(),
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   c.cfg.TenantID,
		Source: types.EventSource{
			ComponentType: c.cfg.ComponentType,
			ComponentID:   c.cfg.ComponentID,
			Platform:      c.cfg.Platform,
			ChannelID:     c.cfg.ChannelID,
			ActorID:       c.cfg.ActorID,
			Transport:     types.TransportTypeWS,
		},
		Routing: types.EventRouting{
			AgentID:   c.cfg.AgentID,
			SessionID: c.cfg.SessionID,
		},
		Payload: payload,
	}

	return c.SendEvent(ctx, event)
}

func (c *Client) SendEvent(ctx context.Context, event types.EventEnvelope) error {
	c.mu.RLock()
	conn := c.conn
	closed := c.closed
	c.mu.RUnlock()
	if conn == nil || closed {
		return fmt.Errorf("client is not connected")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	deadline := time.Now().Add(ioTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if err := conn.WriteJSON(event); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()

	if conn != nil {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(500*time.Millisecond))
		_ = conn.Close()
	}
	close(c.done)
	return nil
}

func (c *Client) performPairing(conn *websocket.Conn) error {
	pairInitRaw, err := c.readStep(conn)
	if err != nil {
		return err
	}
	pairInit, err := protocol.DecodePairInit(pairInitRaw)
	if err != nil {
		return err
	}
	if err := protocol.VerifyPairInit(pairInit, c.cfg.GatewayPublicKeyEd25519B64); err != nil {
		return err
	}
	if strings.TrimSpace(pairInit.Gateway.PublicKeyX25519) == "" {
		return fmt.Errorf("gateway pair.init missing gateway.public_key_x25519; cannot decrypt challenge")
	}

	identity := types.PairIdentity{
		Type:      types.PairingMessageTypeIdentity,
		Version:   types.VersionV1,
		PairingID: pairInit.PairingID,
		Remote: types.PairRemoteInfo{
			ComponentType:    c.cfg.ComponentType,
			ComponentID:      c.cfg.ComponentID,
			PublicKeyEd25519: c.ed25519Public,
			PublicKeyX25519:  c.x25519Public,
		},
	}
	identity, err = protocol.SignPairIdentity(identity, c.ed25519Private)
	if err != nil {
		return err
	}
	if err := c.writeStep(conn, identity); err != nil {
		return err
	}

	challengeRaw, err := c.readStep(conn)
	if err != nil {
		return err
	}
	var challenge types.PairChallenge
	if err := json.Unmarshal(challengeRaw, &challenge); err != nil {
		return fmt.Errorf("decode pair.challenge: %w", err)
	}
	if challenge.Type != types.PairingMessageTypeChallenge {
		return fmt.Errorf("unexpected pairing message type %q", challenge.Type)
	}
	if challenge.Version != types.VersionV1 {
		return fmt.Errorf("unsupported pairing version %q", challenge.Version)
	}
	if challenge.PairingID != pairInit.PairingID {
		return fmt.Errorf("pairing_id mismatch between pair.init and pair.challenge")
	}
	plaintext, err := protocol.DecryptPairChallenge(c.x25519Private, pairInit.Gateway.PublicKeyX25519, challenge)
	if err != nil {
		return err
	}

	response := types.PairChallengeResponse{
		Type:               types.PairingMessageTypeChallengeResponse,
		Version:            types.VersionV1,
		PairingID:          challenge.PairingID,
		ChallengeID:        challenge.ChallengeID,
		ChallengePlaintext: base64.StdEncoding.EncodeToString(plaintext),
	}
	response, err = protocol.SignPairChallengeResponse(response, c.ed25519Private)
	if err != nil {
		return err
	}
	if err := c.writeStep(conn, response); err != nil {
		return err
	}

	completeRaw, err := c.readStep(conn)
	if err != nil {
		return err
	}
	var complete types.PairComplete
	if err := json.Unmarshal(completeRaw, &complete); err != nil {
		return fmt.Errorf("decode pair.complete: %w", err)
	}
	if complete.Type != types.PairingMessageTypeComplete {
		return fmt.Errorf("unexpected pairing message type %q", complete.Type)
	}
	if complete.Version != types.VersionV1 {
		return fmt.Errorf("unsupported pairing version %q", complete.Version)
	}
	if complete.PairingID != pairInit.PairingID {
		return fmt.Errorf("pairing_id mismatch between pair.init and pair.complete")
	}
	if complete.Status != types.PairingStatusOK {
		return fmt.Errorf("pairing failed with status %q", complete.Status)
	}

	return nil
}

func (c *Client) readStep(conn *websocket.Conn) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	_, payload, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read websocket message: %w", err)
	}
	return payload, nil
}

func (c *Client) writeStep(conn *websocket.Conn, v any) error {
	if err := conn.SetWriteDeadline(time.Now().Add(ioTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if err := conn.WriteJSON(v); err != nil {
		return fmt.Errorf("write websocket message: %w", err)
	}
	return nil
}

func (c *Client) readLoop() {
	defer c.Close()
	for {
		c.mu.RLock()
		conn := c.conn
		closed := c.closed
		c.mu.RUnlock()
		if conn == nil || closed {
			return
		}

		if err := conn.SetReadDeadline(time.Now().Add(24 * time.Hour)); err != nil {
			c.pushErr(fmt.Errorf("set read deadline: %w", err))
			return
		}
		_, payload, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return
			}
			c.pushErr(fmt.Errorf("read websocket message: %w", err))
			return
		}

		if pairErr, ok := decodePairError(payload); ok {
			c.pushErr(fmt.Errorf("pairing error %s: %s", pairErr.Code, pairErr.Message))
			continue
		}

		var event types.EventEnvelope
		if err := json.Unmarshal(payload, &event); err != nil {
			c.pushErr(fmt.Errorf("decode event envelope: %w", err))
			continue
		}
		if strings.TrimSpace(string(event.EventType)) == "" {
			continue
		}

		select {
		case c.events <- event:
		default:
			c.pushErr(fmt.Errorf("dropping event %s because the UI channel is full", event.EventID))
		}
	}
}

func (c *Client) pushErr(err error) {
	if err == nil {
		return
	}
	select {
	case c.errs <- err:
	default:
	}
}

func decodePairError(payload []byte) (types.PairError, bool) {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return types.PairError{}, false
	}
	if probe.Type != string(types.PairingMessageTypeError) {
		return types.PairError{}, false
	}
	var msg types.PairError
	if err := json.Unmarshal(payload, &msg); err != nil {
		return types.PairError{}, false
	}
	return msg, true
}

func newID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
