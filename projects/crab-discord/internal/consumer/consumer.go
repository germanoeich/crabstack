package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"crabstack.local/projects/crab-discord/internal/chanmap"
	"crabstack.local/projects/crab-discord/internal/config"
	"crabstack.local/projects/crab-sdk/types"
)

const maxRequestBodyBytes = 1 << 20

type DiscordSender interface {
	SendMessage(channelID string, content string) error
}

type Consumer struct {
	cfg            config.Config
	discordSession DiscordSender
	logger         *log.Logger

	mu       sync.Mutex
	server   *http.Server
	listener net.Listener
	registry *chanmap.ChannelRegistry
}

func NewConsumer(cfg config.Config, discordSession DiscordSender, logger *log.Logger) *Consumer {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Consumer{
		cfg:            cfg,
		discordSession: discordSession,
		logger:         logger,
	}
}

func (c *Consumer) SetChannelRegistry(registry *chanmap.ChannelRegistry) {
	c.mu.Lock()
	c.registry = registry
	c.mu.Unlock()
}

func (c *Consumer) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	addr := strings.TrimSpace(c.cfg.ConsumerAddr)
	if addr == "" {
		return fmt.Errorf("consumer address is empty")
	}

	c.mu.Lock()
	if c.server != nil {
		c.mu.Unlock()
		return fmt.Errorf("consumer already started")
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	server := &http.Server{
		Handler: c.routes(),
	}

	c.server = server
	c.listener = ln
	c.mu.Unlock()

	go func() {
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.logger.Printf("consumer server error: %v", err)
		}
	}()

	c.logger.Printf("discord consumer started addr=%s", ln.Addr().String())
	return nil
}

func (c *Consumer) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()
	server := c.server
	c.server = nil
	c.listener = nil
	c.mu.Unlock()

	if server == nil {
		return nil
	}

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown consumer server: %w", err)
	}

	c.logger.Printf("discord consumer stopped")
	return nil
}

func (c *Consumer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", c.handleEvents)
	return mux
}

func (c *Consumer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()

	var envelope types.EventEnvelope
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err := decoder.Decode(&envelope); err != nil {
		http.Error(w, "invalid event envelope", http.StatusBadRequest)
		return
	}

	if envelope.EventType != types.EventTypeAgentResponseCreated {
		w.WriteHeader(http.StatusOK)
		return
	}

	var payload types.AgentResponseCreatedPayload
	if err := envelope.DecodePayload(&payload); err != nil {
		http.Error(w, "invalid event payload", http.StatusBadRequest)
		return
	}

	channelID := c.resolveChannelID(envelope)
	if channelID == "" {
		c.logger.Printf("missing discord channel mapping for session_id=%s event_id=%s", envelope.Routing.SessionID, envelope.EventID)
		w.WriteHeader(http.StatusOK)
		return
	}

	c.sendPayloadMessages(channelID, payload, envelope)
	w.WriteHeader(http.StatusOK)
}

func (c *Consumer) resolveChannelID(envelope types.EventEnvelope) string {
	if envelope.Routing.Target != nil {
		channelID := strings.TrimSpace(envelope.Routing.Target.ChannelID)
		if channelID != "" {
			return channelID
		}
	}

	c.mu.Lock()
	registry := c.registry
	c.mu.Unlock()
	if registry != nil {
		if channelID, ok := registry.Lookup(envelope.Routing.SessionID); ok {
			if trimmed := strings.TrimSpace(channelID); trimmed != "" {
				return trimmed
			}
		}
	}

	return strings.TrimSpace(envelope.Source.ChannelID)
}

func (c *Consumer) sendPayloadMessages(channelID string, payload types.AgentResponseCreatedPayload, envelope types.EventEnvelope) {
	if c.discordSession == nil {
		c.logger.Printf("discord sender is not configured event_id=%s", envelope.EventID)
		return
	}

	for _, action := range payload.Actions {
		if action.Kind != types.AgentResponseActionKindSendMessage {
			continue
		}
		text := strings.TrimSpace(extractActionText(action.Args))
		if text == "" {
			continue
		}
		if err := c.discordSession.SendMessage(channelID, text); err != nil {
			c.logger.Printf("failed to send discord action message channel_id=%s event_id=%s err=%v", channelID, envelope.EventID, err)
		}
	}

	for _, content := range payload.Content {
		if content.Type != types.AgentResponseContentTypeText {
			continue
		}
		text := strings.TrimSpace(content.Text)
		if text == "" {
			continue
		}
		if err := c.discordSession.SendMessage(channelID, text); err != nil {
			c.logger.Printf("failed to send discord content message channel_id=%s event_id=%s err=%v", channelID, envelope.EventID, err)
		}
	}
}

func extractActionText(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}

	value, ok := args["text"]
	if !ok {
		return ""
	}

	text, ok := value.(string)
	if !ok {
		return ""
	}
	return text
}
