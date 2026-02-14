package listener

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"

	"crabstack.local/projects/crab-discord/internal/config"
	"crabstack.local/projects/crab-sdk/types"
)

const (
	discordComponentID = "discord-listener"
	discordPlatform    = "discord"
	postTimeout        = 10 * time.Second
)

type Listener struct {
	cfg        config.Config
	logger     *log.Logger
	httpClient *http.Client
	eventsURL  string

	mu      sync.Mutex
	session *discordgo.Session
}

func NewListener(cfg config.Config, logger *log.Logger, httpClient *http.Client) *Listener {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: postTimeout}
	}

	return &Listener{
		cfg:        cfg,
		logger:     logger,
		httpClient: httpClient,
		eventsURL:  eventsEndpoint(cfg.GatewayHTTPURL),
	}
}

func (l *Listener) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session != nil {
		return fmt.Errorf("listener already started")
	}

	s, err := discordgo.New(normalizeBotToken(l.cfg.DiscordBotToken))
	if err != nil {
		return fmt.Errorf("create discord session: %w", err)
	}
	s.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsDirectMessages | discordgo.IntentsMessageContent
	s.AddHandler(l.handleMessage)
	if err := s.Open(); err != nil {
		return fmt.Errorf("open discord session: %w", err)
	}

	l.session = s
	l.logger.Printf("discord listener started")
	return nil
}

func (l *Listener) Stop() error {
	l.mu.Lock()
	s := l.session
	l.session = nil
	l.mu.Unlock()

	if s == nil {
		return nil
	}
	if err := s.Close(); err != nil {
		return fmt.Errorf("close discord session: %w", err)
	}
	l.logger.Printf("discord listener stopped")
	return nil
}

func (l *Listener) handleMessage(_ *discordgo.Session, m *discordgo.MessageCreate) {
	if m == nil || m.Message == nil || m.Author == nil {
		return
	}
	if m.Author.Bot {
		return
	}

	envelope, err := buildEvent(m, l.cfg)
	if err != nil {
		l.logger.Printf("failed to build event envelope: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), postTimeout)
	defer cancel()
	if err := l.postEvent(ctx, l.eventsURL, envelope); err != nil {
		l.logger.Printf("failed to post event to gateway: %v", err)
	}
}

func buildEvent(msg *discordgo.MessageCreate, cfg config.Config) (types.EventEnvelope, error) {
	if msg == nil || msg.Message == nil {
		return types.EventEnvelope{}, fmt.Errorf("message is required")
	}
	if msg.Author == nil {
		return types.EventEnvelope{}, fmt.Errorf("message author is required")
	}

	occurredAt := msg.Timestamp.UTC()
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	payload := types.ChannelMessageReceivedPayload{
		Text:        msg.Content,
		Attachments: mapAttachments(msg.Attachments),
	}
	if msg.MessageReference != nil {
		payload.ReplyToMessageID = strings.TrimSpace(msg.MessageReference.MessageID)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return types.EventEnvelope{}, fmt.Errorf("marshal channel message payload: %w", err)
	}

	envelope := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    newID(),
		TraceID:    newID(),
		OccurredAt: occurredAt,
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   cfg.TenantID,
		Source: types.EventSource{
			ComponentType: types.ComponentTypeListener,
			ComponentID:   discordComponentID,
			Platform:      discordPlatform,
			ChannelID:     msg.ChannelID,
			ActorID:       msg.Author.ID,
			MessageID:     msg.ID,
			Transport:     types.TransportTypeHTTP,
		},
		Routing: types.EventRouting{
			AgentID:   cfg.AgentID,
			SessionID: buildSessionID(cfg.TenantID, msg.ChannelID),
		},
		Payload: payloadJSON,
	}
	return envelope, nil
}

func (l *Listener) postEvent(ctx context.Context, url string, envelope types.EventEnvelope) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal event envelope: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if readErr != nil {
			return fmt.Errorf("gateway returned %s", resp.Status)
		}
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("gateway returned %s: %s", resp.Status, msg)
	}

	return nil
}

func mapAttachments(discordAttachments []*discordgo.MessageAttachment) []types.ChannelMessageAttachment {
	if len(discordAttachments) == 0 {
		return nil
	}
	mapped := make([]types.ChannelMessageAttachment, 0, len(discordAttachments))
	for _, attachment := range discordAttachments {
		if attachment == nil {
			continue
		}
		mapped = append(mapped, types.ChannelMessageAttachment{
			Type:     mapAttachmentType(attachment.ContentType),
			URL:      attachment.URL,
			MIMEType: attachment.ContentType,
			Name:     attachment.Filename,
		})
	}
	if len(mapped) == 0 {
		return nil
	}
	return mapped
}

func mapAttachmentType(contentType string) types.ChannelAttachmentType {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.HasPrefix(contentType, "image/"):
		return types.ChannelAttachmentTypeImage
	case strings.HasPrefix(contentType, "audio/"):
		return types.ChannelAttachmentTypeAudio
	case strings.HasPrefix(contentType, "video/"):
		return types.ChannelAttachmentTypeVideo
	default:
		return types.ChannelAttachmentTypeFile
	}
}

func buildSessionID(tenantID, channelID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(tenantID) + ":discord:" + strings.TrimSpace(channelID)))
	return "discord:" + hex.EncodeToString(sum[:16])
}

func eventsEndpoint(gatewayHTTPURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(gatewayHTTPURL))
	if err != nil {
		return strings.TrimRight(strings.TrimSpace(gatewayHTTPURL), "/") + "/v1/events"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	trimmed := strings.TrimSpace(parsed.Path)
	if trimmed == "" || trimmed == "/" {
		parsed.Path = "/v1/events"
		return parsed.String()
	}
	parsed.Path = strings.TrimRight(trimmed, "/") + "/v1/events"
	return parsed.String()
}

func normalizeBotToken(token string) string {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(token), "bot ") {
		return token
	}
	return "Bot " + token
}

func newID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
