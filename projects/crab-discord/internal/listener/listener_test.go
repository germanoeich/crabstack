package listener

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"

	"crabstack.local/projects/crab-discord/internal/config"
	"crabstack.local/projects/crab-sdk/types"
)

func TestHandleMessageBuildsEnvelope(t *testing.T) {
	envelopeCh := make(chan types.EventEnvelope, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/events" {
			t.Fatalf("expected /v1/events path, got %s", r.URL.Path)
		}
		var envelope types.EventEnvelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		envelopeCh <- envelope
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":true,"event_id":"ok"}`))
	}))
	defer server.Close()

	cfg := config.Config{
		DiscordBotToken: "token",
		GatewayHTTPURL:  server.URL,
		TenantID:        "tenant-a",
		AgentID:         "assistant",
	}
	listener := NewListener(cfg, log.New(&bytes.Buffer{}, "", 0), server.Client())

	msg := &discordgo.MessageCreate{Message: &discordgo.Message{
		ID:        "msg-1",
		ChannelID: "channel-1",
		Content:   "hello from discord",
		Timestamp: time.Date(2026, time.February, 14, 12, 34, 56, 0, time.UTC),
		Author: &discordgo.User{
			ID:  "user-1",
			Bot: false,
		},
	}}

	listener.handleMessage(nil, msg)

	var envelope types.EventEnvelope
	select {
	case envelope = <-envelopeCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for gateway post")
	}

	if envelope.Version != types.VersionV1 {
		t.Fatalf("expected version %q, got %q", types.VersionV1, envelope.Version)
	}
	if envelope.EventType != types.EventTypeChannelMessageReceived {
		t.Fatalf("expected event type %q, got %q", types.EventTypeChannelMessageReceived, envelope.EventType)
	}
	if envelope.TenantID != "tenant-a" {
		t.Fatalf("expected tenant id tenant-a, got %q", envelope.TenantID)
	}
	if envelope.Source.ComponentType != types.ComponentTypeListener {
		t.Fatalf("expected source.component_type listener, got %q", envelope.Source.ComponentType)
	}
	if envelope.Source.ComponentID != discordComponentID {
		t.Fatalf("expected source.component_id %q, got %q", discordComponentID, envelope.Source.ComponentID)
	}
	if envelope.Source.Platform != discordPlatform {
		t.Fatalf("expected source.platform %q, got %q", discordPlatform, envelope.Source.Platform)
	}
	if envelope.Source.ChannelID != "channel-1" {
		t.Fatalf("expected source.channel_id channel-1, got %q", envelope.Source.ChannelID)
	}
	if envelope.Source.ActorID != "user-1" {
		t.Fatalf("expected source.actor_id user-1, got %q", envelope.Source.ActorID)
	}
	if envelope.Source.MessageID != "msg-1" {
		t.Fatalf("expected source.message_id msg-1, got %q", envelope.Source.MessageID)
	}
	if envelope.Source.Transport != types.TransportTypeHTTP {
		t.Fatalf("expected source.transport http, got %q", envelope.Source.Transport)
	}
	if envelope.Routing.AgentID != "assistant" {
		t.Fatalf("expected routing.agent_id assistant, got %q", envelope.Routing.AgentID)
	}
	expectedSessionID := buildSessionID("tenant-a", "channel-1")
	if envelope.Routing.SessionID != expectedSessionID {
		t.Fatalf("expected routing.session_id %q, got %q", expectedSessionID, envelope.Routing.SessionID)
	}
	if envelope.OccurredAt.UTC().Format(time.RFC3339) != "2026-02-14T12:34:56Z" {
		t.Fatalf("expected occurred_at to match message timestamp, got %s", envelope.OccurredAt.UTC().Format(time.RFC3339))
	}
	if !hexIDPattern.MatchString(envelope.EventID) {
		t.Fatalf("expected hex event_id, got %q", envelope.EventID)
	}
	if !hexIDPattern.MatchString(envelope.TraceID) {
		t.Fatalf("expected hex trace_id, got %q", envelope.TraceID)
	}

	payload := decodePayload(t, envelope.Payload)
	if payload.Text != "hello from discord" {
		t.Fatalf("expected payload text, got %q", payload.Text)
	}
}

func TestHandleMessageSkipsBotMessages(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := config.Config{
		DiscordBotToken: "token",
		GatewayHTTPURL:  server.URL,
		TenantID:        "tenant-a",
		AgentID:         "assistant",
	}
	listener := NewListener(cfg, log.New(&bytes.Buffer{}, "", 0), server.Client())
	msg := &discordgo.MessageCreate{Message: &discordgo.Message{
		ID:        "bot-msg",
		ChannelID: "channel-1",
		Author: &discordgo.User{
			ID:  "bot-user",
			Bot: true,
		},
	}}

	listener.handleMessage(nil, msg)
	if called {
		t.Fatalf("expected bot message to be skipped")
	}
}

func TestBuildEventMapsAttachments(t *testing.T) {
	cfg := config.Config{TenantID: "tenant-a", AgentID: "assistant"}
	msg := &discordgo.MessageCreate{Message: &discordgo.Message{
		ID:        "msg-attachments",
		ChannelID: "channel-attachments",
		Author:    &discordgo.User{ID: "user-1"},
		Timestamp: time.Date(2026, time.February, 14, 8, 0, 0, 0, time.UTC),
		Attachments: []*discordgo.MessageAttachment{
			{URL: "https://cdn.example.com/a.png", ContentType: "image/png", Filename: "a.png"},
			{URL: "https://cdn.example.com/a.mp3", ContentType: "audio/mpeg", Filename: "a.mp3"},
			{URL: "https://cdn.example.com/a.mp4", ContentType: "video/mp4", Filename: "a.mp4"},
			{URL: "https://cdn.example.com/a.pdf", ContentType: "application/pdf", Filename: "a.pdf"},
		},
	}}

	envelope, err := buildEvent(msg, cfg)
	if err != nil {
		t.Fatalf("buildEvent returned error: %v", err)
	}

	payload := decodePayload(t, envelope.Payload)
	if len(payload.Attachments) != 4 {
		t.Fatalf("expected 4 attachments, got %d", len(payload.Attachments))
	}
	if payload.Attachments[0].Type != types.ChannelAttachmentTypeImage {
		t.Fatalf("expected first attachment type image, got %q", payload.Attachments[0].Type)
	}
	if payload.Attachments[1].Type != types.ChannelAttachmentTypeAudio {
		t.Fatalf("expected second attachment type audio, got %q", payload.Attachments[1].Type)
	}
	if payload.Attachments[2].Type != types.ChannelAttachmentTypeVideo {
		t.Fatalf("expected third attachment type video, got %q", payload.Attachments[2].Type)
	}
	if payload.Attachments[3].Type != types.ChannelAttachmentTypeFile {
		t.Fatalf("expected fourth attachment type file, got %q", payload.Attachments[3].Type)
	}
	if payload.Attachments[0].URL != "https://cdn.example.com/a.png" || payload.Attachments[0].MIMEType != "image/png" || payload.Attachments[0].Name != "a.png" {
		t.Fatalf("unexpected first attachment mapping: %+v", payload.Attachments[0])
	}
}

func TestBuildEventSetsReplyToMessageID(t *testing.T) {
	cfg := config.Config{TenantID: "tenant-a", AgentID: "assistant"}
	msg := &discordgo.MessageCreate{Message: &discordgo.Message{
		ID:               "msg-reply",
		ChannelID:        "channel-1",
		Content:          "reply",
		Author:           &discordgo.User{ID: "user-1"},
		Timestamp:        time.Date(2026, time.February, 14, 9, 0, 0, 0, time.UTC),
		MessageReference: &discordgo.MessageReference{MessageID: "original-123"},
	}}

	envelope, err := buildEvent(msg, cfg)
	if err != nil {
		t.Fatalf("buildEvent returned error: %v", err)
	}
	payload := decodePayload(t, envelope.Payload)
	if payload.ReplyToMessageID != "original-123" {
		t.Fatalf("expected reply_to_message_id original-123, got %q", payload.ReplyToMessageID)
	}
}

func TestHandleMessageGatewayPostFailureIsLogged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	var logBuf bytes.Buffer
	cfg := config.Config{
		DiscordBotToken: "token",
		GatewayHTTPURL:  server.URL,
		TenantID:        "tenant-a",
		AgentID:         "assistant",
	}
	listener := NewListener(cfg, log.New(&logBuf, "", 0), server.Client())
	msg := &discordgo.MessageCreate{Message: &discordgo.Message{
		ID:        "msg-1",
		ChannelID: "channel-1",
		Content:   "hello",
		Timestamp: time.Date(2026, time.February, 14, 12, 34, 56, 0, time.UTC),
		Author:    &discordgo.User{ID: "user-1", Bot: false},
	}}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("handleMessage should not panic on post failure: %v", recovered)
		}
	}()
	listener.handleMessage(nil, msg)

	logs := logBuf.String()
	if !strings.Contains(logs, "failed to post event to gateway") {
		t.Fatalf("expected gateway post failure log, got %q", logs)
	}
}

func decodePayload(t *testing.T, raw json.RawMessage) types.ChannelMessageReceivedPayload {
	t.Helper()
	var payload types.ChannelMessageReceivedPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return payload
}

var hexIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
