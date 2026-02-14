package types

import (
	"encoding/json"
	"time"
)

type EventType string

const (
	EventTypeChannelMessageReceived EventType = "channel.message.received"
	EventTypeChannelMessageEdited   EventType = "channel.message.edited"
	EventTypeChannelMessageDeleted  EventType = "channel.message.deleted"
	EventTypeCronTriggered          EventType = "cron.triggered"
	EventTypeHeartbeatTick          EventType = "heartbeat.tick"
	EventTypeAgentTurnStarted       EventType = "agent.turn.started"
	EventTypeAgentTurnCompleted     EventType = "agent.turn.completed"
	EventTypeAgentTurnFailed        EventType = "agent.turn.failed"
	EventTypeAgentResponseCreated   EventType = "agent.response.created"
	EventTypeToolCallRequested      EventType = "tool.call.requested"
	EventTypeToolCallCompleted      EventType = "tool.call.completed"
	EventTypeToolCallFailed         EventType = "tool.call.failed"
	EventTypePairingStarted         EventType = "pairing.started"
	EventTypePairingCompleted       EventType = "pairing.completed"
	EventTypePairingFailed          EventType = "pairing.failed"
	EventTypeConfigApplied          EventType = "config.applied"
	EventTypeConfigReverted         EventType = "config.reverted"
)

type EventEnvelope struct {
	Version        string          `json:"version"`
	EventID        string          `json:"event_id"`
	TraceID        string          `json:"trace_id"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	OccurredAt     time.Time       `json:"occurred_at"`
	EventType      EventType       `json:"event_type"`
	TenantID       string          `json:"tenant_id"`
	Source         EventSource     `json:"source"`
	Routing        EventRouting    `json:"routing"`
	Payload        json.RawMessage `json:"payload"`
	Meta           map[string]any  `json:"meta,omitempty"`
}

func (e EventEnvelope) DecodePayload(v any) error {
	return json.Unmarshal(e.Payload, v)
}

type EventSource struct {
	ComponentType       ComponentType `json:"component_type"`
	ComponentID         string        `json:"component_id"`
	Platform            string        `json:"platform,omitempty"`
	ChannelID           string        `json:"channel_id,omitempty"`
	ActorID             string        `json:"actor_id,omitempty"`
	MessageID           string        `json:"message_id,omitempty"`
	RequestID           string        `json:"request_id,omitempty"`
	PeerID              string        `json:"peer_id,omitempty"`
	MTLSCertFingerprint string        `json:"mtls_cert_fingerprint,omitempty"`
	Transport           TransportType `json:"transport,omitempty"`
}

type EventRouting struct {
	AgentID      string       `json:"agent_id"`
	SessionID    string       `json:"session_id"`
	IsolationKey string       `json:"isolation_key,omitempty"`
	Target       *EventTarget `json:"target,omitempty"`
	PolicyTags   []string     `json:"policy_tags,omitempty"`
}

type EventTarget struct {
	Platform  string `json:"platform,omitempty"`
	ChannelID string `json:"channel_id,omitempty"`
	ThreadID  string `json:"thread_id,omitempty"`
	Address   string `json:"address,omitempty"`
}
