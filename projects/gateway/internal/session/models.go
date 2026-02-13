package session

import "time"

type SessionRecord struct {
	TenantID            string    `json:"tenant_id"`
	SessionID           string    `json:"session_id"`
	AgentID             string    `json:"agent_id"`
	Platform            string    `json:"platform,omitempty"`
	ChannelID           string    `json:"channel_id,omitempty"`
	ActorID             string    `json:"actor_id,omitempty"`
	IsolationKey        string    `json:"isolation_key,omitempty"`
	LastActivePlatform  string    `json:"last_active_platform,omitempty"`
	LastActiveChannelID string    `json:"last_active_channel_id,omitempty"`
	LastActiveActorID   string    `json:"last_active_actor_id,omitempty"`
	LastActiveAt        time.Time `json:"last_active_at"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type TurnStatus string

const (
	TurnStatusInProgress TurnStatus = "in_progress"
	TurnStatusCompleted  TurnStatus = "completed"
	TurnStatusFailed     TurnStatus = "failed"
)

type TurnRecord struct {
	TurnID            string     `json:"turn_id"`
	TenantID          string     `json:"tenant_id"`
	SessionID         string     `json:"session_id"`
	AgentID           string     `json:"agent_id"`
	Sequence          int64      `json:"sequence"`
	TraceID           string     `json:"trace_id"`
	SourceEventID     string     `json:"source_event_id"`
	SourceEventType   string     `json:"source_event_type"`
	InboundEventJSON  []byte     `json:"inbound_event_json"`
	Status            TurnStatus `json:"status"`
	Error             string     `json:"error,omitempty"`
	ResponseEventID   string     `json:"response_event_id,omitempty"`
	ResponseEventJSON []byte     `json:"response_event_json,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	CompletedAt       time.Time  `json:"completed_at,omitempty"`
	UpdatedAt         time.Time  `json:"updated_at"`
}
