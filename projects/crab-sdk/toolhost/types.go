package toolhost

import "encoding/json"

type ToolDefinition struct {
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	InputSchema      json.RawMessage `json:"input_schema"`
	OutputSchema     json.RawMessage `json:"output_schema"`
	TimeoutMSDefault int             `json:"timeout_ms_default"`
	TimeoutMSMax     int             `json:"timeout_ms_max"`
	Idempotent       bool            `json:"idempotent"`
	SideEffects      bool            `json:"side_effects"`
}

type ToolCallRequest struct {
	Version        string          `json:"version"`
	CallID         string          `json:"call_id"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	ToolName       string          `json:"tool_name"`
	TenantID       string          `json:"tenant_id"`
	Args           json.RawMessage `json:"args"`
	TimeoutMS      int             `json:"timeout_ms,omitempty"`
	Context        ToolCallContext `json:"context"`
}

type ToolCallContext struct {
	AgentID       string `json:"agent_id"`
	SessionID     string `json:"session_id"`
	Platform      string `json:"platform,omitempty"`
	ChannelID     string `json:"channel_id,omitempty"`
	ActorID       string `json:"actor_id,omitempty"`
	IsolationKey  string `json:"isolation_key,omitempty"`
	TraceID       string `json:"trace_id,omitempty"`
	RequestOrigin string `json:"request_origin,omitempty"`
}

type ToolCallResponse struct {
	Version    string          `json:"version"`
	CallID     string          `json:"call_id"`
	ToolName   string          `json:"tool_name"`
	Status     ToolCallStatus  `json:"status"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      *ToolCallError  `json:"error,omitempty"`
	DurationMS int64           `json:"duration_ms"`
	Logs       []string        `json:"logs,omitempty"`
}

type ToolCallStatus string

const (
	ToolCallStatusOK             ToolCallStatus = "ok"
	ToolCallStatusError          ToolCallStatus = "error"
	ToolCallStatusRetryableError ToolCallStatus = "retryable_error"
	ToolCallStatusTimeout        ToolCallStatus = "timeout"
)

type ToolCallError struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Details   json.RawMessage `json:"details,omitempty"`
	Retryable bool            `json:"retryable,omitempty"`
}

const (
	ToolErrorCodeToolNotFound          = "TOOL_NOT_FOUND"
	ToolErrorCodeInvalidArgs           = "INVALID_ARGS"
	ToolErrorCodeUnauthorized          = "UNAUTHORIZED"
	ToolErrorCodeForbidden             = "FORBIDDEN"
	ToolErrorCodeRateLimited           = "RATE_LIMITED"
	ToolErrorCodeDependencyUnavailable = "DEPENDENCY_UNAVAILABLE"
	ToolErrorCodeTimeout               = "TIMEOUT"
	ToolErrorCodeInternal              = "INTERNAL"
)

type DiscoveryResponse struct {
	Version string           `json:"version"`
	Service string           `json:"service"`
	Tools   []ToolDefinition `json:"tools"`
}
