package types

import "encoding/json"

type ToolDescriptor struct {
	Name             string          `json:"name"`
	Description      string          `json:"description,omitempty"`
	InputSchema      json.RawMessage `json:"input_schema,omitempty"`
	OutputSchema     json.RawMessage `json:"output_schema,omitempty"`
	TimeoutMSDefault int             `json:"timeout_ms_default,omitempty"`
	TimeoutMSMax     int             `json:"timeout_ms_max,omitempty"`
	Idempotent       bool            `json:"idempotent,omitempty"`
	SideEffects      bool            `json:"side_effects,omitempty"`
}

type ToolDiscoveryResponse struct {
	Version string           `json:"version"`
	Service string           `json:"service"`
	Tools   []ToolDescriptor `json:"tools"`
}

type RequestOrigin string

const (
	RequestOriginAgentTurn RequestOrigin = "agent_turn"
	RequestOriginCron      RequestOrigin = "cron"
	RequestOriginOperator  RequestOrigin = "operator"
	RequestOriginSystem    RequestOrigin = "system"
)

type ToolCallContext struct {
	AgentID       string        `json:"agent_id"`
	SessionID     string        `json:"session_id"`
	Platform      string        `json:"platform,omitempty"`
	ChannelID     string        `json:"channel_id,omitempty"`
	ActorID       string        `json:"actor_id,omitempty"`
	IsolationKey  string        `json:"isolation_key,omitempty"`
	TraceID       string        `json:"trace_id,omitempty"`
	RequestOrigin RequestOrigin `json:"request_origin,omitempty"`
}

type ToolCallRequest struct {
	Version        string          `json:"version"`
	CallID         string          `json:"call_id"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	ToolName       string          `json:"tool_name"`
	TenantID       string          `json:"tenant_id"`
	Args           map[string]any  `json:"args"`
	TimeoutMS      int             `json:"timeout_ms,omitempty"`
	Context        ToolCallContext `json:"context"`
}

type ToolCallStatus string

const (
	ToolCallStatusOK             ToolCallStatus = "ok"
	ToolCallStatusError          ToolCallStatus = "error"
	ToolCallStatusRetryableError ToolCallStatus = "retryable_error"
	ToolCallStatusTimeout        ToolCallStatus = "timeout"
)

type ToolErrorCode string

const (
	ToolErrorCodeToolNotFound          ToolErrorCode = "TOOL_NOT_FOUND"
	ToolErrorCodeInvalidArgs           ToolErrorCode = "INVALID_ARGS"
	ToolErrorCodeUnauthorized          ToolErrorCode = "UNAUTHORIZED"
	ToolErrorCodeForbidden             ToolErrorCode = "FORBIDDEN"
	ToolErrorCodeRateLimited           ToolErrorCode = "RATE_LIMITED"
	ToolErrorCodeDependencyUnavailable ToolErrorCode = "DEPENDENCY_UNAVAILABLE"
	ToolErrorCodeTimeout               ToolErrorCode = "TIMEOUT"
	ToolErrorCodeInternal              ToolErrorCode = "INTERNAL"
	ToolErrorCodePairingRequired       ToolErrorCode = "PAIRING_REQUIRED"
	ToolErrorCodePairingFailed         ToolErrorCode = "PAIRING_FAILED"
)

type ToolError struct {
	Code      ToolErrorCode  `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	Retryable bool           `json:"retryable,omitempty"`
}

type ToolCallResponse struct {
	Version    string         `json:"version"`
	CallID     string         `json:"call_id"`
	ToolName   string         `json:"tool_name"`
	Status     ToolCallStatus `json:"status"`
	Result     map[string]any `json:"result,omitempty"`
	Error      *ToolError     `json:"error,omitempty"`
	DurationMS int64          `json:"duration_ms"`
	Logs       []string       `json:"logs,omitempty"`
}
