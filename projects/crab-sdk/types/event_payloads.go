package types

import "time"

type ChannelAttachmentType string

const (
	ChannelAttachmentTypeImage ChannelAttachmentType = "image"
	ChannelAttachmentTypeAudio ChannelAttachmentType = "audio"
	ChannelAttachmentTypeFile  ChannelAttachmentType = "file"
	ChannelAttachmentTypeVideo ChannelAttachmentType = "video"
)

type ChannelMessageAttachment struct {
	Type     ChannelAttachmentType `json:"type"`
	URL      string                `json:"url"`
	MIMEType string                `json:"mime_type,omitempty"`
	Name     string                `json:"name,omitempty"`
}

type ChannelMessageReceivedPayload struct {
	Text             string                     `json:"text"`
	Attachments      []ChannelMessageAttachment `json:"attachments,omitempty"`
	ReplyToMessageID string                     `json:"reply_to_message_id,omitempty"`
	Raw              map[string]any             `json:"raw,omitempty"`
}

type CronTriggerReason string

const (
	CronTriggerReasonHeartbeat    CronTriggerReason = "heartbeat"
	CronTriggerReasonScheduledJob CronTriggerReason = "scheduled_task"
)

type CronTriggeredPayload struct {
	JobID        string            `json:"job_id"`
	JobName      string            `json:"job_name"`
	ScheduledFor time.Time         `json:"scheduled_for"`
	TriggeredAt  time.Time         `json:"triggered_at"`
	Input        map[string]any    `json:"input,omitempty"`
	Reason       CronTriggerReason `json:"reason"`
}

type AgentResponseContentType string

const (
	AgentResponseContentTypeText AgentResponseContentType = "text"
)

type AgentResponseActionKind string

const (
	AgentResponseActionKindSendMessage    AgentResponseActionKind = "send_message"
	AgentResponseActionKindReact          AgentResponseActionKind = "react"
	AgentResponseActionKindPlatformAction AgentResponseActionKind = "platform_action"
)

type AgentResponseContent struct {
	Type AgentResponseContentType `json:"type"`
	Text string                   `json:"text"`
}

type AgentResponseAction struct {
	Kind           AgentResponseActionKind `json:"kind"`
	TargetOverride map[string]any          `json:"target_override,omitempty"`
	Args           map[string]any          `json:"args,omitempty"`
}

type Usage struct {
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	Model        string `json:"model"`
	Provider     string `json:"provider"`
}

type AgentResponseCreatedPayload struct {
	ResponseID string                 `json:"response_id"`
	Content    []AgentResponseContent `json:"content,omitempty"`
	Actions    []AgentResponseAction  `json:"actions,omitempty"`
	Usage      *Usage                 `json:"usage,omitempty"`
}

type ToolCallRequestedPayload struct {
	CallID    string         `json:"call_id"`
	ToolName  string         `json:"tool_name"`
	Args      map[string]any `json:"args,omitempty"`
	TimeoutMS int            `json:"timeout_ms,omitempty"`
}

type ToolCallCompletedPayload struct {
	CallID     string         `json:"call_id"`
	ToolName   string         `json:"tool_name"`
	Status     ToolCallStatus `json:"status"`
	Result     map[string]any `json:"result,omitempty"`
	DurationMS int64          `json:"duration_ms"`
}

type ToolCallFailedPayload struct {
	CallID     string         `json:"call_id"`
	ToolName   string         `json:"tool_name"`
	Status     ToolCallStatus `json:"status"`
	Error      *ToolError     `json:"error,omitempty"`
	DurationMS int64          `json:"duration_ms"`
}

type PairingStartedPayload struct {
	PairingID           string        `json:"pairing_id"`
	RemoteURI           string        `json:"remote_uri"`
	RemoteComponentType ComponentType `json:"remote_component_type"`
}

type PairingCompletedPayload struct {
	PairingID              string        `json:"pairing_id"`
	RemoteComponentID      string        `json:"remote_component_id"`
	RemoteComponentType    ComponentType `json:"remote_component_type"`
	RemotePublicKeyEd25519 string        `json:"remote_public_key_ed25519"`
	RemotePublicKeyX25519  string        `json:"remote_public_key_x25519"`
	MTLSCertFingerprint    string        `json:"mtls_cert_fingerprint"`
}

type PairingFailedCode string

const (
	PairingFailedCodeSignatureInvalid PairingFailedCode = "SIGNATURE_INVALID"
	PairingFailedCodeChallengeFailed  PairingFailedCode = "CHALLENGE_FAILED"
	PairingFailedCodeTimeout          PairingFailedCode = "TIMEOUT"
	PairingFailedCodeUnreachable      PairingFailedCode = "UNREACHABLE"
)

type PairingFailedPayload struct {
	PairingID    string            `json:"pairing_id"`
	RemoteURI    string            `json:"remote_uri"`
	ErrorCode    PairingFailedCode `json:"error_code"`
	ErrorMessage string            `json:"error_message"`
}

type ConfigAppliedValidation struct {
	SchemaValid     bool `json:"schema_valid"`
	SemanticValid   bool `json:"semantic_valid"`
	SmokeTestPassed bool `json:"smoke_test_passed"`
}

type ConfigAppliedBy string

const (
	ConfigAppliedByAgent    ConfigAppliedBy = "agent"
	ConfigAppliedByOperator ConfigAppliedBy = "operator"
)

type ConfigAppliedPayload struct {
	RevisionID      string                  `json:"revision_id"`
	Checksum        string                  `json:"checksum"`
	AppliedBy       ConfigAppliedBy         `json:"applied_by"`
	SourcePlatform  string                  `json:"source_platform,omitempty"`
	SourceChannelID string                  `json:"source_channel_id,omitempty"`
	Validation      ConfigAppliedValidation `json:"validation"`
}

type ConfigRevertedPayload struct {
	RevisionID string `json:"revision_id"`
}
