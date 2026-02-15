package model

import (
	"context"
	"encoding/json"
)

type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleSystem    Role = "system"
)

type Provider interface {
	Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error)
}

type CompletionRequest struct {
	Model        string
	Messages     []Message
	Tools        []ToolDefinition
	MaxTokens    int
	Temperature  float64
	SystemPrompt string
}

type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type ContentBlock struct {
	Type      string
	Text      string
	ID        string
	Name      string
	Input     json.RawMessage
	ToolUseID string
	Content   string
	IsError   bool
}

type Message struct {
	Role    Role           `json:"role"`
	Content string         `json:"content"`
	Blocks  []ContentBlock `json:"blocks,omitempty"`
}

type CompletionResponse struct {
	Content    string
	Blocks     []ContentBlock
	Usage      Usage
	Model      string
	StopReason string
}

type Usage struct {
	InputTokens  int64
	OutputTokens int64
}
