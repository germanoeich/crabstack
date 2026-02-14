package model

import "context"

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
	MaxTokens    int
	Temperature  float64
	SystemPrompt string
}

type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

type CompletionResponse struct {
	Content    string
	Usage      Usage
	Model      string
	StopReason string
}

type Usage struct {
	InputTokens  int64
	OutputTokens int64
}
