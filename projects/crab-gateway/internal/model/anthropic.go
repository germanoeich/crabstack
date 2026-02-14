package model

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultAnthropicEndpoint = "https://api.anthropic.com/v1/messages"
	anthropicVersion         = "2023-06-01"
)

type AnthropicOption func(*AnthropicProvider)

type AnthropicProvider struct {
	apiKey   string
	endpoint string
	client   *http.Client
}

func NewAnthropicProvider(apiKey string, opts ...AnthropicOption) *AnthropicProvider {
	provider := &AnthropicProvider{
		apiKey:   strings.TrimSpace(apiKey),
		endpoint: defaultAnthropicEndpoint,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(provider)
		}
	}
	return provider
}

func WithAnthropicEndpoint(endpoint string) AnthropicOption {
	return func(p *AnthropicProvider) {
		if trimmed := strings.TrimSpace(endpoint); trimmed != "" {
			p.endpoint = trimmed
		}
	}
}

func WithAnthropicHTTPClient(client *http.Client) AnthropicOption {
	return func(p *AnthropicProvider) {
		if client != nil {
			p.client = client
		}
	}
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
	System    string             `json:"system,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	ID         string                  `json:"id"`
	Type       string                  `json:"type"`
	Role       string                  `json:"role"`
	Model      string                  `json:"model"`
	Content    []anthropicContentBlock `json:"content"`
	StopReason string                  `json:"stop_reason"`
	Usage      anthropicUsage          `json:"usage"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type anthropicErrorEnvelope struct {
	Error anthropicError `json:"error"`
}

type anthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

var _ Provider = (*AnthropicProvider)(nil)

func (p *AnthropicProvider) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	if strings.TrimSpace(p.apiKey) == "" {
		return CompletionResponse{}, errors.New("anthropic api key is required")
	}
	if strings.TrimSpace(req.Model) == "" {
		return CompletionResponse{}, errors.New("model is required")
	}
	if req.MaxTokens <= 0 {
		return CompletionResponse{}, errors.New("max tokens must be greater than zero")
	}

	messages, system, err := buildAnthropicMessages(req)
	if err != nil {
		return CompletionResponse{}, err
	}
	if len(messages) == 0 {
		return CompletionResponse{}, errors.New("at least one non-system message is required")
	}

	payload := anthropicRequest{
		Model:     req.Model,
		MaxTokens: req.MaxTokens,
		Messages:  messages,
		System:    system,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("marshal anthropic request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("build anthropic request: %w", err)
	}
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("call anthropic api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CompletionResponse{}, parseAnthropicAPIError(resp)
	}

	var parsed anthropicResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return CompletionResponse{}, fmt.Errorf("decode anthropic response: %w", err)
	}

	content := anthropicText(parsed.Content)
	if strings.TrimSpace(content) == "" {
		return CompletionResponse{}, errors.New("anthropic response contained no text")
	}

	modelName := parsed.Model
	if modelName == "" {
		modelName = req.Model
	}

	return CompletionResponse{
		Content: content,
		Usage: Usage{
			InputTokens:  parsed.Usage.InputTokens,
			OutputTokens: parsed.Usage.OutputTokens,
		},
		Model:      modelName,
		StopReason: parsed.StopReason,
	}, nil
}

func buildAnthropicMessages(req CompletionRequest) ([]anthropicMessage, string, error) {
	systemParts := make([]string, 0, len(req.Messages)+1)
	if trimmed := strings.TrimSpace(req.SystemPrompt); trimmed != "" {
		systemParts = append(systemParts, req.SystemPrompt)
	}

	messages := make([]anthropicMessage, 0, len(req.Messages))
	for _, message := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(string(message.Role)))
		switch role {
		case string(RoleSystem):
			if strings.TrimSpace(message.Content) != "" {
				systemParts = append(systemParts, message.Content)
			}
		case string(RoleUser), string(RoleAssistant):
			messages = append(messages, anthropicMessage{Role: role, Content: message.Content})
		default:
			return nil, "", fmt.Errorf("unsupported message role: %s", message.Role)
		}
	}

	return messages, strings.Join(systemParts, "\n\n"), nil
}

func anthropicText(content []anthropicContentBlock) string {
	var builder strings.Builder
	for _, block := range content {
		if block.Type != "text" {
			continue
		}
		builder.WriteString(block.Text)
	}
	return builder.String()
}

func parseAnthropicAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	message := strings.TrimSpace(string(body))
	if len(body) > 0 {
		var parsed anthropicErrorEnvelope
		if err := json.Unmarshal(body, &parsed); err == nil && strings.TrimSpace(parsed.Error.Message) != "" {
			message = parsed.Error.Message
		}
	}
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("anthropic rate limited: %s", message)
	}
	return fmt.Errorf("anthropic api status %d: %s", resp.StatusCode, message)
}
