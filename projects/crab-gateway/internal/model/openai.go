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

const defaultOpenAIEndpoint = "https://api.openai.com/v1/chat/completions"

type OpenAIOption func(*OpenAIProvider)

type OpenAIProvider struct {
	apiKey   string
	endpoint string
	client   *http.Client
}

func NewOpenAIProvider(apiKey string, opts ...OpenAIOption) *OpenAIProvider {
	provider := &OpenAIProvider{
		apiKey:   strings.TrimSpace(apiKey),
		endpoint: defaultOpenAIEndpoint,
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

func WithOpenAIEndpoint(endpoint string) OpenAIOption {
	return func(p *OpenAIProvider) {
		if trimmed := strings.TrimSpace(endpoint); trimmed != "" {
			p.endpoint = trimmed
		}
	}
}

func WithOpenAIHTTPClient(client *http.Client) OpenAIOption {
	return func(p *OpenAIProvider) {
		if client != nil {
			p.client = client
		}
	}
}

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens"`
	Temperature float64         `json:"temperature"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	ID      string         `json:"id"`
	Model   string         `json:"model"`
	Choices []openAIChoice `json:"choices"`
	Usage   openAIUsage    `json:"usage"`
}

type openAIChoice struct {
	Message      openAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type openAIUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
}

type openAIErrorEnvelope struct {
	Error openAIError `json:"error"`
}

type openAIError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

var _ Provider = (*OpenAIProvider)(nil)

func (p *OpenAIProvider) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	if strings.TrimSpace(p.apiKey) == "" {
		return CompletionResponse{}, errors.New("openai api key is required")
	}
	if strings.TrimSpace(req.Model) == "" {
		return CompletionResponse{}, errors.New("model is required")
	}
	if req.MaxTokens <= 0 {
		return CompletionResponse{}, errors.New("max tokens must be greater than zero")
	}

	messages, err := buildOpenAIMessages(req)
	if err != nil {
		return CompletionResponse{}, err
	}
	if len(messages) == 0 {
		return CompletionResponse{}, errors.New("at least one message is required")
	}

	payload := openAIRequest{
		Model:       req.Model,
		Messages:    messages,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("marshal openai request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("build openai request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("call openai api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CompletionResponse{}, parseOpenAIAPIError(resp)
	}

	var parsed openAIResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return CompletionResponse{}, fmt.Errorf("decode openai response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return CompletionResponse{}, errors.New("openai response contained no choices")
	}

	choice := parsed.Choices[0]
	if strings.TrimSpace(choice.Message.Content) == "" {
		return CompletionResponse{}, errors.New("openai response contained no content")
	}

	modelName := parsed.Model
	if modelName == "" {
		modelName = req.Model
	}

	return CompletionResponse{
		Content: choice.Message.Content,
		Usage: Usage{
			InputTokens:  parsed.Usage.PromptTokens,
			OutputTokens: parsed.Usage.CompletionTokens,
		},
		Model:      modelName,
		StopReason: choice.FinishReason,
	}, nil
}

func buildOpenAIMessages(req CompletionRequest) ([]openAIMessage, error) {
	messages := make([]openAIMessage, 0, len(req.Messages)+1)
	if strings.TrimSpace(req.SystemPrompt) != "" {
		messages = append(messages, openAIMessage{Role: string(RoleSystem), Content: req.SystemPrompt})
	}

	for _, message := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(string(message.Role)))
		switch role {
		case string(RoleUser), string(RoleAssistant), string(RoleSystem):
			messages = append(messages, openAIMessage{Role: role, Content: message.Content})
		default:
			return nil, fmt.Errorf("unsupported message role: %s", message.Role)
		}
	}

	return messages, nil
}

func parseOpenAIAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	message := strings.TrimSpace(string(body))
	if len(body) > 0 {
		var parsed openAIErrorEnvelope
		if err := json.Unmarshal(body, &parsed); err == nil && strings.TrimSpace(parsed.Error.Message) != "" {
			message = parsed.Error.Message
		}
	}
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("openai rate limited: %s", message)
	}
	return fmt.Errorf("openai api status %d: %s", resp.StatusCode, message)
}
