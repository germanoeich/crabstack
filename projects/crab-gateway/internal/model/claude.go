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

const claudeOAuthBeta = "claude-code-20250219,oauth-2025-04-20"

type ClaudeOption func(*ClaudeProvider)

type ClaudeProvider struct {
	authToken string
	endpoint  string
	client    *http.Client
}

func NewClaudeProvider(authToken string, opts ...ClaudeOption) *ClaudeProvider {
	provider := &ClaudeProvider{
		authToken: strings.TrimSpace(authToken),
		endpoint:  defaultAnthropicEndpoint,
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

func WithClaudeEndpoint(endpoint string) ClaudeOption {
	return func(p *ClaudeProvider) {
		if trimmed := strings.TrimSpace(endpoint); trimmed != "" {
			p.endpoint = trimmed
		}
	}
}

func WithClaudeHTTPClient(client *http.Client) ClaudeOption {
	return func(p *ClaudeProvider) {
		if client != nil {
			p.client = client
		}
	}
}

var _ Provider = (*ClaudeProvider)(nil)

func (p *ClaudeProvider) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	if strings.TrimSpace(p.authToken) == "" {
		return CompletionResponse{}, errors.New("claude auth token is required")
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
		Tools:     buildAnthropicTools(req.Tools),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("marshal claude request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("build claude request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.authToken)
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	httpReq.Header.Set("anthropic-beta", claudeOAuthBeta)
	httpReq.Header.Set("x-app", "cli")
	httpReq.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("call claude api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CompletionResponse{}, parseAnthropicAPIError(resp)
	}

	var parsed anthropicResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return CompletionResponse{}, fmt.Errorf("decode claude response: %w", err)
	}

	blocks := parseAnthropicBlocks(parsed.Content)
	content := anthropicText(blocks)
	if strings.TrimSpace(content) == "" && !hasToolUseBlock(blocks) {
		return CompletionResponse{}, errors.New("claude response contained no text")
	}

	modelName := parsed.Model
	if modelName == "" {
		modelName = req.Model
	}

	return CompletionResponse{
		Content: content,
		Blocks:  blocks,
		Usage: Usage{
			InputTokens:  parsed.Usage.InputTokens,
			OutputTokens: parsed.Usage.OutputTokens,
		},
		Model:      modelName,
		StopReason: parsed.StopReason,
	}, nil
}
