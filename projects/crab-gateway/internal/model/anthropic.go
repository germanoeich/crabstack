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
	Tools     []anthropicTool    `json:"tools,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthropicMessage struct {
	Role    string           `json:"role"`
	Content anthropicContent `json:"content"`
}

type anthropicContent struct {
	text   *string
	blocks []anthropicContentBlock
}

func newAnthropicTextContent(text string) anthropicContent {
	return anthropicContent{text: &text}
}

func newAnthropicBlockContent(blocks []anthropicContentBlock) anthropicContent {
	copied := make([]anthropicContentBlock, len(blocks))
	copy(copied, blocks)
	return anthropicContent{blocks: copied}
}

func (c anthropicContent) MarshalJSON() ([]byte, error) {
	if len(c.blocks) > 0 {
		return json.Marshal(c.blocks)
	}
	if c.text == nil {
		return json.Marshal("")
	}
	return json.Marshal(*c.text)
}

func (c *anthropicContent) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		empty := ""
		c.text = &empty
		c.blocks = nil
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var blocks []anthropicContentBlock
		if err := json.Unmarshal(trimmed, &blocks); err != nil {
			return err
		}
		c.text = nil
		c.blocks = blocks
		return nil
	}
	var text string
	if err := json.Unmarshal(trimmed, &text); err != nil {
		return err
	}
	c.text = &text
	c.blocks = nil
	return nil
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
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
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
		Tools:     buildAnthropicTools(req.Tools),
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

	blocks := parseAnthropicBlocks(parsed.Content)
	content := anthropicText(blocks)
	if strings.TrimSpace(content) == "" && !hasToolUseBlock(blocks) {
		return CompletionResponse{}, errors.New("anthropic response contained no text")
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
			if text := messageText(message); strings.TrimSpace(text) != "" {
				systemParts = append(systemParts, text)
			}
		case string(RoleUser), string(RoleAssistant):
			if len(message.Blocks) > 0 {
				blocks, err := toAnthropicBlocks(message.Blocks)
				if err != nil {
					return nil, "", err
				}
				messages = append(messages, anthropicMessage{Role: role, Content: newAnthropicBlockContent(blocks)})
				continue
			}
			messages = append(messages, anthropicMessage{Role: role, Content: newAnthropicTextContent(message.Content)})
		default:
			return nil, "", fmt.Errorf("unsupported message role: %s", message.Role)
		}
	}

	return messages, strings.Join(systemParts, "\n\n"), nil
}

func buildAnthropicTools(tools []ToolDefinition) []anthropicTool {
	if len(tools) == 0 {
		return nil
	}
	built := make([]anthropicTool, 0, len(tools))
	for _, tool := range tools {
		built = append(built, anthropicTool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: cloneRawMessageOrObject(tool.InputSchema),
		})
	}
	return built
}

func messageText(message Message) string {
	if len(message.Blocks) == 0 {
		return message.Content
	}
	var builder strings.Builder
	for _, block := range message.Blocks {
		if block.Type != "text" {
			continue
		}
		builder.WriteString(block.Text)
	}
	return builder.String()
}

func toAnthropicBlocks(blocks []ContentBlock) ([]anthropicContentBlock, error) {
	converted := make([]anthropicContentBlock, 0, len(blocks))
	for _, block := range blocks {
		switch block.Type {
		case "text":
			converted = append(converted, anthropicContentBlock{Type: "text", Text: block.Text})
		case "tool_use":
			converted = append(converted, anthropicContentBlock{
				Type:  "tool_use",
				ID:    block.ID,
				Name:  block.Name,
				Input: cloneRawMessageOrObject(block.Input),
			})
		case "tool_result":
			converted = append(converted, anthropicContentBlock{
				Type:      "tool_result",
				ToolUseID: block.ToolUseID,
				Content:   block.Content,
				IsError:   block.IsError,
			})
		default:
			return nil, fmt.Errorf("unsupported content block type: %s", block.Type)
		}
	}
	return converted, nil
}

func parseAnthropicBlocks(content []anthropicContentBlock) []ContentBlock {
	blocks := make([]ContentBlock, 0, len(content))
	for _, block := range content {
		switch block.Type {
		case "text":
			blocks = append(blocks, ContentBlock{Type: "text", Text: block.Text})
		case "tool_use":
			blocks = append(blocks, ContentBlock{
				Type:  "tool_use",
				ID:    block.ID,
				Name:  block.Name,
				Input: cloneRawMessage(block.Input),
			})
		case "tool_result":
			blocks = append(blocks, ContentBlock{
				Type:      "tool_result",
				ToolUseID: block.ToolUseID,
				Content:   block.Content,
				IsError:   block.IsError,
			})
		}
	}
	return blocks
}

func anthropicText(blocks []ContentBlock) string {
	var builder strings.Builder
	for _, block := range blocks {
		if block.Type != "text" {
			continue
		}
		builder.WriteString(block.Text)
	}
	return builder.String()
}

func hasToolUseBlock(blocks []ContentBlock) bool {
	for _, block := range blocks {
		if block.Type == "tool_use" {
			return true
		}
	}
	return false
}

func cloneRawMessage(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	copied := make(json.RawMessage, len(raw))
	copy(copied, raw)
	return copied
}

func cloneRawMessageOrObject(raw json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return json.RawMessage(`{}`)
	}
	copied := make(json.RawMessage, len(trimmed))
	copy(copied, trimmed)
	return copied
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
