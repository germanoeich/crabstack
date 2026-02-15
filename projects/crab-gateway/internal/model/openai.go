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
	Tools       []openAITool    `json:"tools,omitempty"`
}

type openAITool struct {
	Type     string            `json:"type"`
	Function openAIFunctionDef `json:"function"`
}

type openAIFunctionDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type openAIMessage struct {
	Role       string           `json:"role"`
	Content    *string          `json:"content"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAIToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function openAIToolCallFunction `json:"function"`
}

type openAIToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
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
		Tools:       buildOpenAITools(req.Tools),
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
	blocks := parseOpenAIBlocks(choice.Message)
	content := openAIText(blocks)
	if strings.TrimSpace(content) == "" && !hasToolUseBlock(blocks) {
		return CompletionResponse{}, errors.New("openai response contained no content")
	}

	modelName := parsed.Model
	if modelName == "" {
		modelName = req.Model
	}

	return CompletionResponse{
		Content: content,
		Blocks:  blocks,
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
		messages = append(messages, openAIMessage{Role: string(RoleSystem), Content: stringPtr(req.SystemPrompt)})
	}

	for _, message := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(string(message.Role)))
		if len(message.Blocks) == 0 {
			switch role {
			case string(RoleUser), string(RoleAssistant), string(RoleSystem):
				messages = append(messages, openAIMessage{Role: role, Content: stringPtr(message.Content)})
			default:
				return nil, fmt.Errorf("unsupported message role: %s", message.Role)
			}
			continue
		}

		switch role {
		case string(RoleUser):
			resultMessages, userText, err := buildOpenAIUserToolMessages(message.Blocks)
			if err != nil {
				return nil, err
			}
			messages = append(messages, resultMessages...)
			if strings.TrimSpace(userText) != "" {
				messages = append(messages, openAIMessage{Role: role, Content: stringPtr(userText)})
			}
		case string(RoleAssistant):
			assistantMessage, err := buildOpenAIAssistantToolMessage(message.Blocks)
			if err != nil {
				return nil, err
			}
			assistantMessage.Role = role
			messages = append(messages, assistantMessage)
		case string(RoleSystem):
			text, err := textFromBlocks(message.Blocks)
			if err != nil {
				return nil, err
			}
			messages = append(messages, openAIMessage{Role: role, Content: stringPtr(text)})
		default:
			return nil, fmt.Errorf("unsupported message role: %s", message.Role)
		}
	}

	return messages, nil
}

func buildOpenAITools(tools []ToolDefinition) []openAITool {
	if len(tools) == 0 {
		return nil
	}
	built := make([]openAITool, 0, len(tools))
	for _, tool := range tools {
		built = append(built, openAITool{
			Type: "function",
			Function: openAIFunctionDef{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  cloneRawMessageOrObject(tool.InputSchema),
			},
		})
	}
	return built
}

func buildOpenAIUserToolMessages(blocks []ContentBlock) ([]openAIMessage, string, error) {
	results := make([]openAIMessage, 0, len(blocks))
	var textBuilder strings.Builder
	for _, block := range blocks {
		switch block.Type {
		case "tool_result":
			results = append(results, openAIMessage{
				Role:       "tool",
				ToolCallID: block.ToolUseID,
				Content:    stringPtr(block.Content),
			})
		case "text":
			textBuilder.WriteString(block.Text)
		default:
			return nil, "", fmt.Errorf("unsupported content block type: %s", block.Type)
		}
	}
	return results, textBuilder.String(), nil
}

func buildOpenAIAssistantToolMessage(blocks []ContentBlock) (openAIMessage, error) {
	message := openAIMessage{}
	var textBuilder strings.Builder
	for _, block := range blocks {
		switch block.Type {
		case "tool_use":
			message.ToolCalls = append(message.ToolCalls, openAIToolCall{
				ID:   block.ID,
				Type: "function",
				Function: openAIToolCallFunction{
					Name:      block.Name,
					Arguments: rawJSONToString(block.Input),
				},
			})
		case "text":
			textBuilder.WriteString(block.Text)
		default:
			return openAIMessage{}, fmt.Errorf("unsupported content block type: %s", block.Type)
		}
	}
	if text := textBuilder.String(); strings.TrimSpace(text) != "" {
		message.Content = stringPtr(text)
	}
	return message, nil
}

func textFromBlocks(blocks []ContentBlock) (string, error) {
	var builder strings.Builder
	for _, block := range blocks {
		if block.Type != "text" {
			return "", fmt.Errorf("unsupported content block type: %s", block.Type)
		}
		builder.WriteString(block.Text)
	}
	return builder.String(), nil
}

func parseOpenAIBlocks(message openAIMessage) []ContentBlock {
	blocks := make([]ContentBlock, 0, len(message.ToolCalls)+1)
	if message.Content != nil {
		blocks = append(blocks, ContentBlock{Type: "text", Text: *message.Content})
	}
	for _, toolCall := range message.ToolCalls {
		if toolCall.Type != "" && toolCall.Type != "function" {
			continue
		}
		blocks = append(blocks, ContentBlock{
			Type:  "tool_use",
			ID:    toolCall.ID,
			Name:  toolCall.Function.Name,
			Input: openAIArgumentsJSON(toolCall.Function.Arguments),
		})
	}
	return blocks
}

func openAIText(blocks []ContentBlock) string {
	var builder strings.Builder
	for _, block := range blocks {
		if block.Type != "text" {
			continue
		}
		builder.WriteString(block.Text)
	}
	return builder.String()
}

func openAIArgumentsJSON(arguments string) json.RawMessage {
	trimmed := strings.TrimSpace(arguments)
	if trimmed == "" {
		return json.RawMessage(`{}`)
	}
	raw := json.RawMessage(trimmed)
	if json.Valid(raw) {
		return cloneRawMessage(raw)
	}
	encoded, err := json.Marshal(trimmed)
	if err != nil {
		return json.RawMessage(`""`)
	}
	return encoded
}

func rawJSONToString(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "{}"
	}
	return string(trimmed)
}

func stringPtr(value string) *string {
	v := value
	return &v
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
