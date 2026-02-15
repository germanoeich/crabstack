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
	defaultCodexEndpoint = "https://chatgpt.com/backend-api"
	codexResponsesPath   = "/codex/responses"
	codexOpenAIBeta      = "responses=experimental"
	codexOriginator      = "crabstack"
)

type CodexOption func(*CodexProvider)

type CodexProvider struct {
	authToken string
	accountID string
	endpoint  string
	client    *http.Client
}

func NewCodexProvider(authToken, accountID string, opts ...CodexOption) *CodexProvider {
	provider := &CodexProvider{
		authToken: strings.TrimSpace(authToken),
		accountID: strings.TrimSpace(accountID),
		endpoint:  defaultCodexEndpoint,
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

func WithCodexEndpoint(endpoint string) CodexOption {
	return func(p *CodexProvider) {
		if trimmed := strings.TrimSpace(endpoint); trimmed != "" {
			p.endpoint = trimmed
		}
	}
}

func WithCodexHTTPClient(client *http.Client) CodexOption {
	return func(p *CodexProvider) {
		if client != nil {
			p.client = client
		}
	}
}

type codexRequest struct {
	Model             string           `json:"model"`
	Store             bool             `json:"store"`
	Stream            bool             `json:"stream"`
	Instructions      string           `json:"instructions,omitempty"`
	Input             []codexInputItem `json:"input,omitempty"`
	Tools             []codexTool      `json:"tools,omitempty"`
	ToolChoice        string           `json:"tool_choice,omitempty"`
	ParallelToolCalls bool             `json:"parallel_tool_calls,omitempty"`
	Temperature       float64          `json:"temperature"`
}

type codexTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type codexInputItem struct {
	Role      string              `json:"role,omitempty"`
	Content   []codexInputContent `json:"content,omitempty"`
	Type      string              `json:"type,omitempty"`
	CallID    string              `json:"call_id,omitempty"`
	Name      string              `json:"name,omitempty"`
	Arguments string              `json:"arguments,omitempty"`
	Output    string              `json:"output,omitempty"`
}

type codexInputContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type codexResponse struct {
	ID     string            `json:"id"`
	Model  string            `json:"model"`
	Output []codexOutputItem `json:"output"`
	Usage  codexUsage        `json:"usage"`
	Status string            `json:"status"`
}

type codexOutputItem struct {
	Type      string               `json:"type"`
	Role      string               `json:"role,omitempty"`
	Content   []codexOutputContent `json:"content,omitempty"`
	ID        string               `json:"id,omitempty"`
	Name      string               `json:"name,omitempty"`
	Arguments string               `json:"arguments,omitempty"`
}

type codexOutputContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type codexUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
}

type codexErrorEnvelope struct {
	Error codexError `json:"error"`
}

type codexError struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

var _ Provider = (*CodexProvider)(nil)

func (p *CodexProvider) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	if strings.TrimSpace(p.authToken) == "" {
		return CompletionResponse{}, errors.New("codex auth token is required")
	}
	if strings.TrimSpace(p.accountID) == "" {
		return CompletionResponse{}, errors.New("codex account id is required")
	}
	if strings.TrimSpace(req.Model) == "" {
		return CompletionResponse{}, errors.New("codex model is required")
	}

	input, instructions, err := buildCodexInput(req)
	if err != nil {
		return CompletionResponse{}, err
	}
	if len(input) == 0 {
		return CompletionResponse{}, errors.New("codex at least one non-system message is required")
	}

	payload := codexRequest{
		Model:       req.Model,
		Store:       false,
		Stream:      false,
		Input:       input,
		Temperature: req.Temperature,
	}
	if strings.TrimSpace(instructions) != "" {
		payload.Instructions = instructions
	}

	if tools := buildCodexTools(req.Tools); len(tools) > 0 {
		payload.Tools = tools
		payload.ToolChoice = "auto"
		payload.ParallelToolCalls = true
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("marshal codex request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, resolveCodexEndpoint(p.endpoint), bytes.NewReader(body))
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("build codex request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.authToken)
	httpReq.Header.Set("chatgpt-account-id", p.accountID)
	httpReq.Header.Set("OpenAI-Beta", codexOpenAIBeta)
	httpReq.Header.Set("originator", codexOriginator)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return CompletionResponse{}, fmt.Errorf("call codex api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CompletionResponse{}, parseCodexAPIError(resp)
	}

	var parsed codexResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return CompletionResponse{}, fmt.Errorf("decode codex response: %w", err)
	}

	blocks := parseCodexBlocks(parsed.Output)
	content := codexText(blocks)
	if strings.TrimSpace(content) == "" && !hasToolUseBlock(blocks) {
		return CompletionResponse{}, errors.New("codex response contained no content")
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
		StopReason: codexStopReason(parsed.Status, blocks),
	}, nil
}

func buildCodexInput(req CompletionRequest) ([]codexInputItem, string, error) {
	systemParts := make([]string, 0, len(req.Messages)+1)
	if trimmed := strings.TrimSpace(req.SystemPrompt); trimmed != "" {
		systemParts = append(systemParts, req.SystemPrompt)
	}

	input := make([]codexInputItem, 0, len(req.Messages))
	for _, message := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(string(message.Role)))
		switch role {
		case string(RoleSystem):
			text, err := codexSystemText(message)
			if err != nil {
				return nil, "", err
			}
			if strings.TrimSpace(text) != "" {
				systemParts = append(systemParts, text)
			}
		case string(RoleUser):
			items, err := codexUserInputItems(message)
			if err != nil {
				return nil, "", err
			}
			input = append(input, items...)
		case string(RoleAssistant):
			items, err := codexAssistantInputItems(message)
			if err != nil {
				return nil, "", err
			}
			input = append(input, items...)
		default:
			return nil, "", fmt.Errorf("codex unsupported message role: %s", message.Role)
		}
	}

	return input, strings.Join(systemParts, "\n\n"), nil
}

func codexSystemText(message Message) (string, error) {
	if len(message.Blocks) == 0 {
		return message.Content, nil
	}
	text, err := textFromBlocks(message.Blocks)
	if err != nil {
		return "", fmt.Errorf("codex %w", err)
	}
	return text, nil
}

func codexUserInputItems(message Message) ([]codexInputItem, error) {
	if len(message.Blocks) == 0 {
		return []codexInputItem{codexTextInputItem("user", "input_text", message.Content)}, nil
	}

	items := make([]codexInputItem, 0, len(message.Blocks))
	var textBuilder strings.Builder
	flushText := func() {
		if textBuilder.Len() == 0 {
			return
		}
		items = append(items, codexTextInputItem("user", "input_text", textBuilder.String()))
		textBuilder.Reset()
	}

	for _, block := range message.Blocks {
		switch block.Type {
		case "text":
			textBuilder.WriteString(block.Text)
		case "tool_result":
			callID := strings.TrimSpace(block.ToolUseID)
			if callID == "" {
				return nil, errors.New("codex tool_result block requires tool_use_id")
			}
			flushText()
			items = append(items, codexInputItem{
				Type:   "function_call_output",
				CallID: callID,
				Output: block.Content,
			})
		default:
			return nil, fmt.Errorf("codex unsupported content block type: %s", block.Type)
		}
	}
	flushText()
	return items, nil
}

func codexAssistantInputItems(message Message) ([]codexInputItem, error) {
	if len(message.Blocks) == 0 {
		return []codexInputItem{codexTextInputItem("assistant", "output_text", message.Content)}, nil
	}

	items := make([]codexInputItem, 0, len(message.Blocks))
	var textBuilder strings.Builder
	flushText := func() {
		if textBuilder.Len() == 0 {
			return
		}
		items = append(items, codexTextInputItem("assistant", "output_text", textBuilder.String()))
		textBuilder.Reset()
	}

	for _, block := range message.Blocks {
		switch block.Type {
		case "text":
			textBuilder.WriteString(block.Text)
		case "tool_use":
			callID := strings.TrimSpace(block.ID)
			if callID == "" {
				return nil, errors.New("codex tool_use block requires id")
			}
			name := strings.TrimSpace(block.Name)
			if name == "" {
				return nil, errors.New("codex tool_use block requires name")
			}
			flushText()
			items = append(items, codexInputItem{
				Type:      "function_call",
				CallID:    callID,
				Name:      name,
				Arguments: rawJSONToString(block.Input),
			})
		default:
			return nil, fmt.Errorf("codex unsupported content block type: %s", block.Type)
		}
	}
	flushText()
	return items, nil
}

func codexTextInputItem(role, textType, text string) codexInputItem {
	return codexInputItem{
		Role: role,
		Content: []codexInputContent{
			{Type: textType, Text: text},
		},
	}
}

func buildCodexTools(tools []ToolDefinition) []codexTool {
	if len(tools) == 0 {
		return nil
	}
	built := make([]codexTool, 0, len(tools))
	for _, tool := range tools {
		built = append(built, codexTool{
			Type:        "function",
			Name:        tool.Name,
			Description: tool.Description,
			Parameters:  cloneRawMessageOrObject(tool.InputSchema),
		})
	}
	return built
}

func resolveCodexEndpoint(endpoint string) string {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		raw = defaultCodexEndpoint
	}
	normalized := strings.TrimRight(raw, "/")
	if strings.HasSuffix(normalized, codexResponsesPath) {
		return normalized
	}
	if strings.HasSuffix(normalized, "/codex") {
		return normalized + "/responses"
	}
	return normalized + codexResponsesPath
}

func parseCodexBlocks(output []codexOutputItem) []ContentBlock {
	blocks := make([]ContentBlock, 0, len(output))
	for _, item := range output {
		switch item.Type {
		case "message":
			for _, content := range item.Content {
				if content.Type != "output_text" {
					continue
				}
				blocks = append(blocks, ContentBlock{Type: "text", Text: content.Text})
			}
		case "function_call":
			blocks = append(blocks, ContentBlock{
				Type:  "tool_use",
				ID:    item.ID,
				Name:  item.Name,
				Input: openAIArgumentsJSON(item.Arguments),
			})
		}
	}
	return blocks
}

func codexText(blocks []ContentBlock) string {
	var builder strings.Builder
	for _, block := range blocks {
		if block.Type != "text" {
			continue
		}
		builder.WriteString(block.Text)
	}
	return builder.String()
}

func codexStopReason(status string, blocks []ContentBlock) string {
	if hasToolUseBlock(blocks) {
		return "tool_use"
	}
	normalized := strings.ToLower(strings.TrimSpace(status))
	if normalized == "" || normalized == "completed" {
		return "end_turn"
	}
	return normalized
}

func parseCodexAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	message := strings.TrimSpace(string(body))
	if len(body) > 0 {
		var parsed codexErrorEnvelope
		if err := json.Unmarshal(body, &parsed); err == nil && strings.TrimSpace(parsed.Error.Message) != "" {
			message = parsed.Error.Message
		}
	}
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("codex rate limited: %s", message)
	}
	return fmt.Errorf("codex api status %d: %s", resp.StatusCode, message)
}
