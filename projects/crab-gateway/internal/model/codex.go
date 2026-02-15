package model

import (
	"bufio"
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
	Temperature       float64          `json:"temperature,omitempty"`
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
		Model:  req.Model,
		Store:  false,
		Stream: true,
		Input:  input,
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

	parsed, err := parseCodexSSE(resp.Body)
	if err != nil {
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

type codexSSEEvent struct {
	Type     string          `json:"type"`
	Delta    string          `json:"delta"`
	Response json.RawMessage `json:"response"`
	Message  string          `json:"message"`
	Code     string          `json:"code"`
	Error    *codexError     `json:"error"`
	Item     json.RawMessage `json:"item"`
	ItemID   string          `json:"item_id"`
}

func parseCodexSSE(reader io.Reader) (codexResponse, error) {
	stream := bufio.NewReader(reader)
	dataLines := make([]string, 0, 4)
	outputItems := make([]codexOutputItem, 0, 4)
	outputItemIndexes := make(map[string]int)
	pendingFunctionCallArguments := make(map[string]string)
	var deltaText strings.Builder

	processDataLines := func(lines []string) (*codexResponse, bool, error) {
		if len(lines) == 0 {
			return nil, false, nil
		}

		payload := strings.TrimSpace(strings.Join(lines, "\n"))
		if payload == "" || payload == "[DONE]" {
			return nil, false, nil
		}

		var event codexSSEEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return nil, false, fmt.Errorf("parse codex stream event: %w", err)
		}

		switch event.Type {
		case "error":
			return nil, false, fmt.Errorf("codex stream error: %s", codexSSEErrorMessage(event, payload))
		case "response.failed":
			return nil, false, fmt.Errorf("codex response failed: %s", codexSSEErrorMessage(event, payload))
		case "response.completed", "response.done":
			if len(event.Response) == 0 || string(event.Response) == "null" {
				fallback := codexFallbackResponse(outputItems, deltaText.String())
				if len(fallback.Output) > 0 {
					return &fallback, true, nil
				}
				return nil, false, nil
			}

			var parsed codexResponse
			if err := json.Unmarshal(event.Response, &parsed); err != nil {
				return nil, false, fmt.Errorf("parse codex completed event: %w", err)
			}
			if strings.TrimSpace(parsed.Status) == "" {
				parsed.Status = "completed"
			}
			return &parsed, true, nil
		case "response.output_item.added":
			item, itemIDs, err := codexOutputItemFromSSEEvent(event.Item)
			if err != nil {
				return nil, false, fmt.Errorf("parse codex output item: %w", err)
			}
			if item.Type == "" {
				return nil, false, nil
			}

			if item.Type == "function_call" {
				for _, itemID := range itemIDs {
					if delta, ok := pendingFunctionCallArguments[itemID]; ok {
						item.Arguments += delta
						delete(pendingFunctionCallArguments, itemID)
					}
				}
			}

			outputItems = append(outputItems, item)
			for _, itemID := range itemIDs {
				outputItemIndexes[itemID] = len(outputItems) - 1
			}
		case "response.output_text.delta":
			if event.Delta != "" {
				deltaText.WriteString(event.Delta)
				appendCodexOutputTextDelta(outputItems, outputItemIndexes, event.ItemID, event.Delta)
			}
		case "response.function_call_arguments.delta":
			appendCodexFunctionCallArgumentsDelta(outputItems, outputItemIndexes, pendingFunctionCallArguments, event.ItemID, event.Delta)
		}

		return nil, false, nil
	}

	for {
		line, err := stream.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return codexResponse{}, err
		}

		if len(line) > 0 {
			trimmedLine := strings.TrimRight(line, "\r\n")
			if trimmedLine == "" {
				parsed, done, parseErr := processDataLines(dataLines)
				if parseErr != nil {
					return codexResponse{}, parseErr
				}
				if done && parsed != nil {
					return *parsed, nil
				}
				dataLines = dataLines[:0]
			} else if strings.HasPrefix(trimmedLine, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "data:"))
				dataLines = append(dataLines, data)
			}
		}

		if errors.Is(err, io.EOF) {
			break
		}
	}

	if len(dataLines) > 0 {
		parsed, done, parseErr := processDataLines(dataLines)
		if parseErr != nil {
			return codexResponse{}, parseErr
		}
		if done && parsed != nil {
			return *parsed, nil
		}
	}

	fallback := codexFallbackResponse(outputItems, deltaText.String())
	if len(fallback.Output) > 0 {
		return fallback, nil
	}

	return codexResponse{}, errors.New("codex stream ended without completed response")
}

func codexSSEErrorMessage(event codexSSEEvent, payload string) string {
	if message := strings.TrimSpace(event.Message); message != "" {
		return message
	}
	if event.Error != nil {
		if message := strings.TrimSpace(event.Error.Message); message != "" {
			return message
		}
		if code := strings.TrimSpace(event.Error.Code); code != "" {
			return code
		}
		if errorType := strings.TrimSpace(event.Error.Type); errorType != "" {
			return errorType
		}
	}
	if len(event.Response) > 0 && string(event.Response) != "null" {
		var response struct {
			Error codexError `json:"error"`
		}
		if err := json.Unmarshal(event.Response, &response); err == nil {
			if message := strings.TrimSpace(response.Error.Message); message != "" {
				return message
			}
			if code := strings.TrimSpace(response.Error.Code); code != "" {
				return code
			}
			if errorType := strings.TrimSpace(response.Error.Type); errorType != "" {
				return errorType
			}
		}
	}
	if code := strings.TrimSpace(event.Code); code != "" {
		return code
	}
	if payload = strings.TrimSpace(payload); payload != "" {
		return payload
	}
	return "unknown stream failure"
}

func codexOutputItemFromSSEEvent(raw json.RawMessage) (codexOutputItem, []string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return codexOutputItem{}, nil, nil
	}

	var parsed struct {
		Type      string               `json:"type"`
		Role      string               `json:"role"`
		Content   []codexOutputContent `json:"content"`
		ID        string               `json:"id"`
		CallID    string               `json:"call_id"`
		Name      string               `json:"name"`
		Arguments string               `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return codexOutputItem{}, nil, err
	}

	responseItemID := strings.TrimSpace(parsed.CallID)
	if responseItemID == "" {
		responseItemID = strings.TrimSpace(parsed.ID)
	}
	itemIDs := codexSSEItemIDs(parsed.ID, parsed.CallID)

	return codexOutputItem{
		Type:      parsed.Type,
		Role:      parsed.Role,
		Content:   parsed.Content,
		ID:        responseItemID,
		Name:      parsed.Name,
		Arguments: parsed.Arguments,
	}, itemIDs, nil
}

func codexSSEItemIDs(id, callID string) []string {
	ids := make([]string, 0, 2)
	if normalized := strings.TrimSpace(id); normalized != "" {
		ids = append(ids, normalized)
	}
	if normalized := strings.TrimSpace(callID); normalized != "" {
		for _, existing := range ids {
			if existing == normalized {
				return ids
			}
		}
		ids = append(ids, normalized)
	}
	return ids
}

func appendCodexOutputTextDelta(output []codexOutputItem, indexes map[string]int, itemID, delta string) {
	if delta == "" {
		return
	}
	idx, ok := indexes[strings.TrimSpace(itemID)]
	if !ok || idx < 0 || idx >= len(output) || output[idx].Type != "message" {
		return
	}

	contentLen := len(output[idx].Content)
	if contentLen == 0 || output[idx].Content[contentLen-1].Type != "output_text" {
		output[idx].Content = append(output[idx].Content, codexOutputContent{Type: "output_text"})
		contentLen = len(output[idx].Content)
	}
	output[idx].Content[contentLen-1].Text += delta
}

func appendCodexFunctionCallArgumentsDelta(output []codexOutputItem, indexes map[string]int, pending map[string]string, itemID, delta string) {
	if delta == "" {
		return
	}
	normalizedItemID := strings.TrimSpace(itemID)
	if normalizedItemID == "" {
		return
	}

	if idx, ok := indexes[normalizedItemID]; ok && idx >= 0 && idx < len(output) && output[idx].Type == "function_call" {
		output[idx].Arguments += delta
		return
	}

	pending[normalizedItemID] += delta
}

func codexFallbackResponse(output []codexOutputItem, text string) codexResponse {
	response := codexResponse{Status: "completed"}
	if len(output) > 0 {
		if text != "" && !codexOutputHasText(output) {
			output = append(output, codexOutputItem{
				Type:    "message",
				Role:    "assistant",
				Content: []codexOutputContent{{Type: "output_text", Text: text}},
			})
		}
		response.Output = output
		return response
	}

	if text != "" {
		response.Output = []codexOutputItem{{
			Type:    "message",
			Role:    "assistant",
			Content: []codexOutputContent{{Type: "output_text", Text: text}},
		}}
	}

	return response
}

func codexOutputHasText(output []codexOutputItem) bool {
	for _, item := range output {
		if item.Type != "message" {
			continue
		}
		for _, content := range item.Content {
			if content.Type == "output_text" && content.Text != "" {
				return true
			}
		}
	}
	return false
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
