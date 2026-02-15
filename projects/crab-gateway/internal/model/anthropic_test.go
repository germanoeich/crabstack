package model

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func writeAnthropicSSE(w http.ResponseWriter, model string, contentBlocks []anthropicContentBlock, stopReason string, inputTokens, outputTokens int64) {
	w.Header().Set("content-type", "text/event-stream")
	flusher, _ := w.(http.Flusher)

	// message_start
	msgStart := fmt.Sprintf(`{"type":"message_start","message":{"id":"msg_test","type":"message","role":"assistant","model":%q,"content":[],"stop_reason":null,"usage":{"input_tokens":%d,"output_tokens":0}}}`, model, inputTokens)
	fmt.Fprintf(w, "event: message_start\ndata: %s\n\n", msgStart)
	if flusher != nil {
		flusher.Flush()
	}

	for i, block := range contentBlocks {
		switch block.Type {
		case "text":
			// content_block_start
			fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n",
				fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`, i))

			// content_block_delta with text
			escaped, _ := json.Marshal(block.Text)
			fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n",
				fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%s}}`, i, string(escaped)))

			// content_block_stop
			fmt.Fprintf(w, "event: content_block_stop\ndata: %s\n\n",
				fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, i))

		case "tool_use":
			inputJSON := "{}"
			if len(block.Input) > 0 {
				inputJSON = string(block.Input)
			}
			// content_block_start
			fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n",
				fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":%q,"name":%q,"input":{}}}`, i, block.ID, block.Name))

			// content_block_delta with input_json_delta
			if inputJSON != "{}" {
				escaped, _ := json.Marshal(inputJSON)
				fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n",
					fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":%s}}`, i, string(escaped)))
			}

			// content_block_stop
			fmt.Fprintf(w, "event: content_block_stop\ndata: %s\n\n",
				fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, i))
		}
		if flusher != nil {
			flusher.Flush()
		}
	}

	// message_delta
	fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n",
		fmt.Sprintf(`{"type":"message_delta","delta":{"stop_reason":%q},"usage":{"output_tokens":%d}}`, stopReason, outputTokens))

	// message_stop
	fmt.Fprintf(w, "event: message_stop\ndata: %s\n\n", `{"type":"message_stop"}`)
	if flusher != nil {
		flusher.Flush()
	}
}

func TestAnthropicCompleteSuccess(t *testing.T) {
	var seen anthropicRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/messages" {
			t.Fatalf("expected /v1/messages, got %s", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "test-key" {
			t.Fatalf("expected x-api-key header")
		}
		if got := r.Header.Get("anthropic-version"); got != anthropicVersion {
			t.Fatalf("expected anthropic-version=%s, got %s", anthropicVersion, got)
		}
		if got := r.Header.Get("content-type"); got != "application/json" {
			t.Fatalf("expected content-type=application/json, got %s", got)
		}

		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		writeAnthropicSSE(w, "claude-sonnet-4", []anthropicContentBlock{
			{Type: "text", Text: "Hello"},
			{Type: "text", Text: " world"},
		}, "end_turn", 12, 34)
	}))
	defer server.Close()

	provider := NewAnthropicProvider(
		"test-key",
		WithAnthropicEndpoint(server.URL+"/v1/messages"),
		WithAnthropicHTTPClient(server.Client()),
	)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Model:        "claude-sonnet-4",
		MaxTokens:    256,
		SystemPrompt: "You are concise.",
		Messages: []Message{
			{Role: RoleSystem, Content: "Always return plain text."},
			{Role: RoleUser, Content: "Say hi"},
		},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if seen.Model != "claude-sonnet-4" {
		t.Fatalf("unexpected model: %s", seen.Model)
	}
	if seen.MaxTokens != 256 {
		t.Fatalf("unexpected max_tokens: %d", seen.MaxTokens)
	}
	if !seen.Stream {
		t.Fatalf("expected stream=true in request")
	}
	if len(seen.Messages) != 1 {
		t.Fatalf("expected one non-system message, got %d", len(seen.Messages))
	}
	if seen.Messages[0].Role != "user" {
		t.Fatalf("unexpected role: %s", seen.Messages[0].Role)
	}
	if seen.Messages[0].Content.text == nil || *seen.Messages[0].Content.text != "Say hi" {
		t.Fatalf("unexpected message payload: %+v", seen.Messages[0])
	}
	if seen.System != "You are concise.\n\nAlways return plain text." {
		t.Fatalf("unexpected system prompt: %q", seen.System)
	}

	if resp.Content != "Hello world" {
		t.Fatalf("unexpected content: %q", resp.Content)
	}
	if len(resp.Blocks) != 2 || resp.Blocks[0].Type != "text" || resp.Blocks[1].Type != "text" {
		t.Fatalf("unexpected blocks: %+v", resp.Blocks)
	}
	if resp.Usage.InputTokens != 12 || resp.Usage.OutputTokens != 34 {
		t.Fatalf("unexpected usage: %+v", resp.Usage)
	}
	if resp.Model != "claude-sonnet-4" {
		t.Fatalf("unexpected model: %s", resp.Model)
	}
	if resp.StopReason != "end_turn" {
		t.Fatalf("unexpected stop reason: %s", resp.StopReason)
	}
}

func TestAnthropicCompleteRequestIncludesToolsAndToolResultMessages(t *testing.T) {
	var seen anthropicRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		writeAnthropicSSE(w, "claude-sonnet-4", []anthropicContentBlock{
			{Type: "text", Text: "done"},
		}, "end_turn", 1, 1)
	}))
	defer server.Close()

	provider := NewAnthropicProvider(
		"test-key",
		WithAnthropicEndpoint(server.URL),
		WithAnthropicHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "claude-sonnet-4",
		MaxTokens: 128,
		Tools: []ToolDefinition{
			{
				Name:        "get_time",
				Description: "Get current time",
				InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
			},
		},
		Messages: []Message{
			{Role: RoleUser, Content: "What time is it?"},
			{
				Role: RoleAssistant,
				Blocks: []ContentBlock{
					{Type: "tool_use", ID: "toolu_1", Name: "get_time", Input: json.RawMessage(`{}`)},
				},
			},
			{
				Role: RoleUser,
				Blocks: []ContentBlock{
					{Type: "tool_result", ToolUseID: "toolu_1", Content: "3:42 PM"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if len(seen.Tools) != 1 {
		t.Fatalf("expected one tool, got %d", len(seen.Tools))
	}
	if seen.Tools[0].Name != "get_time" || seen.Tools[0].Description != "Get current time" {
		t.Fatalf("unexpected tool: %+v", seen.Tools[0])
	}
	if string(seen.Tools[0].InputSchema) != `{"type":"object","properties":{}}` {
		t.Fatalf("unexpected input schema: %s", string(seen.Tools[0].InputSchema))
	}
	if len(seen.Messages) != 3 {
		t.Fatalf("expected three messages, got %d", len(seen.Messages))
	}
	if seen.Messages[0].Content.text == nil || *seen.Messages[0].Content.text != "What time is it?" {
		t.Fatalf("unexpected user text message: %+v", seen.Messages[0])
	}
	if len(seen.Messages[1].Content.blocks) != 1 || seen.Messages[1].Content.blocks[0].Type != "tool_use" {
		t.Fatalf("unexpected assistant tool_use message: %+v", seen.Messages[1])
	}
	if len(seen.Messages[2].Content.blocks) != 1 || seen.Messages[2].Content.blocks[0].Type != "tool_result" {
		t.Fatalf("unexpected user tool_result message: %+v", seen.Messages[2])
	}
}

func TestAnthropicCompleteToolUseStopReasonIsNotError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeAnthropicSSE(w, "claude-sonnet-4", []anthropicContentBlock{
			{Type: "tool_use", ID: "toolu_xxx", Name: "get_time", Input: json.RawMessage(`{}`)},
		}, "tool_use", 5, 2)
	}))
	defer server.Close()

	provider := NewAnthropicProvider(
		"test-key",
		WithAnthropicEndpoint(server.URL),
		WithAnthropicHTTPClient(server.Client()),
	)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "claude-sonnet-4",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "What time is it?"}},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if resp.Content != "" {
		t.Fatalf("expected empty content for tool_use response, got %q", resp.Content)
	}
	if resp.StopReason != "tool_use" {
		t.Fatalf("unexpected stop reason: %s", resp.StopReason)
	}
	if len(resp.Blocks) != 1 {
		t.Fatalf("expected one block, got %d", len(resp.Blocks))
	}
	if resp.Blocks[0].Type != "tool_use" || resp.Blocks[0].ID != "toolu_xxx" || resp.Blocks[0].Name != "get_time" {
		t.Fatalf("unexpected tool block: %+v", resp.Blocks[0])
	}
}

func TestAnthropicCompleteMixedTextAndToolUseResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeAnthropicSSE(w, "claude-sonnet-4", []anthropicContentBlock{
			{Type: "text", Text: "Let me check. "},
			{Type: "tool_use", ID: "toolu_2", Name: "weather", Input: json.RawMessage(`{"city":"SF"}`)},
		}, "tool_use", 5, 2)
	}))
	defer server.Close()

	provider := NewAnthropicProvider(
		"test-key",
		WithAnthropicEndpoint(server.URL),
		WithAnthropicHTTPClient(server.Client()),
	)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "claude-sonnet-4",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "weather?"}},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if resp.Content != "Let me check. " {
		t.Fatalf("unexpected content: %q", resp.Content)
	}
	if len(resp.Blocks) != 2 {
		t.Fatalf("expected two blocks, got %d", len(resp.Blocks))
	}
	if resp.Blocks[1].Type != "tool_use" || resp.Blocks[1].Name != "weather" {
		t.Fatalf("unexpected second block: %+v", resp.Blocks[1])
	}
}

func TestAnthropicCompleteRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"slow down"}}`))
	}))
	defer server.Close()

	provider := NewAnthropicProvider(
		"test-key",
		WithAnthropicEndpoint(server.URL),
		WithAnthropicHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "claude-sonnet-4",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected rate limit error")
	}
	if !strings.Contains(err.Error(), "rate limited") || !strings.Contains(err.Error(), "slow down") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnthropicCompleteMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return an empty body - the SSE parser will see no data
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider := NewAnthropicProvider(
		"test-key",
		WithAnthropicEndpoint(server.URL),
		WithAnthropicHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "claude-sonnet-4",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected decode error")
	}
	if !strings.Contains(err.Error(), "decode anthropic response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnthropicCompleteEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Stream with no content blocks
		writeAnthropicSSE(w, "claude-sonnet-4", nil, "end_turn", 1, 1)
	}))
	defer server.Close()

	provider := NewAnthropicProvider(
		"test-key",
		WithAnthropicEndpoint(server.URL),
		WithAnthropicHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "claude-sonnet-4",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected empty response error")
	}
	if !strings.Contains(err.Error(), "contained no text") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnthropicCompleteInvalidRoleFailsBeforeRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider := NewAnthropicProvider(
		"test-key",
		WithAnthropicEndpoint(server.URL),
		WithAnthropicHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "claude-sonnet-4",
		MaxTokens: 128,
		Messages:  []Message{{Role: Role("invalid"), Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "unsupported message role") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("expected no request to be made, got %d", got)
	}
}
