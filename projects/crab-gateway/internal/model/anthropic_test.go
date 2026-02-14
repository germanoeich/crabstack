package model

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

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

		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"msg_123",
			"type":"message",
			"role":"assistant",
			"model":"claude-sonnet-4",
			"content":[{"type":"text","text":"Hello"},{"type":"text","text":" world"}],
			"stop_reason":"end_turn",
			"usage":{"input_tokens":12,"output_tokens":34}
		}`))
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
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"model":"claude-sonnet-4","content":[{"type":"text","text":"done"}],"usage":{"input_tokens":1,"output_tokens":1},"stop_reason":"end_turn"}`))
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
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"model":"claude-sonnet-4",
			"content":[{"type":"tool_use","id":"toolu_xxx","name":"get_time","input":{}}],
			"stop_reason":"tool_use",
			"usage":{"input_tokens":5,"output_tokens":2}
		}`))
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
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"model":"claude-sonnet-4",
			"content":[
				{"type":"text","text":"Let me check. "},
				{"type":"tool_use","id":"toolu_2","name":"weather","input":{"city":"SF"}}
			],
			"stop_reason":"tool_use",
			"usage":{"input_tokens":5,"output_tokens":2}
		}`))
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
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":`))
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
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"model":"claude-sonnet-4","content":[],"usage":{"input_tokens":1,"output_tokens":1}}`))
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
