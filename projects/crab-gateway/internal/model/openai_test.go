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

func TestOpenAICompleteSuccess(t *testing.T) {
	var seen openAIRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("expected /v1/chat/completions, got %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		if got := r.Header.Get("content-type"); got != "application/json" {
			t.Fatalf("expected content-type=application/json, got %s", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode body: %v", err)
		}

		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl_1",
			"model":"gpt-4o-mini",
			"choices":[{"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":11,"completion_tokens":5}
		}`))
	}))
	defer server.Close()

	provider := NewOpenAIProvider(
		"test-key",
		WithOpenAIEndpoint(server.URL+"/v1/chat/completions"),
		WithOpenAIHTTPClient(server.Client()),
	)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Model:        "gpt-4o-mini",
		MaxTokens:    256,
		Temperature:  0.2,
		SystemPrompt: "You are concise.",
		Messages: []Message{
			{Role: RoleUser, Content: "ping"},
		},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if seen.Model != "gpt-4o-mini" {
		t.Fatalf("unexpected model: %s", seen.Model)
	}
	if seen.MaxTokens != 256 {
		t.Fatalf("unexpected max_tokens: %d", seen.MaxTokens)
	}
	if seen.Temperature != 0.2 {
		t.Fatalf("unexpected temperature: %v", seen.Temperature)
	}
	if len(seen.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(seen.Messages))
	}
	if seen.Messages[0].Role != "system" || seen.Messages[0].Content == nil || *seen.Messages[0].Content != "You are concise." {
		t.Fatalf("unexpected system message: %+v", seen.Messages[0])
	}
	if seen.Messages[1].Role != "user" || seen.Messages[1].Content == nil || *seen.Messages[1].Content != "ping" {
		t.Fatalf("unexpected user message: %+v", seen.Messages[1])
	}

	if resp.Content != "pong" {
		t.Fatalf("unexpected content: %s", resp.Content)
	}
	if len(resp.Blocks) != 1 || resp.Blocks[0].Type != "text" || resp.Blocks[0].Text != "pong" {
		t.Fatalf("unexpected blocks: %+v", resp.Blocks)
	}
	if resp.Usage.InputTokens != 11 || resp.Usage.OutputTokens != 5 {
		t.Fatalf("unexpected usage: %+v", resp.Usage)
	}
	if resp.Model != "gpt-4o-mini" {
		t.Fatalf("unexpected model: %s", resp.Model)
	}
	if resp.StopReason != "stop" {
		t.Fatalf("unexpected stop reason: %s", resp.StopReason)
	}
}

func TestOpenAICompleteRequestIncludesToolsAndToolResultMessages(t *testing.T) {
	var seen openAIRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer server.Close()

	provider := NewOpenAIProvider(
		"test-key",
		WithOpenAIEndpoint(server.URL),
		WithOpenAIHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "gpt-4o-mini",
		MaxTokens: 256,
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
					{Type: "tool_use", ID: "call_1", Name: "get_time", Input: json.RawMessage(`{}`)},
				},
			},
			{
				Role: RoleUser,
				Blocks: []ContentBlock{
					{Type: "tool_result", ToolUseID: "call_1", Content: "3:42 PM"},
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
	if seen.Tools[0].Type != "function" || seen.Tools[0].Function.Name != "get_time" {
		t.Fatalf("unexpected tool payload: %+v", seen.Tools[0])
	}
	if string(seen.Tools[0].Function.Parameters) != `{"type":"object","properties":{}}` {
		t.Fatalf("unexpected tool parameters: %s", string(seen.Tools[0].Function.Parameters))
	}
	if len(seen.Messages) != 3 {
		t.Fatalf("expected three messages, got %d", len(seen.Messages))
	}
	if seen.Messages[0].Role != "user" || seen.Messages[0].Content == nil || *seen.Messages[0].Content != "What time is it?" {
		t.Fatalf("unexpected first message: %+v", seen.Messages[0])
	}
	if seen.Messages[1].Role != "assistant" || len(seen.Messages[1].ToolCalls) != 1 {
		t.Fatalf("unexpected assistant message: %+v", seen.Messages[1])
	}
	if seen.Messages[1].ToolCalls[0].ID != "call_1" || seen.Messages[1].ToolCalls[0].Function.Name != "get_time" {
		t.Fatalf("unexpected tool call: %+v", seen.Messages[1].ToolCalls[0])
	}
	if seen.Messages[2].Role != "tool" || seen.Messages[2].ToolCallID != "call_1" || seen.Messages[2].Content == nil || *seen.Messages[2].Content != "3:42 PM" {
		t.Fatalf("unexpected tool result message: %+v", seen.Messages[2])
	}
}

func TestOpenAICompleteToolCallsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"model":"gpt-4o-mini",
			"choices":[{
				"message":{
					"role":"assistant",
					"content":null,
					"tool_calls":[{
						"id":"call_xxx",
						"type":"function",
						"function":{"name":"get_time","arguments":"{}"}
					}]
				},
				"finish_reason":"tool_calls"
			}],
			"usage":{"prompt_tokens":11,"completion_tokens":5}
		}`))
	}))
	defer server.Close()

	provider := NewOpenAIProvider(
		"test-key",
		WithOpenAIEndpoint(server.URL),
		WithOpenAIHTTPClient(server.Client()),
	)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "gpt-4o-mini",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "What time is it?"}},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if resp.Content != "" {
		t.Fatalf("expected empty text content, got %q", resp.Content)
	}
	if resp.StopReason != "tool_calls" {
		t.Fatalf("unexpected stop reason: %s", resp.StopReason)
	}
	if len(resp.Blocks) != 1 {
		t.Fatalf("expected one content block, got %d", len(resp.Blocks))
	}
	if resp.Blocks[0].Type != "tool_use" || resp.Blocks[0].ID != "call_xxx" || resp.Blocks[0].Name != "get_time" {
		t.Fatalf("unexpected block: %+v", resp.Blocks[0])
	}
}

func TestOpenAICompleteRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"quota exceeded"}}`))
	}))
	defer server.Close()

	provider := NewOpenAIProvider(
		"test-key",
		WithOpenAIEndpoint(server.URL),
		WithOpenAIHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "gpt-4o-mini",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected rate-limit error")
	}
	if !strings.Contains(err.Error(), "rate limited") || !strings.Contains(err.Error(), "quota exceeded") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenAICompleteMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":`))
	}))
	defer server.Close()

	provider := NewOpenAIProvider(
		"test-key",
		WithOpenAIEndpoint(server.URL),
		WithOpenAIHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "gpt-4o-mini",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected decode error")
	}
	if !strings.Contains(err.Error(), "decode openai response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenAICompleteEmptyChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer server.Close()

	provider := NewOpenAIProvider(
		"test-key",
		WithOpenAIEndpoint(server.URL),
		WithOpenAIHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "gpt-4o-mini",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected empty choices error")
	}
	if !strings.Contains(err.Error(), "contained no choices") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenAICompleteEmptyContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":""},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer server.Close()

	provider := NewOpenAIProvider(
		"test-key",
		WithOpenAIEndpoint(server.URL),
		WithOpenAIHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "gpt-4o-mini",
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected empty content error")
	}
	if !strings.Contains(err.Error(), "contained no content") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenAICompleteInvalidRoleFailsBeforeRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider := NewOpenAIProvider(
		"test-key",
		WithOpenAIEndpoint(server.URL),
		WithOpenAIHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:     "gpt-4o-mini",
		MaxTokens: 128,
		Messages:  []Message{{Role: Role("bad-role"), Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected unsupported role error")
	}
	if !strings.Contains(err.Error(), "unsupported message role") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("expected no request to be made, got %d", got)
	}
}
