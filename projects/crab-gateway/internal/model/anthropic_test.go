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
	if seen.Messages[0].Role != "user" || seen.Messages[0].Content != "Say hi" {
		t.Fatalf("unexpected message payload: %+v", seen.Messages[0])
	}
	if seen.System != "You are concise.\n\nAlways return plain text." {
		t.Fatalf("unexpected system prompt: %q", seen.System)
	}

	if resp.Content != "Hello world" {
		t.Fatalf("unexpected content: %q", resp.Content)
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
