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

func TestCodexCompleteSuccess(t *testing.T) {
	var seen codexRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/codex/responses" {
			t.Fatalf("expected /codex/responses, got %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		if got := r.Header.Get("chatgpt-account-id"); got != "acct-123" {
			t.Fatalf("unexpected account header: %s", got)
		}
		if got := r.Header.Get("OpenAI-Beta"); got != codexOpenAIBeta {
			t.Fatalf("unexpected OpenAI-Beta header: %s", got)
		}
		if got := r.Header.Get("originator"); got != codexOriginator {
			t.Fatalf("unexpected originator header: %s", got)
		}
		if got := r.Header.Get("content-type"); got != "application/json" {
			t.Fatalf("expected content-type=application/json, got %s", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode body: %v", err)
		}

		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"resp_1",
			"model":"gpt-5-codex",
			"status":"completed",
			"output":[
				{"type":"message","role":"assistant","content":[
					{"type":"output_text","text":"pong"},
					{"type":"output_text","text":"!"}
				]}
			],
			"usage":{"input_tokens":11,"output_tokens":5,"total_tokens":16}
		}`))
	}))
	defer server.Close()

	provider := NewCodexProvider(
		"test-token",
		"acct-123",
		WithCodexEndpoint(server.URL),
		WithCodexHTTPClient(server.Client()),
	)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Model:        "gpt-5-codex",
		Temperature:  0.2,
		SystemPrompt: "You are concise.",
		Messages: []Message{
			{Role: RoleSystem, Content: "Always return plain text."},
			{Role: RoleUser, Content: "ping"},
		},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if seen.Model != "gpt-5-codex" {
		t.Fatalf("unexpected model: %s", seen.Model)
	}
	if seen.Store {
		t.Fatalf("expected store=false")
	}
	if seen.Stream {
		t.Fatalf("expected stream=false")
	}
	if seen.Temperature != 0.2 {
		t.Fatalf("unexpected temperature: %v", seen.Temperature)
	}
	if seen.Instructions != "You are concise.\n\nAlways return plain text." {
		t.Fatalf("unexpected instructions: %q", seen.Instructions)
	}
	if len(seen.Input) != 1 {
		t.Fatalf("expected one input item, got %d", len(seen.Input))
	}
	if seen.Input[0].Role != "user" || len(seen.Input[0].Content) != 1 {
		t.Fatalf("unexpected user item: %+v", seen.Input[0])
	}
	if seen.Input[0].Content[0].Type != "input_text" || seen.Input[0].Content[0].Text != "ping" {
		t.Fatalf("unexpected user content item: %+v", seen.Input[0].Content[0])
	}

	if resp.Content != "pong!" {
		t.Fatalf("unexpected content: %q", resp.Content)
	}
	if len(resp.Blocks) != 2 || resp.Blocks[0].Type != "text" || resp.Blocks[1].Type != "text" {
		t.Fatalf("unexpected blocks: %+v", resp.Blocks)
	}
	if resp.Usage.InputTokens != 11 || resp.Usage.OutputTokens != 5 {
		t.Fatalf("unexpected usage: %+v", resp.Usage)
	}
	if resp.Model != "gpt-5-codex" {
		t.Fatalf("unexpected model: %s", resp.Model)
	}
	if resp.StopReason != "end_turn" {
		t.Fatalf("unexpected stop reason: %s", resp.StopReason)
	}
}

func TestCodexCompleteRequestIncludesToolsAndToolResultMessages(t *testing.T) {
	var seen codexRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/codex/responses" {
			t.Fatalf("expected /backend-api/codex/responses, got %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{
			"model":"gpt-5-codex",
			"status":"completed",
			"output":[{"type":"function_call","id":"call_resp_1","name":"get_time","arguments":"{\"zone\":\"UTC\"}"}],
			"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}
		}`))
	}))
	defer server.Close()

	provider := NewCodexProvider(
		"test-token",
		"acct-123",
		WithCodexEndpoint(server.URL+"/backend-api"),
		WithCodexHTTPClient(server.Client()),
	)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Model: "gpt-5-codex",
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
	if seen.Tools[0].Type != "function" || seen.Tools[0].Name != "get_time" {
		t.Fatalf("unexpected tool payload: %+v", seen.Tools[0])
	}
	if string(seen.Tools[0].Parameters) != `{"type":"object","properties":{}}` {
		t.Fatalf("unexpected tool parameters: %s", string(seen.Tools[0].Parameters))
	}
	if seen.ToolChoice != "auto" {
		t.Fatalf("unexpected tool choice: %s", seen.ToolChoice)
	}
	if !seen.ParallelToolCalls {
		t.Fatalf("expected parallel_tool_calls=true")
	}
	if len(seen.Input) != 3 {
		t.Fatalf("expected three input items, got %d", len(seen.Input))
	}
	if seen.Input[0].Role != "user" || seen.Input[0].Content[0].Text != "What time is it?" {
		t.Fatalf("unexpected first input item: %+v", seen.Input[0])
	}
	if seen.Input[1].Type != "function_call" || seen.Input[1].CallID != "call_1" || seen.Input[1].Name != "get_time" || seen.Input[1].Arguments != "{}" {
		t.Fatalf("unexpected second input item: %+v", seen.Input[1])
	}
	if seen.Input[2].Type != "function_call_output" || seen.Input[2].CallID != "call_1" || seen.Input[2].Output != "3:42 PM" {
		t.Fatalf("unexpected third input item: %+v", seen.Input[2])
	}

	if resp.Content != "" {
		t.Fatalf("expected empty text content, got %q", resp.Content)
	}
	if resp.StopReason != "tool_use" {
		t.Fatalf("unexpected stop reason: %s", resp.StopReason)
	}
	if len(resp.Blocks) != 1 {
		t.Fatalf("expected one content block, got %d", len(resp.Blocks))
	}
	if resp.Blocks[0].Type != "tool_use" || resp.Blocks[0].ID != "call_resp_1" || resp.Blocks[0].Name != "get_time" {
		t.Fatalf("unexpected block: %+v", resp.Blocks[0])
	}
	if string(resp.Blocks[0].Input) != `{"zone":"UTC"}` {
		t.Fatalf("unexpected tool input: %s", string(resp.Blocks[0].Input))
	}
}

func TestCodexCompleteRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"quota exceeded"}}`))
	}))
	defer server.Close()

	provider := NewCodexProvider(
		"test-token",
		"acct-123",
		WithCodexEndpoint(server.URL),
		WithCodexHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:    "gpt-5-codex",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected rate-limit error")
	}
	if !strings.Contains(err.Error(), "codex rate limited") || !strings.Contains(err.Error(), "quota exceeded") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCodexCompleteMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":`))
	}))
	defer server.Close()

	provider := NewCodexProvider(
		"test-token",
		"acct-123",
		WithCodexEndpoint(server.URL),
		WithCodexHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:    "gpt-5-codex",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected decode error")
	}
	if !strings.Contains(err.Error(), "decode codex response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCodexCompleteEmptyContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()

	provider := NewCodexProvider(
		"test-token",
		"acct-123",
		WithCodexEndpoint(server.URL),
		WithCodexHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:    "gpt-5-codex",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected empty content error")
	}
	if !strings.Contains(err.Error(), "codex response contained no content") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCodexCompleteInvalidRoleFailsBeforeRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider := NewCodexProvider(
		"test-token",
		"acct-123",
		WithCodexEndpoint(server.URL),
		WithCodexHTTPClient(server.Client()),
	)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:    "gpt-5-codex",
		Messages: []Message{{Role: Role("bad-role"), Content: "hi"}},
	})
	if err == nil {
		t.Fatalf("expected unsupported role error")
	}
	if !strings.Contains(err.Error(), "codex unsupported message role") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("expected no request to be made, got %d", got)
	}
}

func TestCodexCompleteMissingCredentials(t *testing.T) {
	provider := NewCodexProvider("", "acct-123")
	_, err := provider.Complete(context.Background(), CompletionRequest{
		Model:    "gpt-5-codex",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil || !strings.Contains(err.Error(), "codex auth token is required") {
		t.Fatalf("unexpected error for missing token: %v", err)
	}

	provider = NewCodexProvider("test-token", "")
	_, err = provider.Complete(context.Background(), CompletionRequest{
		Model:    "gpt-5-codex",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil || !strings.Contains(err.Error(), "codex account id is required") {
		t.Fatalf("unexpected error for missing account id: %v", err)
	}
}

func TestResolveCodexEndpoint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "default", input: "", want: "https://chatgpt.com/backend-api/codex/responses"},
		{name: "base", input: "https://chatgpt.com/backend-api", want: "https://chatgpt.com/backend-api/codex/responses"},
		{name: "codex", input: "https://chatgpt.com/backend-api/codex", want: "https://chatgpt.com/backend-api/codex/responses"},
		{name: "full", input: "https://chatgpt.com/backend-api/codex/responses", want: "https://chatgpt.com/backend-api/codex/responses"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveCodexEndpoint(tt.input); got != tt.want {
				t.Fatalf("unexpected endpoint: got %s want %s", got, tt.want)
			}
		})
	}
}
