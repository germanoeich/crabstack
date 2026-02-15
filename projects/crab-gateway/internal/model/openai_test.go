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

func writeOpenAISSE(w http.ResponseWriter, id, model string, message openAIMessage, finishReason string, promptTokens, completionTokens int64) {
	w.Header().Set("content-type", "text/event-stream")
	flusher, _ := w.(http.Flusher)

	// First chunk: role
	fmt.Fprintf(w, "data: %s\n\n",
		fmt.Sprintf(`{"id":%q,"object":"chat.completion.chunk","model":%q,"choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`, id, model))
	if flusher != nil {
		flusher.Flush()
	}

	// Content chunks
	if message.Content != nil && *message.Content != "" {
		escaped, _ := json.Marshal(*message.Content)
		fmt.Fprintf(w, "data: %s\n\n",
			fmt.Sprintf(`{"id":%q,"object":"chat.completion.chunk","model":%q,"choices":[{"index":0,"delta":{"content":%s},"finish_reason":null}]}`, id, model, string(escaped)))
		if flusher != nil {
			flusher.Flush()
		}
	}

	// Tool call chunks
	for _, tc := range message.ToolCalls {
		// First chunk: id + name
		nameJSON, _ := json.Marshal(tc.Function.Name)
		fmt.Fprintf(w, "data: %s\n\n",
			fmt.Sprintf(`{"id":%q,"object":"chat.completion.chunk","model":%q,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":%s,"arguments":""}}]},"finish_reason":null}]}`,
				id, model, tc.ID, string(nameJSON)))
		if flusher != nil {
			flusher.Flush()
		}

		// Second chunk: arguments
		argsJSON, _ := json.Marshal(tc.Function.Arguments)
		fmt.Fprintf(w, "data: %s\n\n",
			fmt.Sprintf(`{"id":%q,"object":"chat.completion.chunk","model":%q,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":%s}}]},"finish_reason":null}]}`,
				id, model, string(argsJSON)))
		if flusher != nil {
			flusher.Flush()
		}
	}

	// Final chunk: finish_reason + usage
	fmt.Fprintf(w, "data: %s\n\n",
		fmt.Sprintf(`{"id":%q,"object":"chat.completion.chunk","model":%q,"choices":[{"index":0,"delta":{},"finish_reason":%q}],"usage":{"prompt_tokens":%d,"completion_tokens":%d}}`,
			id, model, finishReason, promptTokens, completionTokens))

	fmt.Fprintf(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

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

		writeOpenAISSE(w, "chatcmpl_1", "gpt-4o-mini",
			openAIMessage{Content: stringPtr("pong")},
			"stop", 11, 5)
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
	if !seen.Stream {
		t.Fatalf("expected stream=true in request")
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
		writeOpenAISSE(w, "chatcmpl_2", "gpt-4o-mini",
			openAIMessage{Content: stringPtr("done")},
			"stop", 1, 1)
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
		writeOpenAISSE(w, "chatcmpl_3", "gpt-4o-mini",
			openAIMessage{
				ToolCalls: []openAIToolCall{
					{
						ID:   "call_xxx",
						Type: "function",
						Function: openAIToolCallFunction{
							Name:      "get_time",
							Arguments: "{}",
						},
					},
				},
			},
			"tool_calls", 11, 5)
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
		// Empty body — SSE parser sees no data
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
		// Send a stream with no content and no finish_reason — will produce empty choices
		w.Header().Set("content-type", "text/event-stream")
		fmt.Fprintf(w, "data: %s\n\n", `{"id":"chatcmpl_x","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
		fmt.Fprintf(w, "data: [DONE]\n\n")
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
	// The SSE parser will produce a response with one choice (accumulated), but
	// with no text and no tool calls, so it'll hit "contained no content"
	if !strings.Contains(err.Error(), "contained no content") && !strings.Contains(err.Error(), "contained no choices") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenAICompleteEmptyContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeOpenAISSE(w, "chatcmpl_x", "gpt-4o-mini",
			openAIMessage{Content: stringPtr("")},
			"stop", 1, 1)
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
