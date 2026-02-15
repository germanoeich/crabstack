package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"crabstack.local/projects/crab-gateway/internal/dispatch"
	"crabstack.local/projects/crab-gateway/internal/model"
	"crabstack.local/projects/crab-gateway/internal/session"
	"crabstack.local/projects/crab-gateway/internal/subscribers"
	"crabstack.local/projects/crab-gateway/internal/toolclient"
	"crabstack.local/projects/crab-sdk/types"
)

type collectorSubscriber struct {
	events chan types.EventEnvelope
}

func (c *collectorSubscriber) Name() string {
	return "collector"
}

func (c *collectorSubscriber) Handle(_ context.Context, event types.EventEnvelope) error {
	c.events <- event
	return nil
}

type mockProvider struct {
	response  model.CompletionResponse
	responses []model.CompletionResponse
	err       error
	requests  []model.CompletionRequest
}

func (m *mockProvider) Complete(_ context.Context, req model.CompletionRequest) (model.CompletionResponse, error) {
	m.requests = append(m.requests, req)
	if m.err != nil {
		return model.CompletionResponse{}, m.err
	}
	resp := m.response
	if len(m.responses) > 0 {
		resp = m.responses[0]
		m.responses = m.responses[1:]
	}
	if resp.Model == "" {
		resp.Model = req.Model
	}
	return resp, nil
}

func TestServiceProcessEvent_ChannelMessageUsesLLMResponse(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{
			Content: "hello from model",
			Usage: model.Usage{
				InputTokens:  11,
				OutputTokens: 7,
			},
			Model: "claude-sonnet-4-20250514",
		},
	}
	svc, collector, store := newTestService(t, map[string]model.Provider{"anthropic": provider})

	inbound := inboundEvent(t, "evt_in", "trace_1", "tenant_1", "session_1", "anthropic", "hello")
	svc.processEvent(context.Background(), inbound)

	seen := collectEventSet(t, collector.events, 3)
	if _, ok := seen[types.EventTypeAgentTurnStarted]; !ok {
		t.Fatalf("expected %s", types.EventTypeAgentTurnStarted)
	}
	if _, ok := seen[types.EventTypeAgentTurnCompleted]; !ok {
		t.Fatalf("expected %s", types.EventTypeAgentTurnCompleted)
	}
	respEvent, ok := seen[types.EventTypeAgentResponseCreated]
	if !ok {
		t.Fatalf("expected %s", types.EventTypeAgentResponseCreated)
	}

	var resp types.AgentResponseCreatedPayload
	if err := respEvent.DecodePayload(&resp); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	if len(resp.Content) == 0 || resp.Content[0].Text != "hello from model" {
		t.Fatalf("unexpected response content: %+v", resp.Content)
	}
	if len(resp.Actions) == 0 {
		t.Fatalf("expected send action")
	}
	if got, _ := resp.Actions[0].Args["text"].(string); got != "hello from model" {
		t.Fatalf("unexpected send_message args text: %q", got)
	}
	if resp.Usage == nil {
		t.Fatalf("expected usage payload")
	}
	if resp.Usage.InputTokens != 11 || resp.Usage.OutputTokens != 7 {
		t.Fatalf("unexpected usage payload: %+v", *resp.Usage)
	}
	if resp.Usage.Provider != "anthropic" {
		t.Fatalf("expected usage provider anthropic, got %q", resp.Usage.Provider)
	}

	if len(provider.requests) != 1 {
		t.Fatalf("expected one provider request, got %d", len(provider.requests))
	}
	req := provider.requests[0]
	if req.Model != defaultModelName {
		t.Fatalf("expected model %q, got %q", defaultModelName, req.Model)
	}
	if req.MaxTokens != defaultMaxTokens {
		t.Fatalf("expected max tokens %d, got %d", defaultMaxTokens, req.MaxTokens)
	}
	if req.SystemPrompt != systemPrompt {
		t.Fatalf("expected system prompt %q, got %q", systemPrompt, req.SystemPrompt)
	}
	wantMessages := []model.Message{
		{Role: model.RoleUser, Content: "hello"},
	}
	if !reflect.DeepEqual(req.Messages, wantMessages) {
		t.Fatalf("unexpected request messages: %+v", req.Messages)
	}

	turns, err := store.GetTurns(context.Background(), "tenant_1", "session_1", 10)
	if err != nil {
		t.Fatalf("get turns: %v", err)
	}
	if len(turns) != 1 {
		t.Fatalf("expected one turn, got %d", len(turns))
	}
	if turns[0].Status != session.TurnStatusCompleted {
		t.Fatalf("expected completed turn status, got %s", turns[0].Status)
	}
}

func TestServiceProcessEvent_ChannelMessageBuildsConversationHistory(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{
			Content: "assistant 3",
		},
	}
	svc, _, store := newTestService(t, map[string]model.Provider{"anthropic": provider})

	first := inboundEvent(t, "evt_prev_1", "trace_prev_1", "tenant_1", "session_1", "anthropic", "user 1")
	second := inboundEvent(t, "evt_prev_2", "trace_prev_2", "tenant_1", "session_1", "anthropic", "user 2")
	seedCompletedTurn(t, store, first, "assistant 1")
	seedCompletedTurn(t, store, second, "assistant 2")

	current := inboundEvent(t, "evt_now", "trace_now", "tenant_1", "session_1", "anthropic", "user 3")
	svc.processEvent(context.Background(), current)

	if len(provider.requests) != 1 {
		t.Fatalf("expected one provider request, got %d", len(provider.requests))
	}
	want := []model.Message{
		{Role: model.RoleUser, Content: "user 1"},
		{Role: model.RoleAssistant, Content: "assistant 1"},
		{Role: model.RoleUser, Content: "user 2"},
		{Role: model.RoleAssistant, Content: "assistant 2"},
		{Role: model.RoleUser, Content: "user 3"},
	}
	if !reflect.DeepEqual(provider.requests[0].Messages, want) {
		t.Fatalf("unexpected conversation history: %+v", provider.requests[0].Messages)
	}
}

func TestServiceProcessEvent_ChannelMessageUsesLast50Turns(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{
			Content: "bounded",
		},
	}
	svc, _, store := newTestService(t, map[string]model.Provider{"anthropic": provider})

	for i := 1; i <= 55; i++ {
		seedCompletedTurn(t, store, inboundEvent(
			t,
			fmt.Sprintf("evt_prev_%02d", i),
			fmt.Sprintf("trace_prev_%02d", i),
			"tenant_1",
			"session_1",
			"anthropic",
			fmt.Sprintf("user %02d", i),
		), fmt.Sprintf("assistant %02d", i))
	}

	current := inboundEvent(t, "evt_now", "trace_now", "tenant_1", "session_1", "anthropic", "user 56")
	svc.processEvent(context.Background(), current)

	if len(provider.requests) != 1 {
		t.Fatalf("expected one provider request, got %d", len(provider.requests))
	}
	got := provider.requests[0].Messages
	if len(got) != 99 {
		t.Fatalf("expected 99 messages from last 50 turns, got %d", len(got))
	}
	if got[0].Role != model.RoleUser || got[0].Content != "user 07" {
		t.Fatalf("unexpected first message: %+v", got[0])
	}
	if got[1].Role != model.RoleAssistant || got[1].Content != "assistant 07" {
		t.Fatalf("unexpected second message: %+v", got[1])
	}
	if last := got[len(got)-1]; last.Role != model.RoleUser || last.Content != "user 56" {
		t.Fatalf("unexpected last message: %+v", last)
	}
}

func TestServiceProcessEvent_ChannelMessageFallsBackToAnthropicProvider(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{
			Content: "from fallback",
		},
	}
	svc, collector, _ := newTestService(t, map[string]model.Provider{"anthropic": provider})

	inbound := inboundEvent(t, "evt_fallback", "trace_fallback", "tenant_1", "session_1", "agent_1", "hello")
	svc.processEvent(context.Background(), inbound)

	seen := collectEventSet(t, collector.events, 3)
	respEvent, ok := seen[types.EventTypeAgentResponseCreated]
	if !ok {
		t.Fatalf("expected %s", types.EventTypeAgentResponseCreated)
	}
	var resp types.AgentResponseCreatedPayload
	if err := respEvent.DecodePayload(&resp); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	if len(resp.Content) == 0 || resp.Content[0].Text != "from fallback" {
		t.Fatalf("unexpected response content: %+v", resp.Content)
	}
	if len(provider.requests) != 1 {
		t.Fatalf("expected fallback provider to be called once, got %d", len(provider.requests))
	}
}

func TestServiceProcessEvent_ProviderErrorEmitsFailed(t *testing.T) {
	provider := &mockProvider{err: errors.New("provider unavailable")}
	svc, collector, store := newTestService(t, map[string]model.Provider{"anthropic": provider})

	inbound := inboundEvent(t, "evt_err", "trace_err", "tenant_1", "session_1", "anthropic", "hello")
	svc.processEvent(context.Background(), inbound)

	seen := collectEventTypes(t, collector.events, 2)
	if !seen[types.EventTypeAgentTurnStarted] {
		t.Fatalf("expected %s", types.EventTypeAgentTurnStarted)
	}
	if !seen[types.EventTypeAgentTurnFailed] {
		t.Fatalf("expected %s", types.EventTypeAgentTurnFailed)
	}
	if seen[types.EventTypeAgentResponseCreated] {
		t.Fatalf("did not expect %s", types.EventTypeAgentResponseCreated)
	}
	if seen[types.EventTypeAgentTurnCompleted] {
		t.Fatalf("did not expect %s", types.EventTypeAgentTurnCompleted)
	}

	turns, err := store.GetTurns(context.Background(), "tenant_1", "session_1", 10)
	if err != nil {
		t.Fatalf("get turns: %v", err)
	}
	if len(turns) != 1 {
		t.Fatalf("expected one turn, got %d", len(turns))
	}
	if turns[0].Status != session.TurnStatusFailed {
		t.Fatalf("expected failed turn status, got %s", turns[0].Status)
	}
}

func TestServiceProcessEvent_InvalidPayloadEmitsFailed(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{
			Content: "unused",
		},
	}
	svc, collector, store := newTestService(t, map[string]model.Provider{"anthropic": provider})

	inbound := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt_in_bad",
		TraceID:    "trace_2",
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   "tenant_1",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeListener,
			ComponentID:   "listener_1",
		},
		Routing: types.EventRouting{
			AgentID:   "anthropic",
			SessionID: "session_1",
		},
		Payload: []byte("[]"),
	}

	svc.processEvent(context.Background(), inbound)

	seen := collectEventTypes(t, collector.events, 2)
	if !seen[types.EventTypeAgentTurnStarted] {
		t.Fatalf("expected %s", types.EventTypeAgentTurnStarted)
	}
	if !seen[types.EventTypeAgentTurnFailed] {
		t.Fatalf("expected %s", types.EventTypeAgentTurnFailed)
	}
	if seen[types.EventTypeAgentTurnCompleted] {
		t.Fatalf("did not expect %s", types.EventTypeAgentTurnCompleted)
	}

	turns, err := store.GetTurns(context.Background(), "tenant_1", "session_1", 10)
	if err != nil {
		t.Fatalf("get turns: %v", err)
	}
	if len(turns) != 1 {
		t.Fatalf("expected one turn, got %d", len(turns))
	}
	if turns[0].Status != session.TurnStatusFailed {
		t.Fatalf("expected failed turn status, got %s", turns[0].Status)
	}
	if len(provider.requests) != 0 {
		t.Fatalf("expected provider not to be called for invalid payload")
	}
}

func TestServiceProcessEvent_CLIMessageTracksCLIChannel(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{
			Content: "hello cli response",
		},
	}
	svc, collector, store := newTestService(t, map[string]model.Provider{"anthropic": provider})

	payload, err := json.Marshal(types.ChannelMessageReceivedPayload{Text: "hello cli"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	inbound := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt_cli_1",
		TraceID:    "trace_cli_1",
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   "tenant_cli",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeOperator,
			ComponentID:   "crab-cli-1",
			Platform:      "cli",
			ChannelID:     "cli",
			ActorID:       "operator",
			Transport:     types.TransportTypeHTTP,
		},
		Routing: types.EventRouting{
			AgentID:   "agent_cli",
			SessionID: "session_cli_1",
		},
		Payload: payload,
	}

	svc.processEvent(context.Background(), inbound)

	seen := collectEventSet(t, collector.events, 3)
	if _, ok := seen[types.EventTypeAgentResponseCreated]; !ok {
		t.Fatalf("expected %s", types.EventTypeAgentResponseCreated)
	}

	sessionRec, err := store.GetSession(context.Background(), "tenant_cli", "session_cli_1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sessionRec.LastActivePlatform != "cli" {
		t.Fatalf("expected last active platform cli, got %q", sessionRec.LastActivePlatform)
	}
	if sessionRec.LastActiveChannelID != "cli" {
		t.Fatalf("expected last active channel cli, got %q", sessionRec.LastActiveChannelID)
	}
}

func TestServiceProcessEvent_ToolLoopHappyPath(t *testing.T) {
	var seenToolReq types.ToolCallRequest
	server := newToolHostServer(t, []types.ToolDescriptor{
		{
			Name:        "get_time",
			Description: "Get time",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		},
	}, func(w http.ResponseWriter, req types.ToolCallRequest) {
		seenToolReq = req
		_ = json.NewEncoder(w).Encode(types.ToolCallResponse{
			Version:  types.VersionV1,
			CallID:   req.CallID,
			ToolName: req.ToolName,
			Status:   types.ToolCallStatusOK,
			Result:   map[string]any{"time": "3:42 PM"},
		})
	})
	defer server.Close()

	toolClient := toolclient.New(log.New(io.Discard, "", 0), []toolclient.HostConfig{{Name: "tools", BaseURL: server.URL}})
	if err := toolClient.Discover(context.Background()); err != nil {
		t.Fatalf("discover tools: %v", err)
	}

	provider := &mockProvider{
		responses: []model.CompletionResponse{
			{
				Blocks: []model.ContentBlock{
					{Type: "tool_use", ID: "toolu_1", Name: "get_time", Input: json.RawMessage(`{}`)},
				},
				StopReason: "tool_use",
				Usage: model.Usage{
					InputTokens:  10,
					OutputTokens: 3,
				},
			},
			{
				Content: "It is 3:42 PM.",
				Blocks:  []model.ContentBlock{{Type: "text", Text: "It is 3:42 PM."}},
				Usage: model.Usage{
					InputTokens:  9,
					OutputTokens: 4,
				},
			},
		},
	}

	svc, collector, _ := newTestServiceWithToolClient(t, map[string]model.Provider{"anthropic": provider}, toolClient)
	inbound := inboundEvent(t, "evt_tool_happy", "trace_tool_happy", "tenant_1", "session_1", "anthropic", "What time is it?")
	svc.processEvent(context.Background(), inbound)

	seen := collectEventSet(t, collector.events, 3)
	respEvent, ok := seen[types.EventTypeAgentResponseCreated]
	if !ok {
		t.Fatalf("expected %s", types.EventTypeAgentResponseCreated)
	}

	var resp types.AgentResponseCreatedPayload
	if err := respEvent.DecodePayload(&resp); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	if len(resp.Content) == 0 || resp.Content[0].Text != "It is 3:42 PM." {
		t.Fatalf("unexpected response content: %+v", resp.Content)
	}
	if resp.Usage == nil {
		t.Fatalf("expected usage payload")
	}
	if resp.Usage.InputTokens != 19 || resp.Usage.OutputTokens != 7 {
		t.Fatalf("unexpected usage totals: %+v", resp.Usage)
	}

	if len(provider.requests) != 2 {
		t.Fatalf("expected two model calls, got %d", len(provider.requests))
	}
	if len(provider.requests[0].Tools) != 1 || provider.requests[0].Tools[0].Name != "get_time" {
		t.Fatalf("expected discovered tools in request: %+v", provider.requests[0].Tools)
	}
	if len(provider.requests[1].Messages) < 3 {
		t.Fatalf("expected follow-up messages with tool result, got %+v", provider.requests[1].Messages)
	}
	followup := provider.requests[1].Messages
	assistantMsg := followup[len(followup)-2]
	if assistantMsg.Role != model.RoleAssistant || len(assistantMsg.Blocks) != 1 || assistantMsg.Blocks[0].Type != "tool_use" {
		t.Fatalf("unexpected assistant follow-up message: %+v", assistantMsg)
	}
	userMsg := followup[len(followup)-1]
	if userMsg.Role != model.RoleUser || len(userMsg.Blocks) != 1 || userMsg.Blocks[0].Type != "tool_result" {
		t.Fatalf("unexpected user tool result message: %+v", userMsg)
	}
	if userMsg.Blocks[0].IsError {
		t.Fatalf("expected successful tool result block")
	}
	if seenToolReq.Context.AgentID != inbound.Routing.AgentID || seenToolReq.Context.SessionID != inbound.Routing.SessionID {
		t.Fatalf("unexpected tool call context: %+v", seenToolReq.Context)
	}
	if seenToolReq.Context.RequestOrigin != types.RequestOriginAgentTurn {
		t.Fatalf("unexpected request origin: %s", seenToolReq.Context.RequestOrigin)
	}
}

func TestServiceProcessEvent_ToolLoopMultipleToolCallsInOneResponse(t *testing.T) {
	callCounts := map[string]int{}
	server := newToolHostServer(t, []types.ToolDescriptor{
		{Name: "get_time", Description: "Get time", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "get_date", Description: "Get date", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}, func(w http.ResponseWriter, req types.ToolCallRequest) {
		callCounts[req.ToolName]++
		_ = json.NewEncoder(w).Encode(types.ToolCallResponse{
			Version:  types.VersionV1,
			CallID:   req.CallID,
			ToolName: req.ToolName,
			Status:   types.ToolCallStatusOK,
			Result:   map[string]any{"value": req.ToolName + "_ok"},
		})
	})
	defer server.Close()

	toolClient := toolclient.New(log.New(io.Discard, "", 0), []toolclient.HostConfig{{Name: "tools", BaseURL: server.URL}})
	if err := toolClient.Discover(context.Background()); err != nil {
		t.Fatalf("discover tools: %v", err)
	}

	provider := &mockProvider{
		responses: []model.CompletionResponse{
			{
				Blocks: []model.ContentBlock{
					{Type: "tool_use", ID: "toolu_1", Name: "get_time", Input: json.RawMessage(`{}`)},
					{Type: "tool_use", ID: "toolu_2", Name: "get_date", Input: json.RawMessage(`{}`)},
				},
				StopReason: "tool_use",
			},
			{Content: "time/date ready"},
		},
	}

	svc, collector, _ := newTestServiceWithToolClient(t, map[string]model.Provider{"anthropic": provider}, toolClient)
	inbound := inboundEvent(t, "evt_tool_multi", "trace_tool_multi", "tenant_1", "session_1", "anthropic", "Need date/time")
	svc.processEvent(context.Background(), inbound)

	seen := collectEventSet(t, collector.events, 3)
	respEvent, ok := seen[types.EventTypeAgentResponseCreated]
	if !ok {
		t.Fatalf("expected %s", types.EventTypeAgentResponseCreated)
	}
	var resp types.AgentResponseCreatedPayload
	if err := respEvent.DecodePayload(&resp); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	if len(resp.Content) == 0 || resp.Content[0].Text != "time/date ready" {
		t.Fatalf("unexpected response content: %+v", resp.Content)
	}

	if callCounts["get_time"] != 1 || callCounts["get_date"] != 1 {
		t.Fatalf("expected one call per tool, got %+v", callCounts)
	}
	if len(provider.requests) != 2 {
		t.Fatalf("expected two model calls, got %d", len(provider.requests))
	}
	followup := provider.requests[1].Messages[len(provider.requests[1].Messages)-1]
	if followup.Role != model.RoleUser || len(followup.Blocks) != 2 {
		t.Fatalf("expected a single user message with two tool results, got %+v", followup)
	}
}

func TestServiceProcessEvent_ToolLoopMaxIterationsReached(t *testing.T) {
	var callCount int
	server := newToolHostServer(t, []types.ToolDescriptor{
		{Name: "loop_tool", Description: "Loop", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}, func(w http.ResponseWriter, req types.ToolCallRequest) {
		callCount++
		_ = json.NewEncoder(w).Encode(types.ToolCallResponse{
			Version:  types.VersionV1,
			CallID:   req.CallID,
			ToolName: req.ToolName,
			Status:   types.ToolCallStatusOK,
			Result:   map[string]any{},
		})
	})
	defer server.Close()

	toolClient := toolclient.New(log.New(io.Discard, "", 0), []toolclient.HostConfig{{Name: "tools", BaseURL: server.URL}})
	if err := toolClient.Discover(context.Background()); err != nil {
		t.Fatalf("discover tools: %v", err)
	}

	provider := &mockProvider{
		response: model.CompletionResponse{
			Blocks: []model.ContentBlock{
				{Type: "tool_use", ID: "toolu_loop", Name: "loop_tool", Input: json.RawMessage(`{}`)},
			},
			StopReason: "tool_use",
		},
	}

	svc, collector, store := newTestServiceWithToolClient(t, map[string]model.Provider{"anthropic": provider}, toolClient)
	inbound := inboundEvent(t, "evt_tool_loop", "trace_tool_loop", "tenant_1", "session_1", "anthropic", "loop")
	svc.processEvent(context.Background(), inbound)

	seen := collectEventTypes(t, collector.events, 2)
	if !seen[types.EventTypeAgentTurnStarted] || !seen[types.EventTypeAgentTurnFailed] {
		t.Fatalf("expected started and failed events, got %+v", seen)
	}

	turns, err := store.GetTurns(context.Background(), "tenant_1", "session_1", 10)
	if err != nil {
		t.Fatalf("get turns: %v", err)
	}
	if len(turns) != 1 || turns[0].Status != session.TurnStatusFailed {
		t.Fatalf("expected failed turn, got %+v", turns)
	}
	if len(provider.requests) != maxToolRounds+1 {
		t.Fatalf("expected %d model calls, got %d", maxToolRounds+1, len(provider.requests))
	}
	if callCount != maxToolRounds {
		t.Fatalf("expected %d tool calls, got %d", maxToolRounds, callCount)
	}
}

func TestServiceProcessEvent_ToolErrorStatusFeedsBackToLLM(t *testing.T) {
	server := newToolHostServer(t, []types.ToolDescriptor{
		{Name: "memory.query", Description: "query", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}, func(w http.ResponseWriter, req types.ToolCallRequest) {
		_ = json.NewEncoder(w).Encode(types.ToolCallResponse{
			Version:  types.VersionV1,
			CallID:   req.CallID,
			ToolName: req.ToolName,
			Status:   types.ToolCallStatusError,
			Error: &types.ToolError{
				Code:    types.ToolErrorCodeInvalidArgs,
				Message: "missing query",
			},
		})
	})
	defer server.Close()

	toolClient := toolclient.New(log.New(io.Discard, "", 0), []toolclient.HostConfig{{Name: "tools", BaseURL: server.URL}})
	if err := toolClient.Discover(context.Background()); err != nil {
		t.Fatalf("discover tools: %v", err)
	}

	provider := &mockProvider{
		responses: []model.CompletionResponse{
			{
				Blocks: []model.ContentBlock{
					{Type: "tool_use", ID: "toolu_err", Name: "memory.query", Input: json.RawMessage(`{}`)},
				},
				StopReason: "tool_use",
			},
			{Content: "I couldn't run memory.query because args were invalid."},
		},
	}

	svc, collector, _ := newTestServiceWithToolClient(t, map[string]model.Provider{"anthropic": provider}, toolClient)
	inbound := inboundEvent(t, "evt_tool_err", "trace_tool_err", "tenant_1", "session_1", "anthropic", "search memory")
	svc.processEvent(context.Background(), inbound)

	seen := collectEventSet(t, collector.events, 3)
	respEvent, ok := seen[types.EventTypeAgentResponseCreated]
	if !ok {
		t.Fatalf("expected %s", types.EventTypeAgentResponseCreated)
	}
	var resp types.AgentResponseCreatedPayload
	if err := respEvent.DecodePayload(&resp); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	if len(resp.Content) == 0 || resp.Content[0].Text == "" {
		t.Fatalf("unexpected response content: %+v", resp.Content)
	}

	if len(provider.requests) != 2 {
		t.Fatalf("expected two model calls, got %d", len(provider.requests))
	}
	feedbackMessage := provider.requests[1].Messages[len(provider.requests[1].Messages)-1]
	if feedbackMessage.Role != model.RoleUser || len(feedbackMessage.Blocks) != 1 {
		t.Fatalf("unexpected tool feedback message: %+v", feedbackMessage)
	}
	if !feedbackMessage.Blocks[0].IsError {
		t.Fatalf("expected error tool_result block")
	}
	if !strings.Contains(feedbackMessage.Blocks[0].Content, "INVALID_ARGS") {
		t.Fatalf("expected error payload in tool result, got %q", feedbackMessage.Blocks[0].Content)
	}
}

func TestServiceProcessEvent_NoToolClientKeepsCurrentBehavior(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{Content: "plain response"},
	}
	svc, collector, _ := newTestService(t, map[string]model.Provider{"anthropic": provider})
	inbound := inboundEvent(t, "evt_notool", "trace_notool", "tenant_1", "session_1", "anthropic", "hello")
	svc.processEvent(context.Background(), inbound)

	seen := collectEventSet(t, collector.events, 3)
	if _, ok := seen[types.EventTypeAgentResponseCreated]; !ok {
		t.Fatalf("expected %s", types.EventTypeAgentResponseCreated)
	}
	if len(provider.requests) != 1 {
		t.Fatalf("expected one provider request, got %d", len(provider.requests))
	}
	if len(provider.requests[0].Tools) != 0 {
		t.Fatalf("expected no tools in provider request when tool client is nil")
	}
}

func TestServiceProcessEvent_UsesConfiguredAgentProviderAndModel(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{Content: "hello from openai"},
	}
	svc, collector, _ := newTestService(t, map[string]model.Provider{"openai": provider})
	if err := svc.SetAgents([]AgentConfig{
		{
			Name:         "assistant-discord",
			Model:        "openai/gpt-4o-mini",
			Channels:     []string{"discord"},
			Users:        []string{"user-1"},
			WorkspaceDir: "/srv/workspaces/assistant-discord",
		},
	}); err != nil {
		t.Fatalf("set agents: %v", err)
	}

	inbound := inboundEvent(t, "evt_cfg_agent", "trace_cfg_agent", "tenant_1", "session_1", "assistant-discord", "hello")
	inbound.Source.Platform = "discord"
	inbound.Source.ActorID = "user-1"
	svc.processEvent(context.Background(), inbound)

	seen := collectEventSet(t, collector.events, 3)
	respEvent, ok := seen[types.EventTypeAgentResponseCreated]
	if !ok {
		t.Fatalf("expected %s", types.EventTypeAgentResponseCreated)
	}

	var resp types.AgentResponseCreatedPayload
	if err := respEvent.DecodePayload(&resp); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	if resp.Usage == nil {
		t.Fatalf("expected usage payload")
	}
	if resp.Usage.Provider != "openai" {
		t.Fatalf("expected provider openai, got %q", resp.Usage.Provider)
	}
	if _, ok := respEvent.Meta["agent_name"].(string); !ok {
		t.Fatalf("expected agent_name metadata")
	}
	if got, _ := respEvent.Meta["workspace_dir"].(string); got != "/srv/workspaces/assistant-discord" {
		t.Fatalf("unexpected workspace_dir metadata: %q", got)
	}

	if len(provider.requests) != 1 {
		t.Fatalf("expected one provider request, got %d", len(provider.requests))
	}
	if provider.requests[0].Model != "gpt-4o-mini" {
		t.Fatalf("expected configured model gpt-4o-mini, got %q", provider.requests[0].Model)
	}
}

func TestServiceProcessEvent_ConfiguredAgentsSelectByChannel(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{Content: "routed"},
	}
	svc, collector, store := newTestService(t, map[string]model.Provider{"openai": provider})
	if err := svc.SetAgents([]AgentConfig{
		{
			Name:     "discord-assistant",
			Model:    "openai/gpt-4o-mini",
			Channels: []string{"discord:ops-room"},
		},
		{
			Name:     "telegram-assistant",
			Model:    "openai/gpt-4o-mini",
			Channels: []string{"telegram"},
		},
	}); err != nil {
		t.Fatalf("set agents: %v", err)
	}

	inbound := inboundEvent(t, "evt_route", "trace_route", "tenant_1", "session_1", "assistant", "hello")
	inbound.Source.Platform = "discord"
	inbound.Source.ChannelID = "ops-room"
	svc.processEvent(context.Background(), inbound)

	_ = collectEventSet(t, collector.events, 3)

	sessionRec, err := store.GetSession(context.Background(), "tenant_1", "session_1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sessionRec.AgentID != "discord-assistant" {
		t.Fatalf("expected routed session agent_id discord-assistant, got %q", sessionRec.AgentID)
	}
}

func TestServiceProcessEvent_ConfiguredAgentsFailWhenNoChannelMatch(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{Content: "nope"},
	}
	svc, collector, _ := newTestService(t, map[string]model.Provider{"openai": provider})
	if err := svc.SetAgents([]AgentConfig{
		{
			Name:     "telegram-assistant",
			Model:    "openai/gpt-4o-mini",
			Channels: []string{"telegram"},
		},
	}); err != nil {
		t.Fatalf("set agents: %v", err)
	}

	inbound := inboundEvent(t, "evt_nomatch", "trace_nomatch", "tenant_1", "session_1", "assistant", "hello")
	inbound.Source.Platform = "discord"
	svc.processEvent(context.Background(), inbound)

	seen := collectEventTypes(t, collector.events, 1)
	if !seen[types.EventTypeAgentTurnFailed] {
		t.Fatalf("expected %s", types.EventTypeAgentTurnFailed)
	}
	if len(provider.requests) != 0 {
		t.Fatalf("expected no provider request on agent mismatch")
	}
}

func TestServiceProcessEvent_ConfiguredAgentsEnforceUserAllowlist(t *testing.T) {
	provider := &mockProvider{
		response: model.CompletionResponse{Content: "restricted"},
	}
	svc, collector, _ := newTestService(t, map[string]model.Provider{"openai": provider})
	if err := svc.SetAgents([]AgentConfig{
		{
			Name:  "discord-assistant",
			Model: "openai/gpt-4o-mini",
			Users: []string{"allowed-user"},
		},
	}); err != nil {
		t.Fatalf("set agents: %v", err)
	}

	inbound := inboundEvent(t, "evt_user", "trace_user", "tenant_1", "session_1", "discord-assistant", "hello")
	inbound.Source.Platform = "discord"
	inbound.Source.ActorID = "blocked-user"
	svc.processEvent(context.Background(), inbound)

	seen := collectEventTypes(t, collector.events, 1)
	if !seen[types.EventTypeAgentTurnFailed] {
		t.Fatalf("expected %s", types.EventTypeAgentTurnFailed)
	}
	if len(provider.requests) != 0 {
		t.Fatalf("expected no provider request for blocked user")
	}
}

func newTestService(t *testing.T, providers map[string]model.Provider) (*Service, *collectorSubscriber, *session.MemoryStore) {
	return newTestServiceWithToolClient(t, providers, nil)
}

func newTestServiceWithToolClient(t *testing.T, providers map[string]model.Provider, toolClient *toolclient.Client) (*Service, *collectorSubscriber, *session.MemoryStore) {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	collector := &collectorSubscriber{events: make(chan types.EventEnvelope, 8)}
	d := dispatch.New(logger, []subscribers.Subscriber{collector})
	store := session.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })

	registry := model.NewRegistry()
	for name, provider := range providers {
		registry.Register(name, provider)
	}

	return NewService(logger, d, store, registry, toolClient), collector, store
}

func collectEventSet(t *testing.T, events <-chan types.EventEnvelope, count int) map[types.EventType]types.EventEnvelope {
	t.Helper()
	seen := make(map[types.EventType]types.EventEnvelope, count)
	deadline := time.After(2 * time.Second)
	for len(seen) < count {
		select {
		case event := <-events:
			seen[event.EventType] = event
		case <-deadline:
			t.Fatalf("timed out waiting for events; got=%d want=%d", len(seen), count)
		}
	}
	return seen
}

func collectEventTypes(t *testing.T, events <-chan types.EventEnvelope, count int) map[types.EventType]bool {
	t.Helper()
	seen := make(map[types.EventType]bool, count)
	deadline := time.After(2 * time.Second)
	for len(seen) < count {
		select {
		case event := <-events:
			seen[event.EventType] = true
		case <-deadline:
			t.Fatalf("timed out waiting for events; got=%d want=%d", len(seen), count)
		}
	}
	return seen
}

func inboundEvent(t *testing.T, eventID, traceID, tenantID, sessionID, agentID, text string) types.EventEnvelope {
	t.Helper()
	payload, err := json.Marshal(types.ChannelMessageReceivedPayload{Text: text})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    eventID,
		TraceID:    traceID,
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   tenantID,
		Source: types.EventSource{
			ComponentType: types.ComponentTypeListener,
			ComponentID:   "listener_1",
		},
		Routing: types.EventRouting{
			AgentID:   agentID,
			SessionID: sessionID,
		},
		Payload: payload,
	}
}

func seedCompletedTurn(t *testing.T, store *session.MemoryStore, inbound types.EventEnvelope, responseText string) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.EnsureSession(ctx, inbound); err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	turn, err := store.StartTurn(ctx, inbound)
	if err != nil {
		t.Fatalf("start turn: %v", err)
	}
	responsePayload, err := json.Marshal(types.AgentResponseCreatedPayload{
		ResponseID: "resp_" + turn.TurnID,
		Content: []types.AgentResponseContent{
			{
				Type: types.AgentResponseContentTypeText,
				Text: responseText,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal response payload: %v", err)
	}
	response := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt_resp_" + turn.TurnID,
		TraceID:    inbound.TraceID,
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeAgentResponseCreated,
		TenantID:   inbound.TenantID,
		Source: types.EventSource{
			ComponentType: types.ComponentTypeGateway,
			ComponentID:   "gateway-core",
		},
		Routing: inbound.Routing,
		Payload: responsePayload,
	}
	if err := store.CompleteTurn(ctx, turn.TurnID, &response); err != nil {
		t.Fatalf("complete turn: %v", err)
	}
}

func newToolHostServer(t *testing.T, tools []types.ToolDescriptor, onCall func(http.ResponseWriter, types.ToolCallRequest)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tools":
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(types.ToolDiscoveryResponse{
				Version: types.VersionV1,
				Service: "test-tool-host",
				Tools:   tools,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tools/call":
			if onCall == nil {
				t.Fatalf("unexpected tool call request")
			}
			var req types.ToolCallRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode tool call request: %v", err)
			}
			onCall(w, req)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}
