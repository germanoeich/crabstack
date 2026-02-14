package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"reflect"
	"testing"
	"time"

	"crabstack.local/lib/types"
	"crabstack.local/projects/crab-gateway/internal/dispatch"
	"crabstack.local/projects/crab-gateway/internal/model"
	"crabstack.local/projects/crab-gateway/internal/session"
	"crabstack.local/projects/crab-gateway/internal/subscribers"
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
	response model.CompletionResponse
	err      error
	requests []model.CompletionRequest
}

func (m *mockProvider) Complete(_ context.Context, req model.CompletionRequest) (model.CompletionResponse, error) {
	m.requests = append(m.requests, req)
	if m.err != nil {
		return model.CompletionResponse{}, m.err
	}
	resp := m.response
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

func newTestService(t *testing.T, providers map[string]model.Provider) (*Service, *collectorSubscriber, *session.MemoryStore) {
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

	return NewService(logger, d, store, registry), collector, store
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
