package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"crabstack.local/projects/crab-gateway/internal/dispatch"
	"crabstack.local/projects/crab-gateway/internal/ids"
	"crabstack.local/projects/crab-gateway/internal/model"
	"crabstack.local/projects/crab-gateway/internal/session"
	"crabstack.local/projects/crab-sdk/types"
)

const (
	defaultProviderName = "anthropic"
	defaultModelName    = "claude-sonnet-4-20250514"
	defaultMaxTokens    = 4096
	systemPrompt        = "You are a helpful assistant."
	historyTurnLimit    = 50
)

type Service struct {
	logger       *log.Logger
	dispatcher   *dispatch.Dispatcher
	scheduler    *session.Scheduler
	sessionStore session.Store
	models       *model.Registry
}

func NewService(logger *log.Logger, dispatcher *dispatch.Dispatcher, sessionStore session.Store, models *model.Registry) *Service {
	if models == nil {
		models = model.NewRegistry()
	}
	svc := &Service{
		logger:       logger,
		dispatcher:   dispatcher,
		sessionStore: sessionStore,
		models:       models,
	}
	svc.scheduler = session.NewScheduler(logger, 256, svc.processEvent)
	return svc
}

func (s *Service) AcceptEvent(ctx context.Context, event types.EventEnvelope) error {
	if err := s.scheduler.Enqueue(ctx, event); err != nil {
		return err
	}
	return nil
}

func (s *Service) processEvent(ctx context.Context, inbound types.EventEnvelope) {
	rec, err := s.sessionStore.EnsureSession(ctx, inbound)
	if err != nil {
		s.dispatcher.Dispatch(ctx, s.lifecycleEvent(inbound, "", types.EventTypeAgentTurnFailed, map[string]any{
			"source_event_id": inbound.EventID,
			"error":           fmt.Sprintf("ensure session failed: %v", err),
		}))
		s.logger.Printf("session ensure failed event_id=%s session_id=%s err=%v", inbound.EventID, inbound.Routing.SessionID, err)
		return
	}

	turn, err := s.sessionStore.StartTurn(ctx, inbound)
	if err != nil {
		s.dispatcher.Dispatch(ctx, s.lifecycleEvent(inbound, "", types.EventTypeAgentTurnFailed, map[string]any{
			"source_event_id": inbound.EventID,
			"error":           fmt.Sprintf("start turn failed: %v", err),
		}))
		s.logger.Printf("turn start failed event_id=%s session_id=%s err=%v", inbound.EventID, inbound.Routing.SessionID, err)
		return
	}

	s.logger.Printf("turn start event_id=%s turn_id=%s session_id=%s", inbound.EventID, turn.TurnID, inbound.Routing.SessionID)
	s.dispatcher.Dispatch(ctx, s.lifecycleEvent(inbound, turn.TurnID, types.EventTypeAgentTurnStarted, map[string]any{
		"source_event_id":   inbound.EventID,
		"source_event_type": inbound.EventType,
		"turn_id":           turn.TurnID,
		"session_id":        rec.SessionID,
	}))

	responseEvent, err := s.handleInboundEvent(ctx, inbound, rec.AgentID)
	if err != nil {
		_ = s.sessionStore.FailTurn(ctx, turn.TurnID, err.Error())
		s.dispatcher.Dispatch(ctx, s.lifecycleEvent(inbound, turn.TurnID, types.EventTypeAgentTurnFailed, map[string]any{
			"source_event_id": inbound.EventID,
			"turn_id":         turn.TurnID,
			"error":           err.Error(),
		}))
		s.logger.Printf("turn failed event_id=%s turn_id=%s session_id=%s err=%v", inbound.EventID, turn.TurnID, inbound.Routing.SessionID, err)
		return
	}

	if err := s.sessionStore.CompleteTurn(ctx, turn.TurnID, responseEvent); err != nil {
		_ = s.sessionStore.FailTurn(ctx, turn.TurnID, fmt.Sprintf("complete turn persist failed: %v", err))
		s.dispatcher.Dispatch(ctx, s.lifecycleEvent(inbound, turn.TurnID, types.EventTypeAgentTurnFailed, map[string]any{
			"source_event_id": inbound.EventID,
			"turn_id":         turn.TurnID,
			"error":           fmt.Sprintf("complete turn persist failed: %v", err),
		}))
		s.logger.Printf("turn completion persist failed event_id=%s turn_id=%s session_id=%s err=%v", inbound.EventID, turn.TurnID, inbound.Routing.SessionID, err)
		return
	}

	if responseEvent != nil {
		s.dispatcher.Dispatch(ctx, *responseEvent)
	}

	s.dispatcher.Dispatch(ctx, s.lifecycleEvent(inbound, turn.TurnID, types.EventTypeAgentTurnCompleted, map[string]any{
		"source_event_id": inbound.EventID,
		"turn_id":         turn.TurnID,
	}))
	s.logger.Printf("turn complete event_id=%s turn_id=%s session_id=%s", inbound.EventID, turn.TurnID, inbound.Routing.SessionID)
}

func (s *Service) handleInboundEvent(ctx context.Context, inbound types.EventEnvelope, sessionAgentID string) (*types.EventEnvelope, error) {
	switch inbound.EventType {
	case types.EventTypeChannelMessageReceived:
		return s.handleChannelMessage(ctx, inbound, sessionAgentID)
	default:
		return nil, nil
	}
}

func (s *Service) handleChannelMessage(ctx context.Context, inbound types.EventEnvelope, sessionAgentID string) (*types.EventEnvelope, error) {
	turns, err := s.sessionStore.GetTurns(ctx, inbound.TenantID, inbound.Routing.SessionID, 0)
	if err != nil {
		return nil, fmt.Errorf("get session turns: %w", err)
	}

	history, err := buildConversationHistory(turns)
	if err != nil {
		return nil, fmt.Errorf("build conversation history: %w", err)
	}

	providerName, provider, err := s.resolveProvider(sessionAgentID)
	if err != nil {
		return nil, err
	}

	completion, err := provider.Complete(ctx, model.CompletionRequest{
		Model:        defaultModelName,
		Messages:     history,
		MaxTokens:    defaultMaxTokens,
		SystemPrompt: systemPrompt,
	})
	if err != nil {
		return nil, fmt.Errorf("complete with provider %q: %w", providerName, err)
	}

	responseText := strings.TrimSpace(completion.Content)
	if responseText == "" {
		return nil, fmt.Errorf("provider %q returned empty response", providerName)
	}

	response := types.AgentResponseCreatedPayload{
		ResponseID: ids.New(),
		Content: []types.AgentResponseContent{
			{
				Type: types.AgentResponseContentTypeText,
				Text: responseText,
			},
		},
		Actions: []types.AgentResponseAction{
			{
				Kind: types.AgentResponseActionKindSendMessage,
				Args: map[string]any{"text": responseText},
			},
		},
	}
	response.Usage = &types.Usage{
		InputTokens:  completion.Usage.InputTokens,
		OutputTokens: completion.Usage.OutputTokens,
		Model:        completion.Model,
		Provider:     providerName,
	}

	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("marshal response payload: %w", err)
	}

	event := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    ids.New(),
		TraceID:    inbound.TraceID,
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeAgentResponseCreated,
		TenantID:   inbound.TenantID,
		Source: types.EventSource{
			ComponentType: types.ComponentTypeGateway,
			ComponentID:   "gateway-core",
			Transport:     types.TransportTypeInternal,
		},
		Routing: inbound.Routing,
		Payload: data,
		Meta: map[string]any{
			"source_event_id": inbound.EventID,
		},
	}

	return &event, nil
}

func (s *Service) resolveProvider(agentID string) (string, model.Provider, error) {
	providerName := strings.TrimSpace(agentID)
	if providerName == "" {
		providerName = defaultProviderName
	}

	if provider, ok := s.models.Get(providerName); ok {
		return providerName, provider, nil
	}
	if !strings.EqualFold(providerName, defaultProviderName) {
		if provider, ok := s.models.Get(defaultProviderName); ok {
			return defaultProviderName, provider, nil
		}
	}
	return "", nil, fmt.Errorf("model provider %q is not registered", providerName)
}

func buildConversationHistory(turns []session.TurnRecord) ([]model.Message, error) {
	if len(turns) > historyTurnLimit {
		turns = turns[len(turns)-historyTurnLimit:]
	}

	messages := make([]model.Message, 0, len(turns)*2)
	for _, turn := range turns {
		inbound, err := decodeEvent(turn.InboundEventJSON)
		if err != nil {
			return nil, fmt.Errorf("decode inbound event for turn %s: %w", turn.TurnID, err)
		}
		if inbound.EventType == types.EventTypeChannelMessageReceived {
			var payload types.ChannelMessageReceivedPayload
			if err := inbound.DecodePayload(&payload); err != nil {
				return nil, fmt.Errorf("decode inbound channel message payload for turn %s: %w", turn.TurnID, err)
			}
			if strings.TrimSpace(payload.Text) != "" {
				messages = append(messages, model.Message{Role: model.RoleUser, Content: payload.Text})
			}
		}

		if len(turn.ResponseEventJSON) == 0 {
			continue
		}
		responseEvent, err := decodeEvent(turn.ResponseEventJSON)
		if err != nil {
			return nil, fmt.Errorf("decode response event for turn %s: %w", turn.TurnID, err)
		}
		if responseEvent.EventType != types.EventTypeAgentResponseCreated {
			continue
		}

		var payload types.AgentResponseCreatedPayload
		if err := responseEvent.DecodePayload(&payload); err != nil {
			return nil, fmt.Errorf("decode response payload for turn %s: %w", turn.TurnID, err)
		}
		text := assistantText(payload)
		if text == "" {
			continue
		}
		messages = append(messages, model.Message{Role: model.RoleAssistant, Content: text})
	}

	return messages, nil
}

func decodeEvent(raw []byte) (types.EventEnvelope, error) {
	var event types.EventEnvelope
	if err := json.Unmarshal(raw, &event); err != nil {
		return types.EventEnvelope{}, err
	}
	return event, nil
}

func assistantText(payload types.AgentResponseCreatedPayload) string {
	parts := make([]string, 0, len(payload.Content))
	for _, content := range payload.Content {
		if content.Type != types.AgentResponseContentTypeText {
			continue
		}
		if strings.TrimSpace(content.Text) == "" {
			continue
		}
		parts = append(parts, content.Text)
	}
	if len(parts) > 0 {
		return strings.Join(parts, "\n")
	}

	for _, action := range payload.Actions {
		if action.Kind != types.AgentResponseActionKindSendMessage {
			continue
		}
		text, _ := action.Args["text"].(string)
		if strings.TrimSpace(text) == "" {
			continue
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, "\n")
}

func (s *Service) lifecycleEvent(inbound types.EventEnvelope, turnID string, eventType types.EventType, payload map[string]any) types.EventEnvelope {
	if turnID != "" {
		payload["turn_id"] = turnID
	}
	data, _ := json.Marshal(payload)
	return types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    ids.New(),
		TraceID:    inbound.TraceID,
		OccurredAt: time.Now().UTC(),
		EventType:  eventType,
		TenantID:   inbound.TenantID,
		Source: types.EventSource{
			ComponentType: types.ComponentTypeGateway,
			ComponentID:   "gateway-core",
			Transport:     types.TransportTypeInternal,
		},
		Routing: inbound.Routing,
		Payload: data,
	}
}
