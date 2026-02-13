package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"crabstack.local/lib/types"
	"crabstack.local/projects/crab-gateway/internal/dispatch"
	"crabstack.local/projects/crab-gateway/internal/ids"
	"crabstack.local/projects/crab-gateway/internal/session"
)

type Service struct {
	logger       *log.Logger
	dispatcher   *dispatch.Dispatcher
	scheduler    *session.Scheduler
	sessionStore session.Store
}

func NewService(logger *log.Logger, dispatcher *dispatch.Dispatcher, sessionStore session.Store) *Service {
	svc := &Service{
		logger:       logger,
		dispatcher:   dispatcher,
		sessionStore: sessionStore,
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

	responseEvent, err := s.handleInboundEvent(ctx, inbound)
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

func (s *Service) handleInboundEvent(ctx context.Context, inbound types.EventEnvelope) (*types.EventEnvelope, error) {
	switch inbound.EventType {
	case types.EventTypeChannelMessageReceived:
		return s.handleChannelMessage(ctx, inbound)
	default:
		return nil, nil
	}
}

func (s *Service) handleChannelMessage(_ context.Context, inbound types.EventEnvelope) (*types.EventEnvelope, error) {
	var payload types.ChannelMessageReceivedPayload
	if err := inbound.DecodePayload(&payload); err != nil {
		return nil, fmt.Errorf("decode channel message payload: %w", err)
	}

	response := types.AgentResponseCreatedPayload{
		ResponseID: ids.New(),
		Content: []types.AgentResponseContent{
			{
				Type: types.AgentResponseContentTypeText,
				Text: payload.Text,
			},
		},
		Actions: []types.AgentResponseAction{
			{
				Kind: types.AgentResponseActionKindSendMessage,
				Args: map[string]any{"text": payload.Text},
			},
		},
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
