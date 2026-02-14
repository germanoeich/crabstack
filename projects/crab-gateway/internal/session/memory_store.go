package session

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"crabstack.local/projects/crab-gateway/internal/ids"
	"crabstack.local/projects/crab-sdk/types"
)

type MemoryStore struct {
	mu             sync.Mutex
	sessions       map[string]SessionRecord
	turnsBySession map[string][]TurnRecord
	turnIndex      map[string]turnLocation
	closed         bool
}

type turnLocation struct {
	key string
	idx int
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions:       make(map[string]SessionRecord),
		turnsBySession: make(map[string][]TurnRecord),
		turnIndex:      make(map[string]turnLocation),
	}
}

func (s *MemoryStore) EnsureSession(_ context.Context, event types.EventEnvelope) (SessionRecord, error) {
	now := time.Now().UTC()
	incoming := sessionFromEvent(event, now)
	key := sessionKey(incoming.TenantID, incoming.SessionID)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return SessionRecord{}, fmt.Errorf("memory store is closed")
	}

	if existing, ok := s.sessions[key]; ok {
		updated := mergeSession(existing, incoming, now)
		s.sessions[key] = updated
		return updated, nil
	}

	s.sessions[key] = incoming
	return incoming, nil
}

func (s *MemoryStore) GetSession(_ context.Context, tenantID, sessionID string) (SessionRecord, error) {
	if err := validateSessionKeyFields(tenantID, sessionID); err != nil {
		return SessionRecord{}, err
	}

	key := sessionKey(tenantID, sessionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return SessionRecord{}, fmt.Errorf("memory store is closed")
	}

	rec, ok := s.sessions[key]
	if !ok {
		return SessionRecord{}, ErrNotFound
	}
	return rec, nil
}

func (s *MemoryStore) StartTurn(_ context.Context, event types.EventEnvelope) (TurnRecord, error) {
	now := time.Now().UTC()
	key := sessionKey(event.TenantID, event.Routing.SessionID)

	inboundJSON, err := json.Marshal(event)
	if err != nil {
		return TurnRecord{}, fmt.Errorf("marshal inbound event: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return TurnRecord{}, fmt.Errorf("memory store is closed")
	}

	sequence := int64(len(s.turnsBySession[key]) + 1)
	turn := TurnRecord{
		TurnID:           ids.New(),
		TenantID:         event.TenantID,
		SessionID:        event.Routing.SessionID,
		AgentID:          event.Routing.AgentID,
		Sequence:         sequence,
		TraceID:          event.TraceID,
		SourceEventID:    event.EventID,
		SourceEventType:  string(event.EventType),
		InboundEventJSON: inboundJSON,
		Status:           TurnStatusInProgress,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	s.turnsBySession[key] = append(s.turnsBySession[key], turn)
	idx := len(s.turnsBySession[key]) - 1
	s.turnIndex[turn.TurnID] = turnLocation{key: key, idx: idx}
	return turn, nil
}

func (s *MemoryStore) CompleteTurn(_ context.Context, turnID string, response *types.EventEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("memory store is closed")
	}

	loc, ok := s.turnIndex[turnID]
	if !ok {
		return ErrNotFound
	}
	turns := s.turnsBySession[loc.key]
	turn := turns[loc.idx]

	turn.Status = TurnStatusCompleted
	turn.CompletedAt = time.Now().UTC()
	turn.UpdatedAt = turn.CompletedAt
	if response != nil {
		encoded, err := json.Marshal(response)
		if err != nil {
			return fmt.Errorf("marshal response event: %w", err)
		}
		turn.ResponseEventID = response.EventID
		turn.ResponseEventJSON = encoded
	}

	turns[loc.idx] = turn
	s.turnsBySession[loc.key] = turns
	return nil
}

func (s *MemoryStore) FailTurn(_ context.Context, turnID, failure string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("memory store is closed")
	}

	loc, ok := s.turnIndex[turnID]
	if !ok {
		return ErrNotFound
	}
	turns := s.turnsBySession[loc.key]
	turn := turns[loc.idx]
	turn.Status = TurnStatusFailed
	turn.Error = failure
	turn.CompletedAt = time.Now().UTC()
	turn.UpdatedAt = turn.CompletedAt
	turns[loc.idx] = turn
	s.turnsBySession[loc.key] = turns
	return nil
}

func (s *MemoryStore) GetTurns(_ context.Context, tenantID, sessionID string, limit int) ([]TurnRecord, error) {
	if err := validateSessionKeyFields(tenantID, sessionID); err != nil {
		return nil, err
	}

	key := sessionKey(tenantID, sessionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("memory store is closed")
	}

	turns, ok := s.turnsBySession[key]
	if !ok {
		return []TurnRecord{}, nil
	}
	if limit > 0 && limit < len(turns) {
		turns = turns[len(turns)-limit:]
	}

	out := make([]TurnRecord, len(turns))
	copy(out, turns)
	return out, nil
}

func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
