package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"pinchy.local/lib/types"
	dbpkg "pinchy.local/projects/gateway/internal/db"
	"pinchy.local/projects/gateway/internal/ids"
)

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(driver, dsn string) (*GormStore, error) {
	gormDB, err := dbpkg.OpenGorm(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open gorm store: %w", err)
	}

	store := &GormStore{db: gormDB}
	if err := store.migrate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *GormStore) migrate() error {
	return s.db.AutoMigrate(&sessionRow{}, &turnRow{})
}

func (s *GormStore) EnsureSession(ctx context.Context, event types.EventEnvelope) (SessionRecord, error) {
	now := time.Now().UTC()
	incoming := sessionFromEvent(event, now)

	var current sessionRow
	err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND session_id = ?", incoming.TenantID, incoming.SessionID).
		Take(&current).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			row := sessionRowFromRecord(incoming)
			if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
				return SessionRecord{}, fmt.Errorf("create session: %w", err)
			}
			return incoming, nil
		}
		return SessionRecord{}, fmt.Errorf("get session: %w", err)
	}

	merged := mergeSession(current.toRecord(), incoming, now)
	row := sessionRowFromRecord(merged)
	if err := s.db.WithContext(ctx).Save(&row).Error; err != nil {
		return SessionRecord{}, fmt.Errorf("update session: %w", err)
	}
	return merged, nil
}

func (s *GormStore) GetSession(ctx context.Context, tenantID, sessionID string) (SessionRecord, error) {
	if err := validateSessionKeyFields(tenantID, sessionID); err != nil {
		return SessionRecord{}, err
	}

	var row sessionRow
	err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND session_id = ?", tenantID, sessionID).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return SessionRecord{}, ErrNotFound
		}
		return SessionRecord{}, fmt.Errorf("get session: %w", err)
	}
	return row.toRecord(), nil
}

func (s *GormStore) StartTurn(ctx context.Context, event types.EventEnvelope) (TurnRecord, error) {
	var out TurnRecord
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var maxSeq int64
		if err := tx.Model(&turnRow{}).
			Where("tenant_id = ? AND session_id = ?", event.TenantID, event.Routing.SessionID).
			Select("COALESCE(MAX(sequence), 0)").
			Scan(&maxSeq).Error; err != nil {
			return fmt.Errorf("sequence lookup: %w", err)
		}

		inboundJSON, err := marshalJSON(event)
		if err != nil {
			return fmt.Errorf("marshal inbound event: %w", err)
		}

		now := time.Now().UTC()
		row := turnRow{
			TurnID:           ids.New(),
			TenantID:         event.TenantID,
			SessionID:        event.Routing.SessionID,
			AgentID:          event.Routing.AgentID,
			Sequence:         maxSeq + 1,
			TraceID:          event.TraceID,
			SourceEventID:    event.EventID,
			SourceEventType:  string(event.EventType),
			InboundEventJSON: string(inboundJSON),
			Status:           string(TurnStatusInProgress),
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("create turn: %w", err)
		}
		out = row.toRecord()
		return nil
	})
	if err != nil {
		return TurnRecord{}, err
	}
	return out, nil
}

func (s *GormStore) CompleteTurn(ctx context.Context, turnID string, response *types.EventEnvelope) error {
	now := time.Now().UTC()
	updates := map[string]any{
		"status":       string(TurnStatusCompleted),
		"completed_at": &now,
		"updated_at":   now,
	}
	if response != nil {
		encoded, err := marshalJSON(response)
		if err != nil {
			return fmt.Errorf("marshal response event: %w", err)
		}
		updates["response_event_id"] = response.EventID
		updates["response_event_json"] = string(encoded)
	}

	res := s.db.WithContext(ctx).Model(&turnRow{}).Where("turn_id = ?", turnID).Updates(updates)
	if res.Error != nil {
		return fmt.Errorf("complete turn: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *GormStore) FailTurn(ctx context.Context, turnID, failure string) error {
	now := time.Now().UTC()
	res := s.db.WithContext(ctx).Model(&turnRow{}).Where("turn_id = ?", turnID).Updates(map[string]any{
		"status":       string(TurnStatusFailed),
		"error":        failure,
		"completed_at": &now,
		"updated_at":   now,
	})
	if res.Error != nil {
		return fmt.Errorf("fail turn: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *GormStore) GetTurns(ctx context.Context, tenantID, sessionID string, limit int) ([]TurnRecord, error) {
	if err := validateSessionKeyFields(tenantID, sessionID); err != nil {
		return nil, err
	}

	query := s.db.WithContext(ctx).
		Model(&turnRow{}).
		Where("tenant_id = ? AND session_id = ?", tenantID, sessionID).
		Order("sequence ASC")
	if limit > 0 {
		query = query.Limit(limit)
	}

	var rows []turnRow
	if err := query.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("get turns: %w", err)
	}
	out := make([]TurnRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.toRecord())
	}
	return out, nil
}

func (s *GormStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("get sql db: %w", err)
	}
	return sqlDB.Close()
}

func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}
