package session

import "time"

type sessionRow struct {
	TenantID            string    `gorm:"primaryKey;size:191"`
	SessionID           string    `gorm:"primaryKey;size:191"`
	AgentID             string    `gorm:"size:191;not null"`
	Platform            string    `gorm:"size:191"`
	ChannelID           string    `gorm:"size:191"`
	ActorID             string    `gorm:"size:191"`
	IsolationKey        string    `gorm:"size:191"`
	LastActivePlatform  string    `gorm:"size:191"`
	LastActiveChannelID string    `gorm:"size:191"`
	LastActiveActorID   string    `gorm:"size:191"`
	LastActiveAt        time.Time `gorm:"not null"`
	CreatedAt           time.Time `gorm:"not null"`
	UpdatedAt           time.Time `gorm:"not null"`
}

func (sessionRow) TableName() string {
	return "sessions"
}

func (r sessionRow) toRecord() SessionRecord {
	return SessionRecord{
		TenantID:            r.TenantID,
		SessionID:           r.SessionID,
		AgentID:             r.AgentID,
		Platform:            r.Platform,
		ChannelID:           r.ChannelID,
		ActorID:             r.ActorID,
		IsolationKey:        r.IsolationKey,
		LastActivePlatform:  r.LastActivePlatform,
		LastActiveChannelID: r.LastActiveChannelID,
		LastActiveActorID:   r.LastActiveActorID,
		LastActiveAt:        r.LastActiveAt,
		CreatedAt:           r.CreatedAt,
		UpdatedAt:           r.UpdatedAt,
	}
}

func sessionRowFromRecord(rec SessionRecord) sessionRow {
	return sessionRow{
		TenantID:            rec.TenantID,
		SessionID:           rec.SessionID,
		AgentID:             rec.AgentID,
		Platform:            rec.Platform,
		ChannelID:           rec.ChannelID,
		ActorID:             rec.ActorID,
		IsolationKey:        rec.IsolationKey,
		LastActivePlatform:  rec.LastActivePlatform,
		LastActiveChannelID: rec.LastActiveChannelID,
		LastActiveActorID:   rec.LastActiveActorID,
		LastActiveAt:        rec.LastActiveAt,
		CreatedAt:           rec.CreatedAt,
		UpdatedAt:           rec.UpdatedAt,
	}
}

type turnRow struct {
	TurnID            string     `gorm:"primaryKey;size:64"`
	TenantID          string     `gorm:"size:191;index:idx_turns_session_sequence,priority:1"`
	SessionID         string     `gorm:"size:191;index:idx_turns_session_sequence,priority:2"`
	AgentID           string     `gorm:"size:191;not null"`
	Sequence          int64      `gorm:"not null;uniqueIndex:idx_turns_session_sequence,priority:3"`
	TraceID           string     `gorm:"size:191;not null"`
	SourceEventID     string     `gorm:"size:191;not null"`
	SourceEventType   string     `gorm:"size:191;not null"`
	InboundEventJSON  string     `gorm:"type:text;not null"`
	Status            string     `gorm:"size:64;not null"`
	Error             string     `gorm:"type:text"`
	ResponseEventID   string     `gorm:"size:191"`
	ResponseEventJSON string     `gorm:"type:text"`
	CreatedAt         time.Time  `gorm:"not null"`
	CompletedAt       *time.Time `gorm:"index"`
	UpdatedAt         time.Time  `gorm:"not null"`
}

func (turnRow) TableName() string {
	return "turns"
}

func (r turnRow) toRecord() TurnRecord {
	rec := TurnRecord{
		TurnID:           r.TurnID,
		TenantID:         r.TenantID,
		SessionID:        r.SessionID,
		AgentID:          r.AgentID,
		Sequence:         r.Sequence,
		TraceID:          r.TraceID,
		SourceEventID:    r.SourceEventID,
		SourceEventType:  r.SourceEventType,
		InboundEventJSON: []byte(r.InboundEventJSON),
		Status:           TurnStatus(r.Status),
		Error:            r.Error,
		ResponseEventID:  r.ResponseEventID,
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,
	}
	if r.ResponseEventJSON != "" {
		rec.ResponseEventJSON = []byte(r.ResponseEventJSON)
	}
	if r.CompletedAt != nil {
		rec.CompletedAt = *r.CompletedAt
	}
	return rec
}
