package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	EnsureSession(context.Context, types.EventEnvelope) (SessionRecord, error)
	GetSession(context.Context, string, string) (SessionRecord, error)
	StartTurn(context.Context, types.EventEnvelope) (TurnRecord, error)
	CompleteTurn(context.Context, string, *types.EventEnvelope) error
	FailTurn(context.Context, string, string) error
	GetTurns(context.Context, string, string, int) ([]TurnRecord, error)
	Close() error
}

func sessionFromEvent(event types.EventEnvelope, now time.Time) SessionRecord {
	platform := strings.TrimSpace(event.Source.Platform)
	channelID := strings.TrimSpace(event.Source.ChannelID)
	actorID := strings.TrimSpace(event.Source.ActorID)

	if event.Routing.Target != nil {
		if platform == "" {
			platform = strings.TrimSpace(event.Routing.Target.Platform)
		}
		if channelID == "" {
			channelID = strings.TrimSpace(event.Routing.Target.ChannelID)
		}
	}

	return SessionRecord{
		TenantID:            event.TenantID,
		SessionID:           event.Routing.SessionID,
		AgentID:             event.Routing.AgentID,
		Platform:            platform,
		ChannelID:           channelID,
		ActorID:             actorID,
		IsolationKey:        strings.TrimSpace(event.Routing.IsolationKey),
		LastActivePlatform:  platform,
		LastActiveChannelID: channelID,
		LastActiveActorID:   actorID,
		LastActiveAt:        now,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

func mergeSession(existing SessionRecord, incoming SessionRecord, now time.Time) SessionRecord {
	out := existing
	if strings.TrimSpace(incoming.AgentID) != "" {
		out.AgentID = incoming.AgentID
	}
	if strings.TrimSpace(incoming.Platform) != "" {
		out.Platform = incoming.Platform
	}
	if strings.TrimSpace(incoming.ChannelID) != "" {
		out.ChannelID = incoming.ChannelID
	}
	if strings.TrimSpace(incoming.ActorID) != "" {
		out.ActorID = incoming.ActorID
	}
	if strings.TrimSpace(incoming.IsolationKey) != "" {
		out.IsolationKey = incoming.IsolationKey
	}
	if strings.TrimSpace(incoming.LastActivePlatform) != "" {
		out.LastActivePlatform = incoming.LastActivePlatform
	}
	if strings.TrimSpace(incoming.LastActiveChannelID) != "" {
		out.LastActiveChannelID = incoming.LastActiveChannelID
	}
	if strings.TrimSpace(incoming.LastActiveActorID) != "" {
		out.LastActiveActorID = incoming.LastActiveActorID
	}
	if strings.TrimSpace(incoming.LastActiveChannelID) != "" || strings.TrimSpace(incoming.LastActivePlatform) != "" {
		out.LastActiveAt = now
	}
	out.UpdatedAt = now
	return out
}

func sessionKey(tenantID, sessionID string) string {
	return tenantID + ":" + sessionID
}

func validateSessionKeyFields(tenantID, sessionID string) error {
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("session_id is required")
	}
	return nil
}
