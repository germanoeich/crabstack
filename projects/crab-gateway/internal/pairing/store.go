package pairing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"crabstack.local/lib/types"
	dbpkg "crabstack.local/projects/crab-gateway/internal/db"
)

type PeerStore interface {
	UpsertPeer(context.Context, types.PairedPeerRecord) error
	GetPeerByEndpoint(context.Context, string) (types.PairedPeerRecord, error)
	UpdatePeerStatus(context.Context, string, types.PairedPeerStatus, time.Time) error
	Close() error
}

type GormPeerStore struct {
	db *gorm.DB
}

func NewGormPeerStore(driver, dsn string) (*GormPeerStore, error) {
	db, err := dbpkg.OpenGorm(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open peer store: %w", err)
	}
	store := &GormPeerStore{db: db}
	if err := db.AutoMigrate(&peerRow{}); err != nil {
		return nil, fmt.Errorf("migrate peer store: %w", err)
	}
	return store, nil
}

func (s *GormPeerStore) UpsertPeer(ctx context.Context, rec types.PairedPeerRecord) error {
	if strings.TrimSpace(rec.Endpoint) == "" {
		return fmt.Errorf("endpoint is required")
	}
	if rec.Status == "" {
		rec.Status = types.PairedPeerStatusPending
	}
	if rec.LastSeenAt.IsZero() {
		rec.LastSeenAt = time.Now().UTC()
	}

	row := peerRowFromRecord(rec)
	return s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "endpoint"}},
			DoUpdates: clause.AssignmentColumns([]string{"component_type", "component_id", "public_key_ed25519", "public_key_x25519", "mtls_cert_fingerprint", "paired_at", "last_seen_at", "status", "updated_at"}),
		}).
		Create(&row).Error
}

func (s *GormPeerStore) GetPeerByEndpoint(ctx context.Context, endpoint string) (types.PairedPeerRecord, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return types.PairedPeerRecord{}, fmt.Errorf("endpoint is required")
	}

	var row peerRow
	if err := s.db.WithContext(ctx).Where("endpoint = ?", endpoint).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return types.PairedPeerRecord{}, fmt.Errorf("%w: peer endpoint %s", ErrProtocolViolation, endpoint)
		}
		return types.PairedPeerRecord{}, fmt.Errorf("get peer: %w", err)
	}
	return row.toRecord(), nil
}

func (s *GormPeerStore) UpdatePeerStatus(ctx context.Context, endpoint string, status types.PairedPeerStatus, at time.Time) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	res := s.db.WithContext(ctx).Model(&peerRow{}).Where("endpoint = ?", endpoint).Updates(map[string]any{
		"status":       string(status),
		"last_seen_at": at,
		"paired_at":    at,
		"updated_at":   at,
	})
	if res.Error != nil {
		return fmt.Errorf("update peer status: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: peer endpoint %s", ErrProtocolViolation, endpoint)
	}
	return nil
}

func (s *GormPeerStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("get sql db: %w", err)
	}
	return sqlDB.Close()
}

type peerRow struct {
	Endpoint            string    `gorm:"primaryKey;size:512"`
	ComponentType       string    `gorm:"size:64;not null"`
	ComponentID         string    `gorm:"size:191;not null"`
	PublicKeyEd25519    string    `gorm:"size:256;not null"`
	PublicKeyX25519     string    `gorm:"size:256;not null"`
	MTLSCertFingerprint string    `gorm:"column:mtls_cert_fingerprint;size:256"`
	PairedAt            time.Time `gorm:"not null"`
	LastSeenAt          time.Time `gorm:"not null"`
	Status              string    `gorm:"size:64;not null"`
	CreatedAt           time.Time `gorm:"not null"`
	UpdatedAt           time.Time `gorm:"not null"`
}

func (peerRow) TableName() string {
	return "paired_peers"
}

func peerRowFromRecord(rec types.PairedPeerRecord) peerRow {
	pairedAt := rec.PairedAt
	if pairedAt.IsZero() {
		pairedAt = time.Now().UTC()
	}
	lastSeen := rec.LastSeenAt
	if lastSeen.IsZero() {
		lastSeen = time.Now().UTC()
	}
	return peerRow{
		Endpoint:            rec.Endpoint,
		ComponentType:       string(rec.ComponentType),
		ComponentID:         rec.ComponentID,
		PublicKeyEd25519:    rec.PublicKeyEd25519,
		PublicKeyX25519:     rec.PublicKeyX25519,
		MTLSCertFingerprint: rec.MTLSCertFingerprint,
		PairedAt:            pairedAt,
		LastSeenAt:          lastSeen,
		Status:              string(rec.Status),
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}
}

func (r peerRow) toRecord() types.PairedPeerRecord {
	return types.PairedPeerRecord{
		ComponentType:       types.ComponentType(r.ComponentType),
		ComponentID:         r.ComponentID,
		Endpoint:            r.Endpoint,
		PublicKeyEd25519:    r.PublicKeyEd25519,
		PublicKeyX25519:     r.PublicKeyX25519,
		MTLSCertFingerprint: r.MTLSCertFingerprint,
		PairedAt:            r.PairedAt,
		LastSeenAt:          r.LastSeenAt,
		Status:              types.PairedPeerStatus(r.Status),
	}
}
