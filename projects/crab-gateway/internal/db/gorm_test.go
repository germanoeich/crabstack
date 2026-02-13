package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenGormSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.db")
	db, err := OpenGorm("sqlite", path)
	if err != nil {
		t.Fatalf("open gorm sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
}

func TestOpenGormInvalidDriver(t *testing.T) {
	if _, err := OpenGorm("invalid", "x"); err == nil {
		t.Fatalf("expected invalid driver error")
	}
}

func TestOpenGormSQLiteCreatesParentDirectory(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "nested", "path", "gateway.db")

	db, err := OpenGorm("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open gorm sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	if _, err := os.Stat(filepath.Dir(dbPath)); err != nil {
		t.Fatalf("expected parent dir to be created: %v", err)
	}
}
