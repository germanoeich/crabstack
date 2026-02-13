package db

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	sqliteDriver "github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func OpenGorm(driver, dsn string) (*gorm.DB, error) {
	driver = strings.ToLower(strings.TrimSpace(driver))
	if driver == "" {
		driver = "sqlite"
	}
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		if driver == "sqlite" {
			dsn = "gateway.db"
		} else {
			return nil, fmt.Errorf("dsn is required for driver %q", driver)
		}
	}

	switch driver {
	case "sqlite":
		if err := ensureSQLiteDirectory(dsn); err != nil {
			return nil, err
		}
		return gorm.Open(sqliteDriver.Open(dsn), &gorm.Config{})
	case "postgres":
		return gorm.Open(postgres.Open(dsn), &gorm.Config{})
	default:
		return nil, fmt.Errorf("unsupported driver %q", driver)
	}
}

func ensureSQLiteDirectory(dsn string) error {
	path, ok := sqliteFilePath(dsn)
	if !ok {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create sqlite db dir: %w", err)
	}
	return nil
}

func sqliteFilePath(dsn string) (string, bool) {
	raw := strings.TrimSpace(dsn)
	if raw == "" {
		return "", false
	}
	if strings.EqualFold(raw, ":memory:") {
		return "", false
	}
	if strings.HasPrefix(strings.ToLower(raw), "file::memory:") {
		return "", false
	}

	if strings.HasPrefix(strings.ToLower(raw), "file:") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return splitSQLitePath(raw), true
		}
		mode := strings.ToLower(strings.TrimSpace(parsed.Query().Get("mode")))
		if mode == "memory" {
			return "", false
		}
		if strings.HasPrefix(strings.ToLower(parsed.Path), ":memory:") {
			return "", false
		}
		if parsed.Path != "" {
			return parsed.Path, true
		}
		if parsed.Opaque != "" {
			return splitSQLitePath(strings.TrimPrefix(raw, "file:")), true
		}
		return "", false
	}

	return splitSQLitePath(raw), true
}

func splitSQLitePath(v string) string {
	if i := strings.Index(v, "?"); i >= 0 {
		return v[:i]
	}
	return v
}
