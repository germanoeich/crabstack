package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func EnvString(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func EnvOrDefault(key, fallback string) string {
	value := EnvString(key)
	if value == "" {
		return fallback
	}
	return value
}

func HostnameOrDefault(fallback string) string {
	hostname, err := os.Hostname()
	if err != nil {
		return fallback
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return fallback
	}
	return hostname
}

func parseBoolEnv(key string, fallback bool) bool {
	switch strings.ToLower(EnvString(key)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func parseOptionalDuration(raw string, fallback time.Duration, field string) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s duration %q: %w", field, value, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be > 0", field)
	}
	return parsed, nil
}
