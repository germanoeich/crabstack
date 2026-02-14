package config

import (
	"os"
	"path/filepath"
	"strings"
)

const crabstackDirName = ".crabstack"

func LocalCrabstackDirExists() bool {
	info, err := os.Stat(crabstackDirName)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func DefaultCrabstackRoot() string {
	if LocalCrabstackDirExists() {
		return crabstackDirName
	}
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, crabstackDirName)
	}
	return crabstackDirName
}

func DefaultCrabstackPath(parts ...string) string {
	elements := make([]string, 0, len(parts)+1)
	elements = append(elements, DefaultCrabstackRoot())
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			elements = append(elements, trimmed)
		}
	}
	return filepath.Join(elements...)
}

func ResolveCrabstackPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}

	expanded := trimmed
	if resolved, err := expandPath(trimmed); err == nil && strings.TrimSpace(resolved) != "" {
		expanded = resolved
	}

	cleaned := filepath.Clean(expanded)
	if filepath.IsAbs(cleaned) {
		return cleaned
	}
	if cleaned == crabstackDirName {
		return DefaultCrabstackRoot()
	}

	prefix := crabstackDirName + string(filepath.Separator)
	if strings.HasPrefix(cleaned, prefix) {
		suffix := strings.TrimPrefix(cleaned, prefix)
		return filepath.Join(DefaultCrabstackRoot(), suffix)
	}
	return cleaned
}
