package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultCrabstackRootFallsBackToHomeWithoutLocalDir(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	setConfigWorkingDir(t, t.TempDir())

	got := DefaultCrabstackRoot()
	want := filepath.Join(homeDir, ".crabstack")
	if got != want {
		t.Fatalf("unexpected root path: got=%q want=%q", got, want)
	}
}

func TestDefaultCrabstackRootUsesLocalDirWhenPresent(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, ".crabstack"), 0o700); err != nil {
		t.Fatalf("mkdir local .crabstack: %v", err)
	}
	setConfigWorkingDir(t, workDir)

	got := DefaultCrabstackRoot()
	if got != ".crabstack" {
		t.Fatalf("unexpected root path: got=%q want=%q", got, ".crabstack")
	}
}

func TestResolveCrabstackPathNormalizesRelativePathWithoutLocalDir(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	setConfigWorkingDir(t, t.TempDir())

	got := ResolveCrabstackPath("./.crabstack/auth/codex.json")
	want := filepath.Join(homeDir, ".crabstack", "auth", "codex.json")
	if got != want {
		t.Fatalf("unexpected resolved path: got=%q want=%q", got, want)
	}
}

func setConfigWorkingDir(t *testing.T, dir string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
}
