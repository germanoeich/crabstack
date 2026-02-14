package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestResolveCommandFindsLeafAndRemainingArgs(t *testing.T) {
	resolution := resolveCommand(crabCommandCatalog, []string{"event", "send", "-timeout", "1s", "hello"})
	if resolution.command == nil {
		t.Fatalf("expected resolved command")
	}
	if resolution.command.Name != "send" {
		t.Fatalf("expected send command, got %q", resolution.command.Name)
	}
	if len(resolution.path) != 2 || resolution.path[0] != "event" || resolution.path[1] != "send" {
		t.Fatalf("unexpected resolution path: %#v", resolution.path)
	}
	if len(resolution.remaining) != 3 {
		t.Fatalf("unexpected remaining args count: %d", len(resolution.remaining))
	}
	if resolution.remaining[0] != "-timeout" || resolution.remaining[2] != "hello" {
		t.Fatalf("unexpected remaining args: %#v", resolution.remaining)
	}
}

func TestRunHelpCommandPrintsCommandMetadata(t *testing.T) {
	output, err := captureStdout(t, func() error {
		return runHelpCommand([]string{"event", "send"})
	})
	if err != nil {
		t.Fatalf("runHelpCommand failed: %v", err)
	}
	if !strings.Contains(output, "Usage:") {
		t.Fatalf("expected usage section")
	}
	if !strings.Contains(output, "crab event send [flags] <text>") {
		t.Fatalf("expected event send usage")
	}
	if !strings.Contains(output, "--gateway-http") {
		t.Fatalf("expected gateway-http flag description")
	}
	if !strings.Contains(output, "Arguments:") || !strings.Contains(output, "text") {
		t.Fatalf("expected argument metadata")
	}
}

func TestRunCLIWrapsTopLevelCommandErrors(t *testing.T) {
	err := runCLI([]string{"pair"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "crab pair failed:") {
		t.Fatalf("expected top-level pair prefix, got %v", err)
	}
	if !strings.Contains(err.Error(), "usage: crab pair") {
		t.Fatalf("expected pair usage, got %v", err)
	}
}

func TestRunHelpCommandRejectsUnknownPath(t *testing.T) {
	err := runHelpCommand([]string{"does-not-exist"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unknown command path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = originalStdout
	}()

	runErr := fn()
	_ = writer.Close()
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		t.Fatalf("read stdout capture: %v", readErr)
	}
	return string(output), runErr
}
