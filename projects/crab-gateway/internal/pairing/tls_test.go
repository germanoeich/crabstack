package pairing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTLSClientConfig_EmptyReturnsNil(t *testing.T) {
	cfg, err := LoadTLSClientConfig("", "", "")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config when no files are provided")
	}
}

func TestLoadTLSClientConfig_RequiresAllFiles(t *testing.T) {
	_, err := LoadTLSClientConfig("/tmp/ca.pem", "", "")
	if err == nil {
		t.Fatalf("expected error when only some mtls files are configured")
	}
}

func TestLoadTLSClientConfig_InvalidFiles(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")

	if err := os.WriteFile(caPath, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatalf("write ca fixture: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatalf("write cert fixture: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not-a-key"), 0o600); err != nil {
		t.Fatalf("write key fixture: %v", err)
	}

	_, err := LoadTLSClientConfig(caPath, certPath, keyPath)
	if err == nil {
		t.Fatalf("expected invalid tls material to fail")
	}
}
