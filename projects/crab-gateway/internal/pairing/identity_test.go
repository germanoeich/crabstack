package pairing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIdentity(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	identity1, err := LoadOrCreateIdentity(keyDir, "gw_test")
	if err != nil {
		t.Fatalf("load/create identity1: %v", err)
	}
	if identity1.GatewayID != "gw_test" {
		t.Fatalf("unexpected gateway id: %s", identity1.GatewayID)
	}
	if len(identity1.PrivateKey) == 0 || len(identity1.PublicKey) == 0 {
		t.Fatalf("expected generated key material")
	}

	identity2, err := LoadOrCreateIdentity(keyDir, "ignored")
	if err != nil {
		t.Fatalf("load/create identity2: %v", err)
	}
	if identity2.GatewayID != "gw_test" {
		t.Fatalf("expected persisted gateway id gw_test, got %s", identity2.GatewayID)
	}
	if string(identity1.PrivateKey) != string(identity2.PrivateKey) {
		t.Fatalf("expected persisted private key to be stable")
	}

	path := filepath.Join(keyDir, identityFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat identity file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected identity file permissions 0600, got %o", info.Mode().Perm())
	}
}
