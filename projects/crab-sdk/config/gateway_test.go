package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGatewayFromEnv_Default(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	setWorkingDir(t, t.TempDir())

	t.Setenv(EnvGatewayHTTPAddr, "")
	t.Setenv(EnvGatewayDBDriver, "")
	t.Setenv(EnvGatewayDBDSN, "")
	t.Setenv(EnvGatewayID, "")
	t.Setenv(EnvGatewayKeyDir, "")
	t.Setenv(EnvGatewayAdminSocketPath, "")
	t.Setenv(EnvGatewayPairTimeout, "")
	t.Setenv(EnvGatewayRequireMTLSRemote, "")
	t.Setenv(EnvGatewayAllowInsecureLoopbackPairing, "")
	t.Setenv(EnvGatewayPairMTLSCAFile, "")
	t.Setenv(EnvGatewayPairMTLSCertFile, "")
	t.Setenv(EnvGatewayPairMTLSKeyFile, "")

	cfg := GatewayFromEnv()
	if cfg.HTTPAddr != DefaultGatewayHTTPAddr {
		t.Fatalf("expected default addr %q, got %q", DefaultGatewayHTTPAddr, cfg.HTTPAddr)
	}
	if cfg.DBDriver != DefaultGatewayDBDriver {
		t.Fatalf("expected default db driver %q, got %q", DefaultGatewayDBDriver, cfg.DBDriver)
	}
	if cfg.DBDSN != DefaultGatewayDBDSN {
		t.Fatalf("expected default db dsn %q, got %q", DefaultGatewayDBDSN, cfg.DBDSN)
	}
	if cfg.GatewayID != DefaultGatewayID {
		t.Fatalf("expected default gateway id %q, got %q", DefaultGatewayID, cfg.GatewayID)
	}
	expectedKeyDir := filepath.Join(homeDir, ".crabstack", "keys")
	if cfg.KeyDir != expectedKeyDir {
		t.Fatalf("expected default key dir %q, got %q", expectedKeyDir, cfg.KeyDir)
	}
	expectedAdminSocket := filepath.Join(homeDir, ".crabstack", "run", "gateway-admin.sock")
	if cfg.AdminSocketPath != expectedAdminSocket {
		t.Fatalf("expected default admin socket path %q, got %q", expectedAdminSocket, cfg.AdminSocketPath)
	}
	if cfg.PairTimeout != DefaultGatewayPairTimeout {
		t.Fatalf("expected default pair timeout %s, got %s", DefaultGatewayPairTimeout, cfg.PairTimeout)
	}
	if cfg.PairRequireMTLSRemote != DefaultGatewayRequireMTLSRemote {
		t.Fatalf("expected default require mtls %v, got %v", DefaultGatewayRequireMTLSRemote, cfg.PairRequireMTLSRemote)
	}
	if cfg.PairAllowInsecureLoopback != DefaultGatewayAllowInsecureLoopbackPair {
		t.Fatalf("expected default allow loopback %v, got %v", DefaultGatewayAllowInsecureLoopbackPair, cfg.PairAllowInsecureLoopback)
	}
}

func TestGatewayFromEnv_DefaultPrefersLocalCrabstackWhenPresent(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, ".crabstack"), 0o700); err != nil {
		t.Fatalf("mkdir local .crabstack: %v", err)
	}
	setWorkingDir(t, workDir)

	t.Setenv(EnvGatewayHTTPAddr, "")
	t.Setenv(EnvGatewayDBDriver, "")
	t.Setenv(EnvGatewayDBDSN, "")
	t.Setenv(EnvGatewayID, "")
	t.Setenv(EnvGatewayKeyDir, "")
	t.Setenv(EnvGatewayAdminSocketPath, "")
	t.Setenv(EnvGatewayPairTimeout, "")
	t.Setenv(EnvGatewayRequireMTLSRemote, "")
	t.Setenv(EnvGatewayAllowInsecureLoopbackPairing, "")
	t.Setenv(EnvGatewayPairMTLSCAFile, "")
	t.Setenv(EnvGatewayPairMTLSCertFile, "")
	t.Setenv(EnvGatewayPairMTLSKeyFile, "")

	cfg := GatewayFromEnv()
	if cfg.KeyDir != DefaultGatewayKeyDir {
		t.Fatalf("expected local default key dir %q, got %q", DefaultGatewayKeyDir, cfg.KeyDir)
	}
	if cfg.AdminSocketPath != DefaultGatewayAdminSocketPath {
		t.Fatalf("expected local default admin socket path %q, got %q", DefaultGatewayAdminSocketPath, cfg.AdminSocketPath)
	}
}

func TestGatewayFromEnv_Override(t *testing.T) {
	t.Setenv(EnvGatewayHTTPAddr, "127.0.0.1:9999")
	t.Setenv(EnvGatewayDBDriver, "PoStGrEs")
	t.Setenv(EnvGatewayDBDSN, "postgres://localhost/crabstack")
	t.Setenv(EnvGatewayID, "gw_home")
	t.Setenv(EnvGatewayKeyDir, "/tmp/crabstack-keys")
	t.Setenv(EnvGatewayAdminSocketPath, "/tmp/crabstack-admin.sock")
	t.Setenv(EnvGatewayPairTimeout, "45s")
	t.Setenv(EnvGatewayRequireMTLSRemote, "false")
	t.Setenv(EnvGatewayAllowInsecureLoopbackPairing, "false")
	t.Setenv(EnvGatewayPairMTLSCAFile, "/tmp/ca.pem")
	t.Setenv(EnvGatewayPairMTLSCertFile, "/tmp/client.crt")
	t.Setenv(EnvGatewayPairMTLSKeyFile, "/tmp/client.key")

	cfg := GatewayFromEnv()
	if cfg.HTTPAddr != "127.0.0.1:9999" {
		t.Fatalf("expected override addr, got %q", cfg.HTTPAddr)
	}
	if cfg.DBDriver != "postgres" {
		t.Fatalf("expected normalized db driver, got %q", cfg.DBDriver)
	}
	if cfg.DBDSN != "postgres://localhost/crabstack" {
		t.Fatalf("expected db dsn override, got %q", cfg.DBDSN)
	}
	if cfg.GatewayID != "gw_home" {
		t.Fatalf("expected gateway id override, got %q", cfg.GatewayID)
	}
	if cfg.KeyDir != "/tmp/crabstack-keys" {
		t.Fatalf("expected key dir override, got %q", cfg.KeyDir)
	}
	if cfg.AdminSocketPath != "/tmp/crabstack-admin.sock" {
		t.Fatalf("expected admin socket path override, got %q", cfg.AdminSocketPath)
	}
	if cfg.PairTimeout.String() != "45s" {
		t.Fatalf("expected pair timeout override, got %s", cfg.PairTimeout)
	}
	if cfg.PairRequireMTLSRemote {
		t.Fatalf("expected mtls requirement override to false")
	}
	if cfg.PairAllowInsecureLoopback {
		t.Fatalf("expected insecure loopback override to false")
	}
	if cfg.PairMTLSCAFile != "/tmp/ca.pem" || cfg.PairMTLSClientCertFile != "/tmp/client.crt" || cfg.PairMTLSClientPrivateKeyFile != "/tmp/client.key" {
		t.Fatalf("expected mtls file overrides")
	}
}

func setWorkingDir(t *testing.T, dir string) {
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

func TestGatewayConfigValidate(t *testing.T) {
	base := GatewayConfig{
		HTTPAddr:                  ":8080",
		DBDriver:                  "sqlite",
		DBDSN:                     "gateway.db",
		GatewayID:                 "gw",
		KeyDir:                    ".keys",
		AdminSocketPath:           ".crabstack/run/gateway-admin.sock",
		PairTimeout:               DefaultGatewayPairTimeout,
		PairRequireMTLSRemote:     DefaultGatewayRequireMTLSRemote,
		PairAllowInsecureLoopback: DefaultGatewayAllowInsecureLoopbackPair,
	}

	if err := (GatewayConfig{
		HTTPAddr: "", DBDriver: "sqlite", DBDSN: "gateway.db", GatewayID: "gw", KeyDir: ".keys", PairTimeout: DefaultGatewayPairTimeout,
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty addr")
	}
	if err := (GatewayConfig{
		HTTPAddr: ":8080", DBDriver: "bad", DBDSN: "x", GatewayID: "gw", KeyDir: ".keys", PairTimeout: DefaultGatewayPairTimeout,
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for bad db driver")
	}
	if err := (GatewayConfig{
		HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "", GatewayID: "gw", KeyDir: ".keys", PairTimeout: DefaultGatewayPairTimeout,
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty db dsn")
	}
	if err := (GatewayConfig{
		HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "x", GatewayID: "", KeyDir: ".keys", PairTimeout: DefaultGatewayPairTimeout,
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty gateway id")
	}
	if err := (GatewayConfig{
		HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "x", GatewayID: "gw", KeyDir: "", PairTimeout: DefaultGatewayPairTimeout,
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty key dir")
	}
	if err := (GatewayConfig{
		HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "x", GatewayID: "gw", KeyDir: ".keys", AdminSocketPath: "", PairTimeout: DefaultGatewayPairTimeout,
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty admin socket path")
	}
	if err := (GatewayConfig{
		HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "x", GatewayID: "gw", KeyDir: ".keys", PairTimeout: 0,
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for invalid pair timeout")
	}
	if err := (GatewayConfig{
		HTTPAddr:               ":8080",
		DBDriver:               "sqlite",
		DBDSN:                  "x",
		GatewayID:              "gw",
		KeyDir:                 ".keys",
		AdminSocketPath:        ".crabstack/run/gateway-admin.sock",
		PairTimeout:            DefaultGatewayPairTimeout,
		PairMTLSCAFile:         "/tmp/ca.pem",
		PairMTLSClientCertFile: "/tmp/client.crt",
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for partial mtls config")
	}

	if err := base.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if err := (GatewayConfig{
		HTTPAddr:        ":8080",
		DBDriver:        "postgres",
		DBDSN:           "postgres://localhost/db",
		GatewayID:       "gw",
		KeyDir:          ".keys",
		AdminSocketPath: ".crabstack/run/gateway-admin.sock",
		PairTimeout:     DefaultGatewayPairTimeout,
	}).Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
