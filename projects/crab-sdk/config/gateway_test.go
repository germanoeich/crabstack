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
	t.Setenv(EnvGatewayAgentsJSON, "")

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
	expectedClaudeCredentials := filepath.Join(homeDir, ".crabstack", "auth", "claude.json")
	if cfg.ClaudeCredentialsFile != expectedClaudeCredentials {
		t.Fatalf("expected default claude credentials path %q, got %q", expectedClaudeCredentials, cfg.ClaudeCredentialsFile)
	}
	expectedCodexCredentials := filepath.Join(homeDir, ".crabstack", "auth", "codex.json")
	if cfg.CodexCredentialsFile != expectedCodexCredentials {
		t.Fatalf("expected default codex credentials path %q, got %q", expectedCodexCredentials, cfg.CodexCredentialsFile)
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
	t.Setenv(EnvGatewayAgentsJSON, "")

	cfg := GatewayFromEnv()
	if cfg.KeyDir != DefaultGatewayKeyDir {
		t.Fatalf("expected local default key dir %q, got %q", DefaultGatewayKeyDir, cfg.KeyDir)
	}
	if cfg.AdminSocketPath != DefaultGatewayAdminSocketPath {
		t.Fatalf("expected local default admin socket path %q, got %q", DefaultGatewayAdminSocketPath, cfg.AdminSocketPath)
	}
	if cfg.ClaudeCredentialsFile != filepath.Join(".crabstack", "auth", "claude.json") {
		t.Fatalf("expected local default claude credentials path, got %q", cfg.ClaudeCredentialsFile)
	}
	if cfg.CodexCredentialsFile != filepath.Join(".crabstack", "auth", "codex.json") {
		t.Fatalf("expected local default codex credentials path, got %q", cfg.CodexCredentialsFile)
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
	t.Setenv(EnvGatewayAgentsJSON, `[{"name":"support","model":"anthropic/claude-sonnet-4-20250514"}]`)

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
	if len(cfg.Agents) != 1 {
		t.Fatalf("expected agents override, got %d", len(cfg.Agents))
	}
	if cfg.Agents[0].Name != "support" || cfg.Agents[0].Model != "anthropic/claude-sonnet-4-20250514" {
		t.Fatalf("unexpected agents override: %+v", cfg.Agents[0])
	}
}

func TestGatewayCredentialLoading(t *testing.T) {
	claudePath := filepath.Join(t.TempDir(), "claude.json")
	codexPath := filepath.Join(t.TempDir(), "codex.json")

	if err := os.WriteFile(claudePath, []byte(`{"provider":"claude","access_token":"claude-token"}`), 0o600); err != nil {
		t.Fatalf("write claude credentials: %v", err)
	}
	if err := os.WriteFile(codexPath, []byte(`{
  "provider": "codex",
  "access_token": "codex-token",
  "account_meta": {
    "chatgpt_account_id": "acct-123"
  }
}`), 0o600); err != nil {
		t.Fatalf("write codex credentials: %v", err)
	}

	cfg := GatewayConfig{
		ClaudeCredentialsFile: claudePath,
		CodexCredentialsFile:  codexPath,
	}
	if err := loadGatewaySubscriptionCredentials(&cfg); err != nil {
		t.Fatalf("loadGatewaySubscriptionCredentials failed: %v", err)
	}
	if cfg.ClaudeAccessToken != "claude-token" {
		t.Fatalf("expected claude access token to load, got %q", cfg.ClaudeAccessToken)
	}
	if cfg.CodexAccessToken != "codex-token" {
		t.Fatalf("expected codex access token to load, got %q", cfg.CodexAccessToken)
	}
	if cfg.CodexAccountID != "acct-123" {
		t.Fatalf("expected codex account id to load from account_meta, got %q", cfg.CodexAccountID)
	}
}

func TestGatewayCredentialLoading_MissingFiles(t *testing.T) {
	cfg := GatewayConfig{
		ClaudeCredentialsFile: filepath.Join(t.TempDir(), "claude.json"),
		CodexCredentialsFile:  filepath.Join(t.TempDir(), "codex.json"),
	}

	if err := loadGatewaySubscriptionCredentials(&cfg); err != nil {
		t.Fatalf("expected missing credentials files to be skipped, got error: %v", err)
	}
	if cfg.ClaudeAccessToken != "" {
		t.Fatalf("expected empty claude access token, got %q", cfg.ClaudeAccessToken)
	}
	if cfg.CodexAccessToken != "" {
		t.Fatalf("expected empty codex access token, got %q", cfg.CodexAccessToken)
	}
	if cfg.CodexAccountID != "" {
		t.Fatalf("expected empty codex account id, got %q", cfg.CodexAccountID)
	}
}

func TestGatewayCredentialLoading_InvalidJSON(t *testing.T) {
	codexPath := filepath.Join(t.TempDir(), "codex.json")
	if err := os.WriteFile(codexPath, []byte(`not-json`), 0o600); err != nil {
		t.Fatalf("write codex credentials: %v", err)
	}

	cfg := GatewayConfig{
		CodexCredentialsFile: codexPath,
	}
	if err := loadGatewaySubscriptionCredentials(&cfg); err == nil {
		t.Fatalf("expected invalid json error")
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
		HTTPAddr:        ":8080",
		DBDriver:        "sqlite",
		DBDSN:           "x",
		GatewayID:       "gw",
		KeyDir:          ".keys",
		AdminSocketPath: ".crabstack/run/gateway-admin.sock",
		PairTimeout:     DefaultGatewayPairTimeout,
		Agents:          []GatewayAgentConfig{{Name: "assistant", Model: "invalid"}},
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for invalid agent model format")
	}
	if err := (GatewayConfig{
		HTTPAddr:        ":8080",
		DBDriver:        "sqlite",
		DBDSN:           "x",
		GatewayID:       "gw",
		KeyDir:          ".keys",
		AdminSocketPath: ".crabstack/run/gateway-admin.sock",
		PairTimeout:     DefaultGatewayPairTimeout,
		Agents: []GatewayAgentConfig{
			{Name: "assistant", Model: "anthropic/claude-sonnet-4-20250514"},
			{Name: "Assistant", Model: "openai/gpt-4o-mini"},
		},
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for duplicate agent names")
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
