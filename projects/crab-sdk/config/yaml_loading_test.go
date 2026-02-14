package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGatewayFromYAMLAndEnv_LoadsYAMLAndEnvOverrides(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv(EnvGatewayDBDSN, "postgres://env/override")
	t.Setenv(EnvGatewayOpenAIAPIKey, "env-openai")

	configPath := writeConfigFile(t, `
version: 1
gateway:
  http_addr: "127.0.0.1:7070"
  db_driver: "postgres"
  db_dsn: "postgres://yaml/db"
  gateway_id: "gw-yaml"
  key_dir: "/tmp/yaml-keys"
  admin_socket_path: "/tmp/yaml.sock"
  pair_timeout: "30s"
  pair_require_mtls_remote: false
  pair_allow_insecure_loopback_pairing: false
  pair_mtls_ca_file: "/tmp/ca.pem"
  pair_mtls_cert_file: "/tmp/client.crt"
  pair_mtls_key_file: "/tmp/client.key"
  anthropic_api_key: "yaml-anthropic"
  openai_api_key: "yaml-openai"
`)
	t.Setenv(EnvConfigFile, configPath)

	cfg, err := GatewayFromYAMLAndEnv()
	if err != nil {
		t.Fatalf("GatewayFromYAMLAndEnv failed: %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:7070" {
		t.Fatalf("unexpected HTTP addr %q", cfg.HTTPAddr)
	}
	if cfg.DBDriver != "postgres" {
		t.Fatalf("unexpected db driver %q", cfg.DBDriver)
	}
	if cfg.DBDSN != "postgres://env/override" {
		t.Fatalf("expected env DB DSN override, got %q", cfg.DBDSN)
	}
	if cfg.GatewayID != "gw-yaml" {
		t.Fatalf("unexpected gateway id %q", cfg.GatewayID)
	}
	if cfg.KeyDir != "/tmp/yaml-keys" {
		t.Fatalf("unexpected key dir %q", cfg.KeyDir)
	}
	if cfg.AdminSocketPath != "/tmp/yaml.sock" {
		t.Fatalf("unexpected admin socket path %q", cfg.AdminSocketPath)
	}
	if cfg.PairTimeout.String() != "30s" {
		t.Fatalf("unexpected pair timeout %s", cfg.PairTimeout)
	}
	if cfg.PairRequireMTLSRemote {
		t.Fatalf("expected pair_require_mtls_remote=false")
	}
	if cfg.PairAllowInsecureLoopback {
		t.Fatalf("expected pair_allow_insecure_loopback_pairing=false")
	}
	if cfg.PairMTLSCAFile != "/tmp/ca.pem" || cfg.PairMTLSClientCertFile != "/tmp/client.crt" || cfg.PairMTLSClientPrivateKeyFile != "/tmp/client.key" {
		t.Fatalf("unexpected mtls file values")
	}
	if cfg.AnthropicAPIKey != "yaml-anthropic" {
		t.Fatalf("unexpected anthropic api key %q", cfg.AnthropicAPIKey)
	}
	if cfg.OpenAIAPIKey != "env-openai" {
		t.Fatalf("expected env openai api key override, got %q", cfg.OpenAIAPIKey)
	}
}

func TestGatewayFromYAMLAndEnv_InvalidDuration(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv(EnvConfigFile, writeConfigFile(t, `
version: 1
gateway:
  pair_timeout: "not-a-duration"
`))

	_, err := GatewayFromYAMLAndEnv()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "gateway.pair_timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGatewayFromYAMLAndEnv_DefaultWhenNoFile(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv(EnvConfigFile, "")
	t.Setenv("HOME", t.TempDir())

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalWD) })

	emptyDir := t.TempDir()
	if err := os.Chdir(emptyDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	cfg, err := GatewayFromYAMLAndEnv()
	if err != nil {
		t.Fatalf("GatewayFromYAMLAndEnv failed: %v", err)
	}
	if cfg.HTTPAddr != DefaultGatewayHTTPAddr {
		t.Fatalf("unexpected default HTTP addr %q", cfg.HTTPAddr)
	}
	if cfg.DBDSN != DefaultGatewayDBDSN {
		t.Fatalf("unexpected default DB DSN %q", cfg.DBDSN)
	}
}

func TestGatewayFromYAMLAndEnv_PathOrderPrefersLocalCrabstackConfig(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv(EnvConfigFile, "")

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	workDir := t.TempDir()

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalWD) })
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if err := writeConfigFileAt(filepath.Join(homeDir, ".crabstack", "config.yaml"), `
version: 1
gateway:
  gateway_id: "home-gw"
`); err != nil {
		t.Fatalf("write home config: %v", err)
	}
	if err := writeConfigFileAt(filepath.Join(workDir, ".crabstack", "config.yaml"), `
version: 1
gateway:
  gateway_id: "local-gw"
`); err != nil {
		t.Fatalf("write local config: %v", err)
	}

	cfg, err := GatewayFromYAMLAndEnv()
	if err != nil {
		t.Fatalf("GatewayFromYAMLAndEnv failed: %v", err)
	}
	if cfg.GatewayID != "local-gw" {
		t.Fatalf("expected local gateway_id, got %q", cfg.GatewayID)
	}
}

func TestGatewayFromYAMLAndEnv_PathOrderFallsBackToHomeCrabstackConfig(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv(EnvConfigFile, "")

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	workDir := t.TempDir()

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalWD) })
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if err := writeConfigFileAt(filepath.Join(homeDir, ".crabstack", "config.yml"), `
version: 1
gateway:
  gateway_id: "home-gw"
`); err != nil {
		t.Fatalf("write home config: %v", err)
	}

	cfg, err := GatewayFromYAMLAndEnv()
	if err != nil {
		t.Fatalf("GatewayFromYAMLAndEnv failed: %v", err)
	}
	if cfg.GatewayID != "home-gw" {
		t.Fatalf("expected home gateway_id, got %q", cfg.GatewayID)
	}
}

func TestGatewayFromYAMLAndEnv_NormalizesCrabstackPathsWithoutLocalDir(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv(EnvConfigFile, "")

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	workDir := t.TempDir()

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalWD) })
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	configPath := writeConfigFile(t, `
version: 1
gateway:
  key_dir: ".crabstack/keys"
  admin_socket_path: ".crabstack/run/gateway-admin.sock"
`)
	t.Setenv(EnvConfigFile, configPath)

	cfg, err := GatewayFromYAMLAndEnv()
	if err != nil {
		t.Fatalf("GatewayFromYAMLAndEnv failed: %v", err)
	}
	expectedKeyDir := filepath.Join(homeDir, ".crabstack", "keys")
	expectedAdminSocket := filepath.Join(homeDir, ".crabstack", "run", "gateway-admin.sock")
	if cfg.KeyDir != expectedKeyDir {
		t.Fatalf("expected key_dir %q, got %q", expectedKeyDir, cfg.KeyDir)
	}
	if cfg.AdminSocketPath != expectedAdminSocket {
		t.Fatalf("expected admin_socket_path %q, got %q", expectedAdminSocket, cfg.AdminSocketPath)
	}
}

func TestCLIFromYAMLAndEnv_LoadsYAMLAndEnvOverrides(t *testing.T) {
	clearCLIEnv(t)
	t.Setenv(EnvCLIGatewayWSURL, "ws://env/ws")
	t.Setenv(EnvGatewayAdminSocketPath, "/tmp/env-admin.sock")

	configPath := writeConfigFile(t, `
version: 1
cli:
  gateway_ws_url: "ws://yaml/ws"
  gateway_http_url: "http://yaml/http"
  gateway_public_key_ed25519: "yaml-pub"
  agent_id: "yaml-agent"
  component_type: "subscriber"
  gateway_admin_socket_path: "/tmp/yaml-admin.sock"
  gateway_key_dir: "/tmp/yaml-keys"
  pair_listen_addr: "127.0.0.1:9191"
  pair_listen_path: "/yaml/pair"
  pair_timeout: "33s"
  pair_test_timeout: "44s"
  event_send_timeout: "15s"
  auth_flow:
    codex_timeout: "65s"
    anthropic_timeout: "75s"
    claude_timeout: "85s"
    claude_mode: "console"
`)
	t.Setenv(EnvConfigFile, configPath)

	cfg, err := CLIFromYAMLAndEnv()
	if err != nil {
		t.Fatalf("CLIFromYAMLAndEnv failed: %v", err)
	}
	if cfg.GatewayWSURL != "ws://env/ws" {
		t.Fatalf("expected env gateway ws override, got %q", cfg.GatewayWSURL)
	}
	if cfg.GatewayHTTPURL != "http://yaml/http" {
		t.Fatalf("unexpected gateway http %q", cfg.GatewayHTTPURL)
	}
	if cfg.GatewayPublicKeyEd25519 != "yaml-pub" {
		t.Fatalf("unexpected gateway public key %q", cfg.GatewayPublicKeyEd25519)
	}
	if cfg.AgentID != "yaml-agent" {
		t.Fatalf("unexpected agent id %q", cfg.AgentID)
	}
	if cfg.ComponentType != "subscriber" {
		t.Fatalf("unexpected component type %q", cfg.ComponentType)
	}
	if cfg.GatewayAdminSocketPath != "/tmp/env-admin.sock" {
		t.Fatalf("expected env admin socket override, got %q", cfg.GatewayAdminSocketPath)
	}
	if cfg.GatewayKeyDir != "/tmp/yaml-keys" {
		t.Fatalf("unexpected gateway key dir %q", cfg.GatewayKeyDir)
	}
	if cfg.PairListenAddr != "127.0.0.1:9191" {
		t.Fatalf("unexpected pair listen addr %q", cfg.PairListenAddr)
	}
	if cfg.PairListenPath != "/yaml/pair" {
		t.Fatalf("unexpected pair listen path %q", cfg.PairListenPath)
	}
	if cfg.PairTimeout.String() != "33s" {
		t.Fatalf("unexpected pair timeout %s", cfg.PairTimeout)
	}
	if cfg.PairTestTimeout.String() != "44s" {
		t.Fatalf("unexpected pair test timeout %s", cfg.PairTestTimeout)
	}
	if cfg.EventSendTimeout.String() != "15s" {
		t.Fatalf("unexpected event send timeout %s", cfg.EventSendTimeout)
	}
	if cfg.AuthFlow.CodexTimeout != 65*time.Second {
		t.Fatalf("unexpected codex timeout %s", cfg.AuthFlow.CodexTimeout)
	}
	if cfg.AuthFlow.AnthropicTimeout != 75*time.Second {
		t.Fatalf("unexpected anthropic timeout %s", cfg.AuthFlow.AnthropicTimeout)
	}
	if cfg.AuthFlow.ClaudeTimeout != 85*time.Second {
		t.Fatalf("unexpected claude timeout %s", cfg.AuthFlow.ClaudeTimeout)
	}
	if cfg.AuthFlow.ClaudeMode != "console" {
		t.Fatalf("unexpected claude mode %q", cfg.AuthFlow.ClaudeMode)
	}
}

func TestCLIFromYAMLAndEnv_NormalizesCrabstackPathsWithoutLocalDir(t *testing.T) {
	clearCLIEnv(t)
	t.Setenv(EnvConfigFile, "")

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	workDir := t.TempDir()

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalWD) })
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	configPath := writeConfigFile(t, `
version: 1
cli:
  gateway_admin_socket_path: ".crabstack/run/gateway-admin.sock"
  gateway_key_dir: ".crabstack/keys"
`)
	t.Setenv(EnvConfigFile, configPath)

	cfg, err := CLIFromYAMLAndEnv()
	if err != nil {
		t.Fatalf("CLIFromYAMLAndEnv failed: %v", err)
	}
	expectedKeyDir := filepath.Join(homeDir, ".crabstack", "keys")
	expectedAdminSocket := filepath.Join(homeDir, ".crabstack", "run", "gateway-admin.sock")
	if cfg.GatewayKeyDir != expectedKeyDir {
		t.Fatalf("expected gateway_key_dir %q, got %q", expectedKeyDir, cfg.GatewayKeyDir)
	}
	if cfg.GatewayAdminSocketPath != expectedAdminSocket {
		t.Fatalf("expected gateway_admin_socket_path %q, got %q", expectedAdminSocket, cfg.GatewayAdminSocketPath)
	}
}

func TestCLIFromYAMLAndEnv_InvalidDuration(t *testing.T) {
	clearCLIEnv(t)
	t.Setenv(EnvConfigFile, writeConfigFile(t, `
version: 1
cli:
  pair_timeout: "not-a-duration"
`))

	_, err := CLIFromYAMLAndEnv()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "cli.pair_timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := writeConfigFileAt(path, content); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return path
}

func writeConfigFileAt(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600)
}

func clearGatewayEnv(t *testing.T) {
	t.Helper()

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
	t.Setenv(EnvGatewayAnthropicAPIKey, "")
	t.Setenv(EnvGatewayOpenAIAPIKey, "")
}

func clearCLIEnv(t *testing.T) {
	t.Helper()

	t.Setenv(EnvConfigFile, "")
	t.Setenv(EnvCLIGatewayWSURL, "")
	t.Setenv(EnvCLIGatewayHTTPURL, "")
	t.Setenv(EnvCLIGatewayPublicKeyEd25519, "")
	t.Setenv(EnvCLIAgentID, "")
	t.Setenv(EnvCLIComponentType, "")
	t.Setenv(EnvGatewayAdminSocketPath, "")
	t.Setenv(EnvGatewayKeyDir, "")
	t.Setenv(EnvCLIPairListenAddr, "")
	t.Setenv(EnvCLIPairListenPath, "")
}
