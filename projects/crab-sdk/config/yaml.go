package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	EnvConfigFile           = "CRAB_CONFIG_FILE"
	defaultConfigFileName   = "config.yaml"
	alternateConfigFileName = "config.yml"
)

type fileConfig struct {
	Version int               `yaml:"version"`
	Gateway fileGatewayConfig `yaml:"gateway"`
	CLI     fileCLIConfig     `yaml:"cli"`
}

type fileGatewayConfig struct {
	HTTPAddr                         string                   `yaml:"http_addr"`
	DBDriver                         string                   `yaml:"db_driver"`
	DBDSN                            string                   `yaml:"db_dsn"`
	GatewayID                        string                   `yaml:"gateway_id"`
	KeyDir                           string                   `yaml:"key_dir"`
	AdminSocketPath                  string                   `yaml:"admin_socket_path"`
	PairTimeout                      string                   `yaml:"pair_timeout"`
	PairRequireMTLSRemote            *bool                    `yaml:"pair_require_mtls_remote"`
	PairAllowInsecureLoopbackPairing *bool                    `yaml:"pair_allow_insecure_loopback_pairing"`
	PairMTLSCAFile                   string                   `yaml:"pair_mtls_ca_file"`
	PairMTLSClientCertFile           string                   `yaml:"pair_mtls_cert_file"`
	PairMTLSClientPrivateKeyFile     string                   `yaml:"pair_mtls_key_file"`
	Agents                           []fileGatewayAgentConfig `yaml:"agents"`
	AnthropicAPIKey                  string                   `yaml:"anthropic_api_key"`
	OpenAIAPIKey                     string                   `yaml:"openai_api_key"`
}

type fileGatewayAgentConfig struct {
	Name         string   `yaml:"name"`
	Model        string   `yaml:"model"`
	Channels     []string `yaml:"channels"`
	Users        []string `yaml:"users"`
	WorkspaceDir string   `yaml:"workspace_dir"`
}

type fileCLIConfig struct {
	GatewayWSURL            string            `yaml:"gateway_ws_url"`
	GatewayHTTPURL          string            `yaml:"gateway_http_url"`
	GatewayPublicKeyEd25519 string            `yaml:"gateway_public_key_ed25519"`
	AgentID                 string            `yaml:"agent_id"`
	ComponentType           string            `yaml:"component_type"`
	GatewayAdminSocketPath  string            `yaml:"gateway_admin_socket_path"`
	GatewayKeyDir           string            `yaml:"gateway_key_dir"`
	PairListenAddr          string            `yaml:"pair_listen_addr"`
	PairListenPath          string            `yaml:"pair_listen_path"`
	PairTimeout             string            `yaml:"pair_timeout"`
	PairTestTimeout         string            `yaml:"pair_test_timeout"`
	EventSendTimeout        string            `yaml:"event_send_timeout"`
	AuthFlow                fileCLIAuthConfig `yaml:"auth_flow"`
}

type fileCLIAuthConfig struct {
	CodexTimeout     string `yaml:"codex_timeout"`
	AnthropicTimeout string `yaml:"anthropic_timeout"`
	ClaudeTimeout    string `yaml:"claude_timeout"`
	ClaudeMode       string `yaml:"claude_mode"`
}

func loadFileConfig() (fileConfig, error) {
	path, ok, err := resolveConfigFilePath()
	if err != nil {
		return fileConfig{}, err
	}
	if !ok {
		return fileConfig{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, fmt.Errorf("read config file %s: %w", path, err)
	}

	var cfg fileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fileConfig{}, fmt.Errorf("decode config file %s: %w", path, err)
	}

	return cfg, nil
}

func resolveConfigFilePath() (string, bool, error) {
	if explicit := EnvString(EnvConfigFile); explicit != "" {
		resolvedPath, err := expandPath(explicit)
		if err != nil {
			return "", false, fmt.Errorf("resolve %s: %w", EnvConfigFile, err)
		}
		info, err := os.Stat(resolvedPath)
		if err != nil {
			return "", false, fmt.Errorf("config file %s: %w", resolvedPath, err)
		}
		if info.IsDir() {
			return "", false, fmt.Errorf("config file %s is a directory", resolvedPath)
		}
		return resolvedPath, true, nil
	}

	localCandidates := []string{
		filepath.Join(crabstackDirName, defaultConfigFileName),
		filepath.Join(crabstackDirName, alternateConfigFileName),
	}
	for _, candidate := range localCandidates {
		info, err := os.Stat(candidate)
		if err == nil {
			if info.IsDir() {
				return "", false, fmt.Errorf("config path %s is a directory", candidate)
			}
			return candidate, true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", false, fmt.Errorf("stat config file %s: %w", candidate, err)
		}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", false, fmt.Errorf("resolve home directory for config lookup: %w", err)
	}
	homeCandidates := []string{
		filepath.Join(homeDir, crabstackDirName, defaultConfigFileName),
		filepath.Join(homeDir, crabstackDirName, alternateConfigFileName),
	}
	for _, candidate := range homeCandidates {
		info, err := os.Stat(candidate)
		if err == nil {
			if info.IsDir() {
				return "", false, fmt.Errorf("config path %s is a directory", candidate)
			}
			return candidate, true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", false, fmt.Errorf("stat config file %s: %w", candidate, err)
		}
	}

	return "", false, nil
}

func expandPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", nil
	}
	if trimmed == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return home, nil
	}
	if strings.HasPrefix(trimmed, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, strings.TrimPrefix(trimmed, "~/")), nil
	}
	return trimmed, nil
}
