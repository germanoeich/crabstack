package config

import (
	"strings"
	"time"
)

type CLIAuthFlowConfig struct {
	CodexTimeout     time.Duration
	AnthropicTimeout time.Duration
	ClaudeTimeout    time.Duration
	ClaudeMode       string
}

type CLIConfig struct {
	GatewayWSURL            string
	GatewayHTTPURL          string
	GatewayPublicKeyEd25519 string
	AgentID                 string
	ComponentType           string
	GatewayAdminSocketPath  string
	GatewayKeyDir           string
	PairListenAddr          string
	PairListenPath          string
	PairTimeout             time.Duration
	PairTestTimeout         time.Duration
	EventSendTimeout        time.Duration
	AuthFlow                CLIAuthFlowConfig
}

func CLIFromYAMLAndEnv() (CLIConfig, error) {
	cfg := defaultCLIConfig()

	fileCfg, err := loadFileConfig()
	if err != nil {
		return CLIConfig{}, err
	}
	if err := applyCLIYAML(&cfg, fileCfg.CLI); err != nil {
		return CLIConfig{}, err
	}
	applyCLIEnv(&cfg)

	return cfg, nil
}

func defaultCLIConfig() CLIConfig {
	return CLIConfig{
		GatewayWSURL:            DefaultCLIGatewayWSURL,
		GatewayHTTPURL:          DefaultCLIGatewayHTTPURL,
		GatewayPublicKeyEd25519: "",
		AgentID:                 DefaultCLIAgentID,
		ComponentType:           DefaultCLIComponentType,
		GatewayAdminSocketPath:  ResolveCrabstackPath(DefaultGatewayAdminSocketPath),
		GatewayKeyDir:           ResolveCrabstackPath(DefaultGatewayKeyDir),
		PairListenAddr:          DefaultCLIPairListenAddress,
		PairListenPath:          DefaultCLIPairListenPath,
		PairTimeout:             DefaultCLIPairTimeout,
		PairTestTimeout:         DefaultCLIPairTimeout,
		EventSendTimeout:        DefaultCLIEventSendTimeout,
		AuthFlow: CLIAuthFlowConfig{
			CodexTimeout:     DefaultCLICodexAuthTimeout,
			AnthropicTimeout: DefaultCLIAnthropicAuthTimeout,
			ClaudeTimeout:    DefaultCLIClaudeAuthTimeout,
			ClaudeMode:       DefaultCLIClaudeMode,
		},
	}
}

func applyCLIYAML(cfg *CLIConfig, source fileCLIConfig) error {
	if value := strings.TrimSpace(source.GatewayWSURL); value != "" {
		cfg.GatewayWSURL = value
	}
	if value := strings.TrimSpace(source.GatewayHTTPURL); value != "" {
		cfg.GatewayHTTPURL = value
	}
	if value := strings.TrimSpace(source.GatewayPublicKeyEd25519); value != "" {
		cfg.GatewayPublicKeyEd25519 = value
	}
	if value := strings.TrimSpace(source.AgentID); value != "" {
		cfg.AgentID = value
	}
	if value := strings.TrimSpace(source.ComponentType); value != "" {
		cfg.ComponentType = value
	}
	if value := strings.TrimSpace(source.GatewayAdminSocketPath); value != "" {
		cfg.GatewayAdminSocketPath = ResolveCrabstackPath(value)
	}
	if value := strings.TrimSpace(source.GatewayKeyDir); value != "" {
		cfg.GatewayKeyDir = ResolveCrabstackPath(value)
	}
	if value := strings.TrimSpace(source.PairListenAddr); value != "" {
		cfg.PairListenAddr = value
	}
	if value := strings.TrimSpace(source.PairListenPath); value != "" {
		cfg.PairListenPath = value
	}

	pairTimeout, err := parseOptionalDuration(source.PairTimeout, cfg.PairTimeout, "cli.pair_timeout")
	if err != nil {
		return err
	}
	cfg.PairTimeout = pairTimeout

	pairTestTimeout, err := parseOptionalDuration(source.PairTestTimeout, cfg.PairTestTimeout, "cli.pair_test_timeout")
	if err != nil {
		return err
	}
	cfg.PairTestTimeout = pairTestTimeout

	eventSendTimeout, err := parseOptionalDuration(source.EventSendTimeout, cfg.EventSendTimeout, "cli.event_send_timeout")
	if err != nil {
		return err
	}
	cfg.EventSendTimeout = eventSendTimeout

	codexTimeout, err := parseOptionalDuration(source.AuthFlow.CodexTimeout, cfg.AuthFlow.CodexTimeout, "cli.auth_flow.codex_timeout")
	if err != nil {
		return err
	}
	cfg.AuthFlow.CodexTimeout = codexTimeout

	anthropicTimeout, err := parseOptionalDuration(source.AuthFlow.AnthropicTimeout, cfg.AuthFlow.AnthropicTimeout, "cli.auth_flow.anthropic_timeout")
	if err != nil {
		return err
	}
	cfg.AuthFlow.AnthropicTimeout = anthropicTimeout

	claudeTimeout, err := parseOptionalDuration(source.AuthFlow.ClaudeTimeout, cfg.AuthFlow.ClaudeTimeout, "cli.auth_flow.claude_timeout")
	if err != nil {
		return err
	}
	cfg.AuthFlow.ClaudeTimeout = claudeTimeout

	if value := strings.TrimSpace(source.AuthFlow.ClaudeMode); value != "" {
		cfg.AuthFlow.ClaudeMode = strings.ToLower(value)
	}

	return nil
}

func applyCLIEnv(cfg *CLIConfig) {
	cfg.GatewayWSURL = EnvOrDefault(EnvCLIGatewayWSURL, cfg.GatewayWSURL)
	cfg.GatewayHTTPURL = EnvOrDefault(EnvCLIGatewayHTTPURL, cfg.GatewayHTTPURL)
	cfg.GatewayPublicKeyEd25519 = EnvOrDefault(EnvCLIGatewayPublicKeyEd25519, cfg.GatewayPublicKeyEd25519)
	cfg.AgentID = EnvOrDefault(EnvCLIAgentID, cfg.AgentID)
	cfg.ComponentType = EnvOrDefault(EnvCLIComponentType, cfg.ComponentType)
	cfg.GatewayAdminSocketPath = ResolveCrabstackPath(EnvOrDefault(EnvGatewayAdminSocketPath, cfg.GatewayAdminSocketPath))
	cfg.GatewayKeyDir = ResolveCrabstackPath(EnvOrDefault(EnvGatewayKeyDir, cfg.GatewayKeyDir))
	cfg.PairListenAddr = EnvOrDefault(EnvCLIPairListenAddr, cfg.PairListenAddr)
	cfg.PairListenPath = EnvOrDefault(EnvCLIPairListenPath, cfg.PairListenPath)
}
