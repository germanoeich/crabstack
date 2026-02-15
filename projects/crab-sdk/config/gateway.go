package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	EnvGatewayHTTPAddr                     = "CRAB_GATEWAY_HTTP_ADDR"
	EnvGatewayDBDriver                     = "CRAB_GATEWAY_DB_DRIVER"
	EnvGatewayDBDSN                        = "CRAB_GATEWAY_DB_DSN"
	EnvGatewayID                           = "CRAB_GATEWAY_ID"
	EnvGatewayKeyDir                       = "CRAB_GATEWAY_KEY_DIR"
	EnvGatewayAdminSocketPath              = "CRAB_GATEWAY_ADMIN_SOCKET_PATH"
	EnvGatewayPairTimeout                  = "CRAB_GATEWAY_PAIR_TIMEOUT"
	EnvGatewayRequireMTLSRemote            = "CRAB_GATEWAY_REQUIRE_MTLS_REMOTE"
	EnvGatewayAllowInsecureLoopbackPairing = "CRAB_GATEWAY_ALLOW_INSECURE_LOOPBACK_PAIRING"
	EnvGatewayPairMTLSCAFile               = "CRAB_GATEWAY_PAIR_MTLS_CA_FILE"
	EnvGatewayPairMTLSCertFile             = "CRAB_GATEWAY_PAIR_MTLS_CERT_FILE"
	EnvGatewayPairMTLSKeyFile              = "CRAB_GATEWAY_PAIR_MTLS_KEY_FILE"
	EnvGatewayAgentsJSON                   = "CRAB_GATEWAY_AGENTS_JSON"
	EnvGatewayAnthropicAPIKey              = "ANTHROPIC_API_KEY"
	EnvGatewayOpenAIAPIKey                 = "OPENAI_API_KEY"
)

const (
	DefaultGatewayHTTPAddr                  = ":8080"
	DefaultGatewayDBDriver                  = "sqlite"
	DefaultGatewayDBDSN                     = "gateway.db"
	DefaultGatewayID                        = "gateway-core"
	DefaultGatewayKeyDir                    = ".crabstack/keys"
	DefaultGatewayAdminSocketPath           = ".crabstack/run/gateway-admin.sock"
	DefaultGatewayPairTimeout               = 15 * time.Second
	DefaultGatewayRequireMTLSRemote         = true
	DefaultGatewayAllowInsecureLoopbackPair = true
)

type GatewayConfig struct {
	HTTPAddr                     string
	DBDriver                     string
	DBDSN                        string
	GatewayID                    string
	KeyDir                       string
	AdminSocketPath              string
	PairTimeout                  time.Duration
	PairRequireMTLSRemote        bool
	PairAllowInsecureLoopback    bool
	PairMTLSCAFile               string
	PairMTLSClientCertFile       string
	PairMTLSClientPrivateKeyFile string
	Agents                       []GatewayAgentConfig
	AnthropicAPIKey              string
	OpenAIAPIKey                 string
	ClaudeCredentialsFile        string
	CodexCredentialsFile         string
	ClaudeAccessToken            string
	CodexAccessToken             string
	CodexAccountID               string
}

type GatewayAgentConfig struct {
	Name         string
	Model        string
	Channels     []string
	Users        []string
	WorkspaceDir string
}

func GatewayFromEnv() GatewayConfig {
	cfg := defaultGatewayConfig()
	applyGatewayEnv(&cfg)
	if err := loadGatewaySubscriptionCredentials(&cfg); err != nil {
		log.Printf("warn: failed loading gateway subscription credentials: %v", err)
	}
	return cfg
}

func GatewayFromYAMLAndEnv() (GatewayConfig, error) {
	cfg := defaultGatewayConfig()

	fileCfg, err := loadFileConfig()
	if err != nil {
		return GatewayConfig{}, err
	}
	if err := applyGatewayYAML(&cfg, fileCfg.Gateway); err != nil {
		return GatewayConfig{}, err
	}
	applyGatewayEnv(&cfg)
	if err := loadGatewaySubscriptionCredentials(&cfg); err != nil {
		return GatewayConfig{}, err
	}

	return cfg, nil
}

func defaultGatewayConfig() GatewayConfig {
	return GatewayConfig{
		HTTPAddr:                  DefaultGatewayHTTPAddr,
		DBDriver:                  DefaultGatewayDBDriver,
		DBDSN:                     DefaultGatewayDBDSN,
		GatewayID:                 DefaultGatewayID,
		KeyDir:                    ResolveCrabstackPath(DefaultGatewayKeyDir),
		AdminSocketPath:           ResolveCrabstackPath(DefaultGatewayAdminSocketPath),
		PairTimeout:               DefaultGatewayPairTimeout,
		PairRequireMTLSRemote:     DefaultGatewayRequireMTLSRemote,
		PairAllowInsecureLoopback: DefaultGatewayAllowInsecureLoopbackPair,
		ClaudeCredentialsFile:     DefaultCrabstackPath("auth", "claude.json"),
		CodexCredentialsFile:      DefaultCrabstackPath("auth", "codex.json"),
	}
}

func applyGatewayYAML(cfg *GatewayConfig, source fileGatewayConfig) error {
	if value := strings.TrimSpace(source.HTTPAddr); value != "" {
		cfg.HTTPAddr = value
	}
	if value := strings.TrimSpace(source.DBDriver); value != "" {
		cfg.DBDriver = strings.ToLower(value)
	}
	if value := strings.TrimSpace(source.DBDSN); value != "" {
		cfg.DBDSN = value
	}
	if value := strings.TrimSpace(source.GatewayID); value != "" {
		cfg.GatewayID = value
	}
	if value := strings.TrimSpace(source.KeyDir); value != "" {
		cfg.KeyDir = ResolveCrabstackPath(value)
	}
	if value := strings.TrimSpace(source.AdminSocketPath); value != "" {
		cfg.AdminSocketPath = ResolveCrabstackPath(value)
	}

	pairTimeout, err := parseOptionalDuration(source.PairTimeout, cfg.PairTimeout, "gateway.pair_timeout")
	if err != nil {
		return err
	}
	cfg.PairTimeout = pairTimeout

	if source.PairRequireMTLSRemote != nil {
		cfg.PairRequireMTLSRemote = *source.PairRequireMTLSRemote
	}
	if source.PairAllowInsecureLoopbackPairing != nil {
		cfg.PairAllowInsecureLoopback = *source.PairAllowInsecureLoopbackPairing
	}

	if value := strings.TrimSpace(source.PairMTLSCAFile); value != "" {
		cfg.PairMTLSCAFile = value
	}
	if value := strings.TrimSpace(source.PairMTLSClientCertFile); value != "" {
		cfg.PairMTLSClientCertFile = value
	}
	if value := strings.TrimSpace(source.PairMTLSClientPrivateKeyFile); value != "" {
		cfg.PairMTLSClientPrivateKeyFile = value
	}
	if len(source.Agents) > 0 {
		cfg.Agents = make([]GatewayAgentConfig, 0, len(source.Agents))
		for _, sourceAgent := range source.Agents {
			agent := GatewayAgentConfig{
				Name:         strings.TrimSpace(sourceAgent.Name),
				Model:        strings.TrimSpace(sourceAgent.Model),
				WorkspaceDir: strings.TrimSpace(sourceAgent.WorkspaceDir),
			}
			for _, channel := range sourceAgent.Channels {
				trimmed := strings.TrimSpace(channel)
				if trimmed == "" {
					continue
				}
				agent.Channels = append(agent.Channels, trimmed)
			}
			for _, user := range sourceAgent.Users {
				trimmed := strings.TrimSpace(user)
				if trimmed == "" {
					continue
				}
				agent.Users = append(agent.Users, trimmed)
			}
			cfg.Agents = append(cfg.Agents, agent)
		}
	}
	if value := strings.TrimSpace(source.AnthropicAPIKey); value != "" {
		cfg.AnthropicAPIKey = value
	}
	if value := strings.TrimSpace(source.OpenAIAPIKey); value != "" {
		cfg.OpenAIAPIKey = value
	}
	claudeCredentialsFile := source.Auth.ClaudeCredentialsFile
	if strings.TrimSpace(claudeCredentialsFile) == "" {
		claudeCredentialsFile = source.Auth.AnthropicCredentialsFile
	}
	if value := strings.TrimSpace(claudeCredentialsFile); value != "" {
		cfg.ClaudeCredentialsFile = ResolveCrabstackPath(value)
	}
	if value := strings.TrimSpace(source.Auth.CodexCredentialsFile); value != "" {
		cfg.CodexCredentialsFile = ResolveCrabstackPath(value)
	}

	return nil
}

func applyGatewayEnv(cfg *GatewayConfig) {
	cfg.HTTPAddr = EnvOrDefault(EnvGatewayHTTPAddr, cfg.HTTPAddr)
	cfg.DBDriver = strings.ToLower(EnvOrDefault(EnvGatewayDBDriver, cfg.DBDriver))
	cfg.DBDSN = EnvOrDefault(EnvGatewayDBDSN, cfg.DBDSN)
	cfg.GatewayID = EnvOrDefault(EnvGatewayID, cfg.GatewayID)
	cfg.KeyDir = ResolveCrabstackPath(EnvOrDefault(EnvGatewayKeyDir, cfg.KeyDir))
	cfg.AdminSocketPath = ResolveCrabstackPath(EnvOrDefault(EnvGatewayAdminSocketPath, cfg.AdminSocketPath))

	if raw := EnvString(EnvGatewayPairTimeout); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err == nil && parsed > 0 {
			cfg.PairTimeout = parsed
		}
	}
	cfg.PairRequireMTLSRemote = parseBoolEnv(EnvGatewayRequireMTLSRemote, cfg.PairRequireMTLSRemote)
	cfg.PairAllowInsecureLoopback = parseBoolEnv(EnvGatewayAllowInsecureLoopbackPairing, cfg.PairAllowInsecureLoopback)
	cfg.PairMTLSCAFile = EnvOrDefault(EnvGatewayPairMTLSCAFile, cfg.PairMTLSCAFile)
	cfg.PairMTLSClientCertFile = EnvOrDefault(EnvGatewayPairMTLSCertFile, cfg.PairMTLSClientCertFile)
	cfg.PairMTLSClientPrivateKeyFile = EnvOrDefault(EnvGatewayPairMTLSKeyFile, cfg.PairMTLSClientPrivateKeyFile)
	if raw := EnvString(EnvGatewayAgentsJSON); raw != "" {
		var envAgents []GatewayAgentConfig
		if err := json.Unmarshal([]byte(raw), &envAgents); err == nil {
			cfg.Agents = envAgents
		}
	}
	cfg.AnthropicAPIKey = EnvOrDefault(EnvGatewayAnthropicAPIKey, cfg.AnthropicAPIKey)
	cfg.OpenAIAPIKey = EnvOrDefault(EnvGatewayOpenAIAPIKey, cfg.OpenAIAPIKey)
}

type subscriptionCredentials struct {
	Provider    string            `json:"provider"`
	AccountID   string            `json:"account_id"`
	AccessToken string            `json:"access_token"`
	AccountMeta map[string]string `json:"account_meta,omitempty"`
}

func loadSubscriptionCredentials(path string) (subscriptionCredentials, error) {
	resolvedPath := ResolveCrabstackPath(path)
	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		return subscriptionCredentials{}, err
	}

	var creds subscriptionCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return subscriptionCredentials{}, fmt.Errorf("decode credentials file %s: %w", resolvedPath, err)
	}
	creds.AccessToken = strings.TrimSpace(creds.AccessToken)
	if creds.AccessToken == "" {
		return subscriptionCredentials{}, fmt.Errorf("credentials file %s has empty access_token", resolvedPath)
	}
	creds.AccountID = strings.TrimSpace(creds.AccountID)
	return creds, nil
}

func loadGatewaySubscriptionCredentials(cfg *GatewayConfig) error {
	if strings.TrimSpace(cfg.ClaudeAccessToken) == "" {
		claudeCreds, err := loadSubscriptionCredentials(cfg.ClaudeCredentialsFile)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else {
			cfg.ClaudeAccessToken = claudeCreds.AccessToken
		}
	}

	if strings.TrimSpace(cfg.CodexAccessToken) == "" {
		codexCreds, err := loadSubscriptionCredentials(cfg.CodexCredentialsFile)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		}
		cfg.CodexAccessToken = codexCreds.AccessToken
		if codexCreds.AccountID != "" {
			cfg.CodexAccountID = codexCreds.AccountID
		} else if accountID := strings.TrimSpace(codexCreds.AccountMeta["chatgpt_account_id"]); accountID != "" {
			cfg.CodexAccountID = accountID
		}
	}

	return nil
}

func (c GatewayConfig) Validate() error {
	if strings.TrimSpace(c.HTTPAddr) == "" {
		return fmt.Errorf("%s must not be empty", EnvGatewayHTTPAddr)
	}
	switch strings.ToLower(strings.TrimSpace(c.DBDriver)) {
	case "sqlite", "postgres":
	default:
		return fmt.Errorf("%s must be sqlite or postgres", EnvGatewayDBDriver)
	}
	if strings.TrimSpace(c.DBDSN) == "" {
		return fmt.Errorf("%s must not be empty", EnvGatewayDBDSN)
	}
	if strings.TrimSpace(c.GatewayID) == "" {
		return fmt.Errorf("%s must not be empty", EnvGatewayID)
	}
	if strings.TrimSpace(c.KeyDir) == "" {
		return fmt.Errorf("%s must not be empty", EnvGatewayKeyDir)
	}
	if strings.TrimSpace(c.AdminSocketPath) == "" {
		return fmt.Errorf("%s must not be empty", EnvGatewayAdminSocketPath)
	}
	if c.PairTimeout <= 0 {
		return fmt.Errorf("%s must be > 0", EnvGatewayPairTimeout)
	}
	seenAgentNames := make(map[string]struct{}, len(c.Agents))
	for index, agent := range c.Agents {
		name := strings.TrimSpace(agent.Name)
		if name == "" {
			return fmt.Errorf("gateway.agents[%d].name must not be empty", index)
		}
		model := strings.TrimSpace(agent.Model)
		if model == "" {
			return fmt.Errorf("gateway.agents[%d].model must not be empty", index)
		}
		providerName, modelName, ok := strings.Cut(model, "/")
		if !ok || strings.TrimSpace(providerName) == "" || strings.TrimSpace(modelName) == "" {
			return fmt.Errorf("gateway.agents[%d].model must use provider/model format", index)
		}
		normalizedName := strings.ToLower(name)
		if _, exists := seenAgentNames[normalizedName]; exists {
			return fmt.Errorf("gateway.agents contains duplicate name %q", name)
		}
		seenAgentNames[normalizedName] = struct{}{}
		for channelIndex, channel := range agent.Channels {
			if strings.TrimSpace(channel) == "" {
				return fmt.Errorf("gateway.agents[%d].channels[%d] must not be empty", index, channelIndex)
			}
		}
		for userIndex, user := range agent.Users {
			if strings.TrimSpace(user) == "" {
				return fmt.Errorf("gateway.agents[%d].users[%d] must not be empty", index, userIndex)
			}
		}
	}

	mtlsFieldsSet := 0
	if strings.TrimSpace(c.PairMTLSCAFile) != "" {
		mtlsFieldsSet++
	}
	if strings.TrimSpace(c.PairMTLSClientCertFile) != "" {
		mtlsFieldsSet++
	}
	if strings.TrimSpace(c.PairMTLSClientPrivateKeyFile) != "" {
		mtlsFieldsSet++
	}
	if mtlsFieldsSet > 0 && mtlsFieldsSet < 3 {
		return fmt.Errorf("%s, %s and %s must be provided together", EnvGatewayPairMTLSCAFile, EnvGatewayPairMTLSCertFile, EnvGatewayPairMTLSKeyFile)
	}

	return nil
}
