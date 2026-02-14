package config

import (
	"fmt"
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
	AnthropicAPIKey              string
	OpenAIAPIKey                 string
}

func GatewayFromEnv() GatewayConfig {
	cfg := defaultGatewayConfig()
	applyGatewayEnv(&cfg)
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
	if value := strings.TrimSpace(source.AnthropicAPIKey); value != "" {
		cfg.AnthropicAPIKey = value
	}
	if value := strings.TrimSpace(source.OpenAIAPIKey); value != "" {
		cfg.OpenAIAPIKey = value
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
	cfg.AnthropicAPIKey = EnvOrDefault(EnvGatewayAnthropicAPIKey, cfg.AnthropicAPIKey)
	cfg.OpenAIAPIKey = EnvOrDefault(EnvGatewayOpenAIAPIKey, cfg.OpenAIAPIKey)
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
