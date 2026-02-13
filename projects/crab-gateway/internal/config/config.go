package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const defaultHTTPAddr = ":8080"
const (
	defaultDBDriver              = "sqlite"
	defaultDBDSN                 = "gateway.db"
	defaultGatewayID             = "gateway-core"
	defaultKeyDir                = ".crabstack/keys"
	defaultAdminSocketPath       = ".crabstack/run/gateway-admin.sock"
	defaultPairTimeout           = 15 * time.Second
	defaultRequireMTLSRemote     = true
	defaultAllowLoopbackInsecure = true
)

type Config struct {
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
}

func FromEnv() Config {
	addr := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_HTTP_ADDR"))
	if addr == "" {
		addr = defaultHTTPAddr
	}

	driver := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_DB_DRIVER"))
	if driver == "" {
		driver = defaultDBDriver
	}
	dsn := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_DB_DSN"))
	if dsn == "" {
		dsn = defaultDBDSN
	}
	gatewayID := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_ID"))
	if gatewayID == "" {
		gatewayID = defaultGatewayID
	}
	keyDir := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_KEY_DIR"))
	if keyDir == "" {
		keyDir = defaultKeyDir
	}
	adminSocketPath := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_ADMIN_SOCKET_PATH"))
	if adminSocketPath == "" {
		adminSocketPath = defaultAdminSocketPath
	}
	pairTimeout := defaultPairTimeout
	if raw := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_PAIR_TIMEOUT")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err == nil && parsed > 0 {
			pairTimeout = parsed
		}
	}
	pairRequireMTLSRemote := parseBoolEnv("CRAB_GATEWAY_REQUIRE_MTLS_REMOTE", defaultRequireMTLSRemote)
	pairAllowInsecureLoopback := parseBoolEnv("CRAB_GATEWAY_ALLOW_INSECURE_LOOPBACK_PAIRING", defaultAllowLoopbackInsecure)

	return Config{
		HTTPAddr:                     addr,
		DBDriver:                     strings.ToLower(driver),
		DBDSN:                        dsn,
		GatewayID:                    gatewayID,
		KeyDir:                       keyDir,
		AdminSocketPath:              adminSocketPath,
		PairTimeout:                  pairTimeout,
		PairRequireMTLSRemote:        pairRequireMTLSRemote,
		PairAllowInsecureLoopback:    pairAllowInsecureLoopback,
		PairMTLSCAFile:               strings.TrimSpace(os.Getenv("CRAB_GATEWAY_PAIR_MTLS_CA_FILE")),
		PairMTLSClientCertFile:       strings.TrimSpace(os.Getenv("CRAB_GATEWAY_PAIR_MTLS_CERT_FILE")),
		PairMTLSClientPrivateKeyFile: strings.TrimSpace(os.Getenv("CRAB_GATEWAY_PAIR_MTLS_KEY_FILE")),
	}
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.HTTPAddr) == "" {
		return fmt.Errorf("CRAB_GATEWAY_HTTP_ADDR must not be empty")
	}
	switch strings.ToLower(strings.TrimSpace(c.DBDriver)) {
	case "sqlite", "postgres":
	default:
		return fmt.Errorf("CRAB_GATEWAY_DB_DRIVER must be sqlite or postgres")
	}
	if strings.TrimSpace(c.DBDSN) == "" {
		return fmt.Errorf("CRAB_GATEWAY_DB_DSN must not be empty")
	}
	if strings.TrimSpace(c.GatewayID) == "" {
		return fmt.Errorf("CRAB_GATEWAY_ID must not be empty")
	}
	if strings.TrimSpace(c.KeyDir) == "" {
		return fmt.Errorf("CRAB_GATEWAY_KEY_DIR must not be empty")
	}
	if strings.TrimSpace(c.AdminSocketPath) == "" {
		return fmt.Errorf("CRAB_GATEWAY_ADMIN_SOCKET_PATH must not be empty")
	}
	if c.PairTimeout <= 0 {
		return fmt.Errorf("CRAB_GATEWAY_PAIR_TIMEOUT must be > 0")
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
		return fmt.Errorf("CRAB_GATEWAY_PAIR_MTLS_CA_FILE, CRAB_GATEWAY_PAIR_MTLS_CERT_FILE and CRAB_GATEWAY_PAIR_MTLS_KEY_FILE must be provided together")
	}
	return nil
}

func parseBoolEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
