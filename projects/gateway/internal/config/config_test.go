package config

import "testing"

func TestFromEnv_Default(t *testing.T) {
	t.Setenv("PINCHY_GATEWAY_HTTP_ADDR", "")
	t.Setenv("PINCHY_GATEWAY_DB_DRIVER", "")
	t.Setenv("PINCHY_GATEWAY_DB_DSN", "")
	t.Setenv("PINCHY_GATEWAY_ID", "")
	t.Setenv("PINCHY_GATEWAY_KEY_DIR", "")
	t.Setenv("PINCHY_GATEWAY_ADMIN_SOCKET_PATH", "")
	t.Setenv("PINCHY_GATEWAY_PAIR_TIMEOUT", "")
	t.Setenv("PINCHY_GATEWAY_REQUIRE_MTLS_REMOTE", "")
	t.Setenv("PINCHY_GATEWAY_ALLOW_INSECURE_LOOPBACK_PAIRING", "")
	t.Setenv("PINCHY_GATEWAY_PAIR_MTLS_CA_FILE", "")
	t.Setenv("PINCHY_GATEWAY_PAIR_MTLS_CERT_FILE", "")
	t.Setenv("PINCHY_GATEWAY_PAIR_MTLS_KEY_FILE", "")
	cfg := FromEnv()
	if cfg.HTTPAddr != defaultHTTPAddr {
		t.Fatalf("expected default addr %q, got %q", defaultHTTPAddr, cfg.HTTPAddr)
	}
	if cfg.DBDriver != defaultDBDriver {
		t.Fatalf("expected default db driver %q, got %q", defaultDBDriver, cfg.DBDriver)
	}
	if cfg.DBDSN != defaultDBDSN {
		t.Fatalf("expected default db dsn %q, got %q", defaultDBDSN, cfg.DBDSN)
	}
	if cfg.GatewayID != defaultGatewayID {
		t.Fatalf("expected default gateway id %q, got %q", defaultGatewayID, cfg.GatewayID)
	}
	if cfg.KeyDir != defaultKeyDir {
		t.Fatalf("expected default key dir %q, got %q", defaultKeyDir, cfg.KeyDir)
	}
	if cfg.AdminSocketPath != defaultAdminSocketPath {
		t.Fatalf("expected default admin socket path %q, got %q", defaultAdminSocketPath, cfg.AdminSocketPath)
	}
	if cfg.PairTimeout != defaultPairTimeout {
		t.Fatalf("expected default pair timeout %s, got %s", defaultPairTimeout, cfg.PairTimeout)
	}
	if cfg.PairRequireMTLSRemote != defaultRequireMTLSRemote {
		t.Fatalf("expected default require mtls %v, got %v", defaultRequireMTLSRemote, cfg.PairRequireMTLSRemote)
	}
	if cfg.PairAllowInsecureLoopback != defaultAllowLoopbackInsecure {
		t.Fatalf("expected default allow loopback %v, got %v", defaultAllowLoopbackInsecure, cfg.PairAllowInsecureLoopback)
	}
}

func TestFromEnv_Override(t *testing.T) {
	t.Setenv("PINCHY_GATEWAY_HTTP_ADDR", "127.0.0.1:9999")
	t.Setenv("PINCHY_GATEWAY_DB_DRIVER", "PoStGrEs")
	t.Setenv("PINCHY_GATEWAY_DB_DSN", "postgres://localhost/pinchy")
	t.Setenv("PINCHY_GATEWAY_ID", "gw_home")
	t.Setenv("PINCHY_GATEWAY_KEY_DIR", "/tmp/pinchy-keys")
	t.Setenv("PINCHY_GATEWAY_ADMIN_SOCKET_PATH", "/tmp/pinchy-admin.sock")
	t.Setenv("PINCHY_GATEWAY_PAIR_TIMEOUT", "45s")
	t.Setenv("PINCHY_GATEWAY_REQUIRE_MTLS_REMOTE", "false")
	t.Setenv("PINCHY_GATEWAY_ALLOW_INSECURE_LOOPBACK_PAIRING", "false")
	t.Setenv("PINCHY_GATEWAY_PAIR_MTLS_CA_FILE", "/tmp/ca.pem")
	t.Setenv("PINCHY_GATEWAY_PAIR_MTLS_CERT_FILE", "/tmp/client.crt")
	t.Setenv("PINCHY_GATEWAY_PAIR_MTLS_KEY_FILE", "/tmp/client.key")
	cfg := FromEnv()
	if cfg.HTTPAddr != "127.0.0.1:9999" {
		t.Fatalf("expected override addr, got %q", cfg.HTTPAddr)
	}
	if cfg.DBDriver != "postgres" {
		t.Fatalf("expected normalized db driver, got %q", cfg.DBDriver)
	}
	if cfg.DBDSN != "postgres://localhost/pinchy" {
		t.Fatalf("expected db dsn override, got %q", cfg.DBDSN)
	}
	if cfg.GatewayID != "gw_home" {
		t.Fatalf("expected gateway id override, got %q", cfg.GatewayID)
	}
	if cfg.KeyDir != "/tmp/pinchy-keys" {
		t.Fatalf("expected key dir override, got %q", cfg.KeyDir)
	}
	if cfg.AdminSocketPath != "/tmp/pinchy-admin.sock" {
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

func TestConfigValidate(t *testing.T) {
	base := Config{
		HTTPAddr:                  ":8080",
		DBDriver:                  "sqlite",
		DBDSN:                     "gateway.db",
		GatewayID:                 "gw",
		KeyDir:                    ".keys",
		AdminSocketPath:           ".pinchy/run/gateway-admin.sock",
		PairTimeout:               defaultPairTimeout,
		PairRequireMTLSRemote:     defaultRequireMTLSRemote,
		PairAllowInsecureLoopback: defaultAllowLoopbackInsecure,
	}

	if err := (Config{HTTPAddr: "", DBDriver: "sqlite", DBDSN: "gateway.db", GatewayID: "gw", KeyDir: ".keys", PairTimeout: defaultPairTimeout}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty addr")
	}

	if err := (Config{HTTPAddr: ":8080", DBDriver: "bad", DBDSN: "x", GatewayID: "gw", KeyDir: ".keys", PairTimeout: defaultPairTimeout}).Validate(); err == nil {
		t.Fatalf("expected validation error for bad db driver")
	}
	if err := (Config{HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "", GatewayID: "gw", KeyDir: ".keys", PairTimeout: defaultPairTimeout}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty db dsn")
	}
	if err := (Config{HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "x", GatewayID: "", KeyDir: ".keys", PairTimeout: defaultPairTimeout}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty gateway id")
	}
	if err := (Config{HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "x", GatewayID: "gw", KeyDir: "", PairTimeout: defaultPairTimeout}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty key dir")
	}
	if err := (Config{HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "x", GatewayID: "gw", KeyDir: ".keys", AdminSocketPath: "", PairTimeout: defaultPairTimeout}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty admin socket path")
	}
	if err := (Config{HTTPAddr: ":8080", DBDriver: "sqlite", DBDSN: "x", GatewayID: "gw", KeyDir: ".keys", PairTimeout: 0}).Validate(); err == nil {
		t.Fatalf("expected validation error for invalid pair timeout")
	}
	if err := (Config{
		HTTPAddr:               ":8080",
		DBDriver:               "sqlite",
		DBDSN:                  "x",
		GatewayID:              "gw",
		KeyDir:                 ".keys",
		AdminSocketPath:        ".pinchy/run/gateway-admin.sock",
		PairTimeout:            defaultPairTimeout,
		PairMTLSCAFile:         "/tmp/ca.pem",
		PairMTLSClientCertFile: "/tmp/client.crt",
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for partial mtls config")
	}

	if err := base.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if err := (Config{
		HTTPAddr:        ":8080",
		DBDriver:        "postgres",
		DBDSN:           "postgres://localhost/db",
		GatewayID:       "gw",
		KeyDir:          ".keys",
		AdminSocketPath: ".pinchy/run/gateway-admin.sock",
		PairTimeout:     defaultPairTimeout,
	}).Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
