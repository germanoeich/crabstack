package config

import "testing"

func TestFromEnvDefaults(t *testing.T) {
	t.Setenv("CRAB_GATEWAY_HTTP_URL", "")
	t.Setenv("CRAB_CRON_HTTP_ADDR", "")
	t.Setenv("CRAB_CRON_TENANT_ID", "")
	t.Setenv("CRAB_CRON_AGENT_ID", "")
	t.Setenv("CRAB_CRON_DB_PATH", "")

	cfg := FromEnv()
	if cfg.GatewayHTTPURL != defaultGatewayHTTPURL {
		t.Fatalf("expected default gateway url %q, got %q", defaultGatewayHTTPURL, cfg.GatewayHTTPURL)
	}
	if cfg.HTTPAddr != defaultHTTPAddr {
		t.Fatalf("expected default http addr %q, got %q", defaultHTTPAddr, cfg.HTTPAddr)
	}
	if cfg.TenantID != defaultTenantID {
		t.Fatalf("expected default tenant id %q, got %q", defaultTenantID, cfg.TenantID)
	}
	if cfg.AgentID != defaultAgentID {
		t.Fatalf("expected default agent id %q, got %q", defaultAgentID, cfg.AgentID)
	}
	if cfg.DBPath != defaultDBPath {
		t.Fatalf("expected default db path %q, got %q", defaultDBPath, cfg.DBPath)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("CRAB_GATEWAY_HTTP_URL", " http://gateway.internal:8081 ")
	t.Setenv("CRAB_CRON_HTTP_ADDR", " 127.0.0.1:8091 ")
	t.Setenv("CRAB_CRON_TENANT_ID", " tenant-x ")
	t.Setenv("CRAB_CRON_AGENT_ID", " helper-bot ")
	t.Setenv("CRAB_CRON_DB_PATH", " /tmp/cron.db ")

	cfg := FromEnv()
	if cfg.GatewayHTTPURL != "http://gateway.internal:8081" {
		t.Fatalf("expected gateway override, got %q", cfg.GatewayHTTPURL)
	}
	if cfg.HTTPAddr != "127.0.0.1:8091" {
		t.Fatalf("expected http addr override, got %q", cfg.HTTPAddr)
	}
	if cfg.TenantID != "tenant-x" {
		t.Fatalf("expected tenant override, got %q", cfg.TenantID)
	}
	if cfg.AgentID != "helper-bot" {
		t.Fatalf("expected agent override, got %q", cfg.AgentID)
	}
	if cfg.DBPath != "/tmp/cron.db" {
		t.Fatalf("expected db path override, got %q", cfg.DBPath)
	}
}

func TestConfigValidate(t *testing.T) {
	valid := Config{
		GatewayHTTPURL: "http://127.0.0.1:8080",
		HTTPAddr:       ":8091",
		TenantID:       "tenant-a",
		AgentID:        "assistant",
		DBPath:         "cron.db",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}

	if err := (Config{GatewayHTTPURL: "127.0.0.1:8080", HTTPAddr: ":8091", TenantID: "tenant-a", AgentID: "assistant", DBPath: "cron.db"}).Validate(); err == nil {
		t.Fatalf("expected invalid gateway url validation error")
	}
	if err := (Config{GatewayHTTPURL: "http://127.0.0.1:8080", HTTPAddr: "", TenantID: "tenant-a", AgentID: "assistant", DBPath: "cron.db"}).Validate(); err == nil {
		t.Fatalf("expected empty http addr validation error")
	}
	if err := (Config{GatewayHTTPURL: "http://127.0.0.1:8080", HTTPAddr: ":8091", TenantID: "", AgentID: "assistant", DBPath: "cron.db"}).Validate(); err == nil {
		t.Fatalf("expected empty tenant validation error")
	}
	if err := (Config{GatewayHTTPURL: "http://127.0.0.1:8080", HTTPAddr: ":8091", TenantID: "tenant-a", AgentID: "", DBPath: "cron.db"}).Validate(); err == nil {
		t.Fatalf("expected empty agent validation error")
	}
	if err := (Config{GatewayHTTPURL: "http://127.0.0.1:8080", HTTPAddr: ":8091", TenantID: "tenant-a", AgentID: "assistant", DBPath: ""}).Validate(); err == nil {
		t.Fatalf("expected empty db path validation error")
	}
}
