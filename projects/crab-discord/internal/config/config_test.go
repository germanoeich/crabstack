package config

import "testing"

func TestFromEnvDefaults(t *testing.T) {
	t.Setenv("DISCORD_BOT_TOKEN", "")
	t.Setenv("CRAB_GATEWAY_HTTP_URL", "")
	t.Setenv("CRAB_DISCORD_TENANT_ID", "")
	t.Setenv("CRAB_DISCORD_AGENT_ID", "")
	t.Setenv("CRAB_DISCORD_CONSUMER_ADDR", "")

	cfg := FromEnv()
	if cfg.DiscordBotToken != "" {
		t.Fatalf("expected empty bot token by default, got %q", cfg.DiscordBotToken)
	}
	if cfg.GatewayHTTPURL != defaultGatewayHTTPURL {
		t.Fatalf("expected default gateway url %q, got %q", defaultGatewayHTTPURL, cfg.GatewayHTTPURL)
	}
	if cfg.TenantID != defaultTenantID {
		t.Fatalf("expected default tenant id %q, got %q", defaultTenantID, cfg.TenantID)
	}
	if cfg.AgentID != defaultAgentID {
		t.Fatalf("expected default agent id %q, got %q", defaultAgentID, cfg.AgentID)
	}
	if cfg.ConsumerAddr != defaultConsumerAddr {
		t.Fatalf("expected default consumer addr %q, got %q", defaultConsumerAddr, cfg.ConsumerAddr)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("DISCORD_BOT_TOKEN", " token ")
	t.Setenv("CRAB_GATEWAY_HTTP_URL", " http://gateway.internal:8081 ")
	t.Setenv("CRAB_DISCORD_TENANT_ID", " tenant-x ")
	t.Setenv("CRAB_DISCORD_AGENT_ID", " helper-bot ")
	t.Setenv("CRAB_DISCORD_CONSUMER_ADDR", " 127.0.0.1:8091 ")

	cfg := FromEnv()
	if cfg.DiscordBotToken != "token" {
		t.Fatalf("expected trimmed token override, got %q", cfg.DiscordBotToken)
	}
	if cfg.GatewayHTTPURL != "http://gateway.internal:8081" {
		t.Fatalf("expected gateway override, got %q", cfg.GatewayHTTPURL)
	}
	if cfg.TenantID != "tenant-x" {
		t.Fatalf("expected tenant override, got %q", cfg.TenantID)
	}
	if cfg.AgentID != "helper-bot" {
		t.Fatalf("expected agent override, got %q", cfg.AgentID)
	}
	if cfg.ConsumerAddr != "127.0.0.1:8091" {
		t.Fatalf("expected consumer addr override, got %q", cfg.ConsumerAddr)
	}
}

func TestConfigValidate(t *testing.T) {
	valid := Config{
		DiscordBotToken: "token",
		GatewayHTTPURL:  "http://127.0.0.1:8080",
		TenantID:        "tenant-a",
		AgentID:         "assistant",
		ConsumerAddr:    ":8090",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}

	if err := (Config{GatewayHTTPURL: "http://127.0.0.1:8080", TenantID: "tenant-a", AgentID: "assistant"}).Validate(); err == nil {
		t.Fatalf("expected missing token validation error")
	}
	if err := (Config{DiscordBotToken: "token", GatewayHTTPURL: "127.0.0.1:8080", TenantID: "tenant-a", AgentID: "assistant"}).Validate(); err == nil {
		t.Fatalf("expected invalid gateway url validation error")
	}
	if err := (Config{DiscordBotToken: "token", GatewayHTTPURL: "http://127.0.0.1:8080", TenantID: "", AgentID: "assistant"}).Validate(); err == nil {
		t.Fatalf("expected empty tenant validation error")
	}
	if err := (Config{DiscordBotToken: "token", GatewayHTTPURL: "http://127.0.0.1:8080", TenantID: "tenant-a", AgentID: ""}).Validate(); err == nil {
		t.Fatalf("expected empty agent validation error")
	}
	if err := (Config{DiscordBotToken: "token", GatewayHTTPURL: "http://127.0.0.1:8080", TenantID: "tenant-a", AgentID: "assistant", ConsumerAddr: ""}).Validate(); err == nil {
		t.Fatalf("expected empty consumer addr validation error")
	}
}
