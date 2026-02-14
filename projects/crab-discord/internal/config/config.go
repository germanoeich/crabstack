package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	defaultGatewayHTTPURL = "http://127.0.0.1:8080"
	defaultTenantID       = "default"
	defaultAgentID        = "assistant"
)

type Config struct {
	DiscordBotToken string
	GatewayHTTPURL  string
	TenantID        string
	AgentID         string
}

func FromEnv() Config {
	gatewayHTTPURL := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_HTTP_URL"))
	if gatewayHTTPURL == "" {
		gatewayHTTPURL = defaultGatewayHTTPURL
	}

	tenantID := strings.TrimSpace(os.Getenv("CRAB_DISCORD_TENANT_ID"))
	if tenantID == "" {
		tenantID = defaultTenantID
	}

	agentID := strings.TrimSpace(os.Getenv("CRAB_DISCORD_AGENT_ID"))
	if agentID == "" {
		agentID = defaultAgentID
	}

	return Config{
		DiscordBotToken: strings.TrimSpace(os.Getenv("DISCORD_BOT_TOKEN")),
		GatewayHTTPURL:  gatewayHTTPURL,
		TenantID:        tenantID,
		AgentID:         agentID,
	}
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.DiscordBotToken) == "" {
		return fmt.Errorf("DISCORD_BOT_TOKEN is required")
	}
	if err := validateGatewayURL(c.GatewayHTTPURL); err != nil {
		return err
	}
	if strings.TrimSpace(c.TenantID) == "" {
		return fmt.Errorf("CRAB_DISCORD_TENANT_ID must not be empty")
	}
	if strings.TrimSpace(c.AgentID) == "" {
		return fmt.Errorf("CRAB_DISCORD_AGENT_ID must not be empty")
	}
	return nil
}

func validateGatewayURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("CRAB_GATEWAY_HTTP_URL is invalid: %w", err)
	}
	if strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("CRAB_GATEWAY_HTTP_URL must include scheme and host")
	}
	return nil
}
