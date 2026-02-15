package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	defaultGatewayHTTPURL = "http://127.0.0.1:8080"
	defaultHTTPAddr       = ":8091"
	defaultTenantID       = "default"
	defaultAgentID        = "assistant"
	defaultDBPath         = "cron.db"
)

type Config struct {
	GatewayHTTPURL string
	HTTPAddr       string
	TenantID       string
	AgentID        string
	DBPath         string
}

func FromEnv() Config {
	gatewayHTTPURL := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_HTTP_URL"))
	if gatewayHTTPURL == "" {
		gatewayHTTPURL = defaultGatewayHTTPURL
	}

	httpAddr := strings.TrimSpace(os.Getenv("CRAB_CRON_HTTP_ADDR"))
	if httpAddr == "" {
		httpAddr = defaultHTTPAddr
	}

	tenantID := strings.TrimSpace(os.Getenv("CRAB_CRON_TENANT_ID"))
	if tenantID == "" {
		tenantID = defaultTenantID
	}

	agentID := strings.TrimSpace(os.Getenv("CRAB_CRON_AGENT_ID"))
	if agentID == "" {
		agentID = defaultAgentID
	}

	dbPath := strings.TrimSpace(os.Getenv("CRAB_CRON_DB_PATH"))
	if dbPath == "" {
		dbPath = defaultDBPath
	}

	return Config{
		GatewayHTTPURL: gatewayHTTPURL,
		HTTPAddr:       httpAddr,
		TenantID:       tenantID,
		AgentID:        agentID,
		DBPath:         dbPath,
	}
}

func (c Config) Validate() error {
	if err := validateGatewayURL(c.GatewayHTTPURL); err != nil {
		return err
	}
	if strings.TrimSpace(c.HTTPAddr) == "" {
		return fmt.Errorf("CRAB_CRON_HTTP_ADDR must not be empty")
	}
	if strings.TrimSpace(c.TenantID) == "" {
		return fmt.Errorf("CRAB_CRON_TENANT_ID must not be empty")
	}
	if strings.TrimSpace(c.AgentID) == "" {
		return fmt.Errorf("CRAB_CRON_AGENT_ID must not be empty")
	}
	if strings.TrimSpace(c.DBPath) == "" {
		return fmt.Errorf("CRAB_CRON_DB_PATH must not be empty")
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
