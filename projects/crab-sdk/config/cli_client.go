package config

import (
	"fmt"
	"strings"

	"crabstack.local/projects/crab-sdk/types"
)

type CLIClientConfig struct {
	GatewayWSURL               string
	GatewayPublicKeyEd25519B64 string
	TenantID                   string
	AgentID                    string
	SessionID                  string
	ComponentID                string
	ComponentType              types.ComponentType
	Platform                   string
	ChannelID                  string
	ActorID                    string
}

func (c CLIClientConfig) Validate() error {
	if strings.TrimSpace(c.GatewayWSURL) == "" {
		return fmt.Errorf("gateway ws url is required")
	}
	if strings.TrimSpace(c.GatewayPublicKeyEd25519B64) == "" {
		return fmt.Errorf("gateway public key is required")
	}
	if strings.TrimSpace(c.TenantID) == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if strings.TrimSpace(c.AgentID) == "" {
		return fmt.Errorf("agent_id is required")
	}
	if strings.TrimSpace(c.SessionID) == "" {
		return fmt.Errorf("session_id is required")
	}
	if strings.TrimSpace(c.ComponentID) == "" {
		return fmt.Errorf("component_id is required")
	}
	switch c.ComponentType {
	case types.ComponentTypeListener,
		types.ComponentTypeSubscriber,
		types.ComponentTypeToolHost,
		types.ComponentTypeProvider,
		types.ComponentTypeOperator:
	default:
		return fmt.Errorf("unsupported component_type %q", c.ComponentType)
	}
	return nil
}
