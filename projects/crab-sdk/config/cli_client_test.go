package config

import (
	"testing"

	"crabstack.local/projects/crab-sdk/types"
)

func TestCLIClientConfigValidate(t *testing.T) {
	valid := CLIClientConfig{
		GatewayWSURL:               "ws://127.0.0.1:8080/v1/pair",
		GatewayPublicKeyEd25519B64: "ZmFrZS1rZXk=",
		TenantID:                   "local",
		AgentID:                    "assistant",
		SessionID:                  "cli-123",
		ComponentID:                "cli-host",
		ComponentType:              types.ComponentTypeOperator,
		Platform:                   "cli",
		ChannelID:                  "terminal",
		ActorID:                    "operator",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}

	invalidType := valid
	invalidType.ComponentType = types.ComponentType("unknown")
	if err := invalidType.Validate(); err == nil {
		t.Fatalf("expected invalid component type error")
	}

	missingGateway := valid
	missingGateway.GatewayWSURL = ""
	if err := missingGateway.Validate(); err == nil {
		t.Fatalf("expected missing gateway url error")
	}
}
