package config

import (
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

const (
	EnvCLIGatewayWSURL             = "CRAB_CLI_GATEWAY_WS_URL"
	EnvCLIGatewayHTTPURL           = "CRAB_CLI_GATEWAY_HTTP_URL"
	EnvCLIGatewayPublicKeyEd25519  = "CRAB_CLI_GATEWAY_PUBLIC_KEY_ED25519"
	EnvCLIAgentID                  = "CRAB_CLI_AGENT_ID"
	EnvCLIComponentType            = "CRAB_CLI_COMPONENT_TYPE"
	EnvCLIPairListenAddr           = "CRAB_CLI_PAIR_LISTEN_ADDR"
	EnvCLIPairListenPath           = "CRAB_CLI_PAIR_LISTEN_PATH"
	DefaultCLIGatewayWSURL         = "ws://127.0.0.1:8080/v1/pair"
	DefaultCLIGatewayHTTPURL       = "http://127.0.0.1:8080"
	DefaultCLITenantID             = "local"
	DefaultCLIAgentID              = "assistant"
	DefaultCLIComponentID          = "crab-cli"
	DefaultCLIComponentType        = string(types.ComponentTypeOperator)
	DefaultCLIPlatform             = "cli"
	DefaultCLIChannelID            = "terminal"
	DefaultCLIEventSendChannelID   = "cli"
	DefaultCLIActorID              = "operator"
	DefaultCLIPairTestComponentID  = "crab-cli-test"
	DefaultCLIPairListenAddress    = "127.0.0.1:0"
	DefaultCLIPairListenPath       = "/v1/pair"
	DefaultCLIPairTimeout          = 20 * time.Second
	DefaultCLIEventSendTimeout     = 10 * time.Second
	DefaultCLICodexAuthTimeout     = 60 * time.Second
	DefaultCLIAnthropicAuthTimeout = 60 * time.Second
	DefaultCLIClaudeAuthTimeout    = 60 * time.Second
	DefaultCLIClaudeMode           = "max"
)
