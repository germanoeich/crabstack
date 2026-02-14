package main

import (
	"fmt"
	"os"
	"strings"

	sdkconfig "crabstack.local/projects/crab-sdk/config"
	"crabstack.local/projects/crab-sdk/types"
)

type commandFlag struct {
	Name         string
	Description  string
	DefaultValue string
	EnvVar       string
}

type commandArg struct {
	Name        string
	Description string
	Required    bool
}

type commandSpec struct {
	Name        string
	Summary     string
	Usage       string
	Description string
	Flags       []commandFlag
	Args        []commandArg
	Subcommands []*commandSpec
	Run         func(args []string) error
}

type commandResolution struct {
	command   *commandSpec
	path      []string
	remaining []string
}

var crabCommandCatalog = buildCommandCatalog()

func buildCommandCatalog() *commandSpec {
	pairTool := &commandSpec{
		Name:    "tool",
		Summary: "Pair a tool host by endpoint + name",
		Usage:   "crab pair tool [--admin-socket <path>] [--timeout <duration>] <endpoint> <name>",
		Flags: []commandFlag{
			{Name: "admin-socket", Description: "Gateway admin unix socket path", DefaultValue: sdkconfig.DefaultGatewayAdminSocketPath, EnvVar: sdkconfig.EnvGatewayAdminSocketPath},
			{Name: "timeout", Description: "Pairing timeout", DefaultValue: sdkconfig.DefaultCLIPairTimeout.String()},
		},
		Args: []commandArg{
			{Name: "endpoint", Description: "Remote pair endpoint URL", Required: true},
			{Name: "name", Description: "Component ID", Required: true},
		},
		Run: func(args []string) error { return runPairTargetCommand("tool", types.ComponentTypeToolHost, args) },
	}

	pairSubscriber := &commandSpec{
		Name:    "subscriber",
		Summary: "Pair a subscriber by endpoint + name",
		Usage:   "crab pair subscriber [--admin-socket <path>] [--timeout <duration>] <endpoint> <name>",
		Flags: []commandFlag{
			{Name: "admin-socket", Description: "Gateway admin unix socket path", DefaultValue: sdkconfig.DefaultGatewayAdminSocketPath, EnvVar: sdkconfig.EnvGatewayAdminSocketPath},
			{Name: "timeout", Description: "Pairing timeout", DefaultValue: sdkconfig.DefaultCLIPairTimeout.String()},
		},
		Args: []commandArg{
			{Name: "endpoint", Description: "Remote pair endpoint URL", Required: true},
			{Name: "name", Description: "Component ID", Required: true},
		},
		Run: func(args []string) error {
			return runPairTargetCommand("subscriber", types.ComponentTypeSubscriber, args)
		},
	}

	pairCLI := &commandSpec{
		Name:    "cli",
		Summary: "Pair an operator CLI endpoint by endpoint + name",
		Usage:   "crab pair cli [--admin-socket <path>] [--timeout <duration>] <endpoint> <name>",
		Flags: []commandFlag{
			{Name: "admin-socket", Description: "Gateway admin unix socket path", DefaultValue: sdkconfig.DefaultGatewayAdminSocketPath, EnvVar: sdkconfig.EnvGatewayAdminSocketPath},
			{Name: "timeout", Description: "Pairing timeout", DefaultValue: sdkconfig.DefaultCLIPairTimeout.String()},
		},
		Args: []commandArg{
			{Name: "endpoint", Description: "Remote pair endpoint URL", Required: true},
			{Name: "name", Description: "Component ID", Required: true},
		},
		Run: func(args []string) error { return runPairTargetCommand("cli", types.ComponentTypeOperator, args) },
	}

	pairTest := &commandSpec{
		Name:    "test",
		Summary: "Run full pairing handshake test flow",
		Usage:   "crab pair test [--admin-socket <path>] [--gateway-public-key <base64>] [--component-id <id>] [--listen-addr <addr>] [--listen-path <path>] [--timeout <duration>]",
		Flags: []commandFlag{
			{Name: "admin-socket", Description: "Gateway admin unix socket path", DefaultValue: sdkconfig.DefaultGatewayAdminSocketPath, EnvVar: sdkconfig.EnvGatewayAdminSocketPath},
			{Name: "gateway-public-key", Description: "Trusted gateway ed25519 public key (base64)", EnvVar: sdkconfig.EnvCLIGatewayPublicKeyEd25519},
			{Name: "component-id", Description: "Component ID", DefaultValue: "<hostname|" + sdkconfig.DefaultCLIPairTestComponentID + ">"},
			{Name: "listen-addr", Description: "Local temporary pair listener address", DefaultValue: sdkconfig.DefaultCLIPairListenAddress, EnvVar: sdkconfig.EnvCLIPairListenAddr},
			{Name: "listen-path", Description: "Local temporary pair listener path", DefaultValue: sdkconfig.DefaultCLIPairListenPath, EnvVar: sdkconfig.EnvCLIPairListenPath},
			{Name: "timeout", Description: "Pairing timeout", DefaultValue: sdkconfig.DefaultCLIPairTimeout.String()},
		},
		Run: runPairTestCommand,
	}

	pair := &commandSpec{
		Name:        "pair",
		Summary:     "Gateway pairing commands",
		Usage:       "crab pair <test|tool|subscriber|cli> ...",
		Subcommands: []*commandSpec{pairTest, pairTool, pairSubscriber, pairCLI},
	}

	authCodex := &commandSpec{
		Name:    "codex",
		Summary: "Run Codex OAuth login",
		Usage:   "crab auth codex [--auth-file <path>] [--timeout <duration>]",
		Flags: []commandFlag{
			{Name: "auth-file", Description: "Output path for Codex credentials JSON", DefaultValue: "~/.crabstack/auth/codex.json"},
			{Name: "timeout", Description: "OAuth callback wait timeout", DefaultValue: sdkconfig.DefaultCLICodexAuthTimeout.String()},
		},
		Run: runAuthCodexCommand,
	}

	authClaude := &commandSpec{
		Name:    "claude",
		Summary: "Run Claude setup-token auth flow",
		Usage:   "crab auth claude [--auth-file <path>] [--mode <max|console>] [--timeout <duration>]",
		Flags: []commandFlag{
			{Name: "auth-file", Description: "Output path for Claude credentials JSON", DefaultValue: "~/.crabstack/auth/claude.json"},
			{Name: "mode", Description: "Auth mode label", DefaultValue: "max"},
			{Name: "timeout", Description: "Setup-token input timeout", DefaultValue: sdkconfig.DefaultCLIClaudeAuthTimeout.String()},
		},
		Run: runAuthClaudeCommand,
	}

	authAnthropic := &commandSpec{
		Name:    "anthropic",
		Summary: "Run Anthropic OAuth login",
		Usage:   "crab auth anthropic [--auth-file <path>] [--timeout <duration>]",
		Flags: []commandFlag{
			{Name: "auth-file", Description: "Output path for Anthropic credentials JSON", DefaultValue: "~/.crabstack/auth/anthropic.json"},
			{Name: "timeout", Description: "OAuth callback wait timeout", DefaultValue: sdkconfig.DefaultCLIAnthropicAuthTimeout.String()},
		},
		Run: runAuthAnthropicCommand,
	}

	auth := &commandSpec{
		Name:        "auth",
		Summary:     "Authentication flows",
		Usage:       "crab auth <codex|claude|anthropic> ...",
		Subcommands: []*commandSpec{authCodex, authClaude, authAnthropic},
	}

	eventSend := &commandSpec{
		Name:    "send",
		Summary: "Send one channel.message.received envelope",
		Usage:   "crab event send [flags] <text>",
		Flags: []commandFlag{
			{Name: "gateway-http", Description: "Gateway HTTP base URL", DefaultValue: sdkconfig.DefaultCLIGatewayHTTPURL, EnvVar: sdkconfig.EnvCLIGatewayHTTPURL},
			{Name: "tenant-id", Description: "Tenant ID", DefaultValue: sdkconfig.DefaultCLITenantID},
			{Name: "agent-id", Description: "Agent ID", DefaultValue: sdkconfig.DefaultCLIAgentID},
			{Name: "component-id", Description: "Component ID", DefaultValue: "<hostname|" + sdkconfig.DefaultCLIComponentID + ">"},
			{Name: "channel-id", Description: "Channel ID", DefaultValue: sdkconfig.DefaultCLIEventSendChannelID},
			{Name: "actor-id", Description: "Actor ID", DefaultValue: sdkconfig.DefaultCLIActorID},
			{Name: "timeout", Description: "Request timeout", DefaultValue: sdkconfig.DefaultCLIEventSendTimeout.String()},
		},
		Args: []commandArg{
			{Name: "text", Description: "Message text payload", Required: true},
		},
		Run: runEventSendCommand,
	}

	event := &commandSpec{
		Name:        "event",
		Summary:     "Event commands",
		Usage:       "crab event <send> ...",
		Subcommands: []*commandSpec{eventSend},
	}

	help := &commandSpec{
		Name:    "help",
		Summary: "Show command help",
		Usage:   "crab help [command ...]",
		Args: []commandArg{
			{Name: "command", Description: "Optional command path", Required: false},
		},
	}

	root := &commandSpec{
		Name:    "crab",
		Summary: "Crabstack CLI",
		Usage:   "crab [flags] | crab <command> [args]",
		Flags: []commandFlag{
			{Name: "gateway-ws", Description: "Gateway pairing websocket URL", DefaultValue: sdkconfig.DefaultCLIGatewayWSURL, EnvVar: sdkconfig.EnvCLIGatewayWSURL},
			{Name: "gateway-public-key", Description: "Trusted gateway ed25519 public key (base64)", EnvVar: sdkconfig.EnvCLIGatewayPublicKeyEd25519},
			{Name: "tenant-id", Description: "Tenant ID", DefaultValue: sdkconfig.DefaultCLITenantID},
			{Name: "agent-id", Description: "Agent ID", DefaultValue: sdkconfig.DefaultCLIAgentID, EnvVar: sdkconfig.EnvCLIAgentID},
			{Name: "session-id", Description: "Session ID", DefaultValue: "cli-<unix-ts>"},
			{Name: "component-id", Description: "Component ID", DefaultValue: "<hostname|" + sdkconfig.DefaultCLIComponentID + ">"},
			{Name: "component-type", Description: "Component type", DefaultValue: sdkconfig.DefaultCLIComponentType, EnvVar: sdkconfig.EnvCLIComponentType},
			{Name: "platform", Description: "Outbound source platform", DefaultValue: sdkconfig.DefaultCLIPlatform},
			{Name: "channel-id", Description: "Outbound source channel_id", DefaultValue: sdkconfig.DefaultCLIChannelID},
			{Name: "actor-id", Description: "Outbound source actor_id", DefaultValue: sdkconfig.DefaultCLIActorID},
		},
		Subcommands: []*commandSpec{pair, auth, event, help},
		Run:         runDefaultCLI,
	}
	help.Run = func(args []string) error {
		return runHelpCommandFor(root, args)
	}
	return root
}

func dispatchNamedSubcommand(root *commandSpec, name string, args []string) error {
	command := commandChild(root, name)
	if command == nil {
		return fmt.Errorf("internal command %q not registered", name)
	}
	return dispatchCommand(command, args)
}

func resolveCommand(root *commandSpec, args []string) commandResolution {
	current := root
	consumed := make([]string, 0, len(args))
	index := 0
	for index < len(args) {
		token := normalizeCommandToken(args[index])
		if token == "" {
			break
		}
		next := commandChild(current, token)
		if next == nil {
			break
		}
		current = next
		consumed = append(consumed, next.Name)
		index++
	}
	return commandResolution{
		command:   current,
		path:      consumed,
		remaining: args[index:],
	}
}

func dispatchCommand(root *commandSpec, args []string) error {
	return dispatchResolvedCommand(resolveCommand(root, args))
}

func dispatchResolvedCommand(resolution commandResolution) error {
	if resolution.command == nil {
		return fmt.Errorf("internal command resolution failed")
	}
	if resolution.command.Run != nil {
		return resolution.command.Run(resolution.remaining)
	}

	if len(resolution.remaining) == 0 {
		return fmt.Errorf("usage: %s", resolution.command.Usage)
	}

	token := normalizeCommandToken(resolution.remaining[0])
	if strings.HasPrefix(strings.TrimSpace(resolution.remaining[0]), "-") || token == "" {
		return fmt.Errorf("usage: %s", resolution.command.Usage)
	}

	return fmt.Errorf(
		"unsupported %s subcommand %q (supported: %s)",
		resolution.command.Name,
		token,
		supportedSubcommands(resolution.command),
	)
}

func runHelpCommand(args []string) error {
	return runHelpCommandFor(crabCommandCatalog, args)
}

func runHelpCommandFor(root *commandSpec, args []string) error {
	target, err := resolveHelpTargetFor(root, args)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprint(os.Stdout, formatCommandHelp(target))
	return nil
}

func resolveHelpTarget(args []string) (*commandSpec, error) {
	return resolveHelpTargetFor(crabCommandCatalog, args)
}

func resolveHelpTargetFor(root *commandSpec, args []string) (*commandSpec, error) {
	target := root
	path := make([]string, 0, len(args))
	for _, raw := range args {
		token := normalizeCommandToken(raw)
		if token == "" {
			continue
		}
		child := commandChild(target, token)
		if child == nil {
			path = append(path, token)
			return nil, fmt.Errorf("unknown command path %q", strings.Join(path, " "))
		}
		target = child
		path = append(path, child.Name)
	}
	return target, nil
}

func formatCommandHelp(command *commandSpec) string {
	var builder strings.Builder
	if command == nil {
		return ""
	}

	if strings.TrimSpace(command.Summary) != "" {
		builder.WriteString(command.Summary)
		builder.WriteString("\n")
	}

	if strings.TrimSpace(command.Usage) != "" {
		builder.WriteString("\nUsage:\n")
		builder.WriteString("  ")
		builder.WriteString(command.Usage)
		builder.WriteString("\n")
	}

	if strings.TrimSpace(command.Description) != "" {
		builder.WriteString("\n")
		builder.WriteString(strings.TrimSpace(command.Description))
		builder.WriteString("\n")
	}

	if len(command.Subcommands) > 0 {
		builder.WriteString("\nCommands:\n")
		for _, child := range command.Subcommands {
			builder.WriteString("  ")
			builder.WriteString(child.Name)
			if strings.TrimSpace(child.Summary) != "" {
				builder.WriteString("\t")
				builder.WriteString(child.Summary)
			}
			builder.WriteString("\n")
		}
	}

	if len(command.Flags) > 0 {
		builder.WriteString("\nFlags:\n")
		for _, flagInfo := range command.Flags {
			builder.WriteString("  --")
			builder.WriteString(flagInfo.Name)
			if strings.TrimSpace(flagInfo.Description) != "" {
				builder.WriteString("\t")
				builder.WriteString(flagInfo.Description)
			}
			if strings.TrimSpace(flagInfo.DefaultValue) != "" {
				builder.WriteString(" (default: ")
				builder.WriteString(flagInfo.DefaultValue)
				builder.WriteString(")")
			}
			if strings.TrimSpace(flagInfo.EnvVar) != "" {
				builder.WriteString(" (env: ")
				builder.WriteString(flagInfo.EnvVar)
				builder.WriteString(")")
			}
			builder.WriteString("\n")
		}
	}

	if len(command.Args) > 0 {
		builder.WriteString("\nArguments:\n")
		for _, arg := range command.Args {
			builder.WriteString("  ")
			builder.WriteString(arg.Name)
			builder.WriteString("\t")
			if arg.Required {
				builder.WriteString("required")
			} else {
				builder.WriteString("optional")
			}
			if strings.TrimSpace(arg.Description) != "" {
				builder.WriteString(" - ")
				builder.WriteString(arg.Description)
			}
			builder.WriteString("\n")
		}
	}

	return builder.String()
}

func commandChild(parent *commandSpec, token string) *commandSpec {
	if parent == nil {
		return nil
	}
	normalizedToken := normalizeCommandToken(token)
	if normalizedToken == "" {
		return nil
	}
	for _, child := range parent.Subcommands {
		if normalizeCommandToken(child.Name) == normalizedToken {
			return child
		}
	}
	return nil
}

func supportedSubcommands(command *commandSpec) string {
	if command == nil || len(command.Subcommands) == 0 {
		return ""
	}
	names := make([]string, 0, len(command.Subcommands))
	for _, child := range command.Subcommands {
		names = append(names, child.Name)
	}
	return strings.Join(names, ", ")
}

func normalizeCommandToken(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}
