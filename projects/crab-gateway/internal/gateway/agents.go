package gateway

import (
	"fmt"
	"strings"

	"crabstack.local/projects/crab-sdk/types"
)

type AgentConfig struct {
	Name         string
	Model        string
	Channels     []string
	Users        []string
	WorkspaceDir string
}

type runtimeAgentConfig struct {
	name         string
	providerName string
	modelName    string
	channels     []channelSelector
	users        map[string]struct{}
	workspaceDir string
}

type channelSelector struct {
	platform  string
	channelID string
	threadID  string
	address   string
}

func (s *Service) SetAgents(configs []AgentConfig) error {
	compiled, byName, err := compileAgentConfigs(configs)
	if err != nil {
		return err
	}
	s.agents = compiled
	s.agentIndexByName = byName
	return nil
}

func (s *Service) resolveAgentForEvent(event types.EventEnvelope, preferredName string) (*runtimeAgentConfig, error) {
	if len(s.agents) == 0 {
		return nil, nil
	}

	preferredKey := normalizeAgentName(preferredName)
	if preferredKey != "" {
		if index, ok := s.agentIndexByName[preferredKey]; ok {
			agent := s.agents[index]
			if !agent.matchesEvent(event) {
				return nil, fmt.Errorf("agent %q does not match event context", agent.name)
			}
			return &agent, nil
		}
	}

	for _, agent := range s.agents {
		if agent.matchesEvent(event) {
			return &agent, nil
		}
	}

	return nil, fmt.Errorf(
		"no matching agent for platform=%q channel_id=%q actor_id=%q",
		strings.TrimSpace(event.Source.Platform),
		strings.TrimSpace(event.Source.ChannelID),
		strings.TrimSpace(event.Source.ActorID),
	)
}

func (s *Service) resolveExecutionTarget(event types.EventEnvelope, sessionAgentID string) (executionTarget, error) {
	if len(s.agents) == 0 {
		return executionTarget{
			providerName:          strings.TrimSpace(sessionAgentID),
			modelName:             defaultModelName,
			allowProviderFallback: true,
		}, nil
	}

	agent, err := s.resolveAgentForEvent(event, sessionAgentID)
	if err != nil {
		return executionTarget{}, err
	}
	if agent == nil {
		return executionTarget{}, fmt.Errorf("agent resolution failed")
	}

	return executionTarget{
		agentName:             agent.name,
		providerName:          agent.providerName,
		modelName:             agent.modelName,
		workspaceDir:          agent.workspaceDir,
		allowProviderFallback: false,
	}, nil
}

func (a runtimeAgentConfig) matchesEvent(event types.EventEnvelope) bool {
	if len(a.channels) > 0 {
		matched := false
		for _, selector := range a.channels {
			if selector.matchesEvent(event) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(a.users) > 0 {
		actorID := strings.TrimSpace(event.Source.ActorID)
		if actorID == "" {
			return false
		}
		if _, ok := a.users[actorID]; !ok {
			return false
		}
	}

	return true
}

func (s channelSelector) matchesEvent(event types.EventEnvelope) bool {
	platform := strings.ToLower(strings.TrimSpace(event.Source.Platform))
	if platform == "" && event.Routing.Target != nil {
		platform = strings.ToLower(strings.TrimSpace(event.Routing.Target.Platform))
	}
	if platform != s.platform {
		return false
	}

	if s.channelID != "" {
		channelID := strings.TrimSpace(event.Source.ChannelID)
		if channelID == "" && event.Routing.Target != nil {
			channelID = strings.TrimSpace(event.Routing.Target.ChannelID)
		}
		if channelID != s.channelID {
			return false
		}
	}

	if s.threadID != "" {
		threadID := ""
		if event.Routing.Target != nil {
			threadID = strings.TrimSpace(event.Routing.Target.ThreadID)
		}
		if threadID != s.threadID {
			return false
		}
	}

	if s.address != "" {
		address := ""
		if event.Routing.Target != nil {
			address = strings.TrimSpace(event.Routing.Target.Address)
		}
		if address != s.address {
			return false
		}
	}

	return true
}

func compileAgentConfigs(configs []AgentConfig) ([]runtimeAgentConfig, map[string]int, error) {
	compiled := make([]runtimeAgentConfig, 0, len(configs))
	byName := make(map[string]int, len(configs))

	for index, cfg := range configs {
		name := strings.TrimSpace(cfg.Name)
		if name == "" {
			return nil, nil, fmt.Errorf("agents[%d].name must not be empty", index)
		}
		nameKey := normalizeAgentName(name)
		if _, exists := byName[nameKey]; exists {
			return nil, nil, fmt.Errorf("duplicate agent name %q", name)
		}

		providerName, modelName, err := parseProviderModel(cfg.Model)
		if err != nil {
			return nil, nil, fmt.Errorf("agents[%d].model: %w", index, err)
		}

		agent := runtimeAgentConfig{
			name:         name,
			providerName: providerName,
			modelName:    modelName,
			workspaceDir: strings.TrimSpace(cfg.WorkspaceDir),
		}

		for channelIndex, rawChannel := range cfg.Channels {
			selector, err := parseChannelSelector(rawChannel)
			if err != nil {
				return nil, nil, fmt.Errorf("agents[%d].channels[%d]: %w", index, channelIndex, err)
			}
			agent.channels = append(agent.channels, selector)
		}

		if len(cfg.Users) > 0 {
			agent.users = make(map[string]struct{}, len(cfg.Users))
			for userIndex, rawUser := range cfg.Users {
				userID := strings.TrimSpace(rawUser)
				if userID == "" {
					return nil, nil, fmt.Errorf("agents[%d].users[%d] must not be empty", index, userIndex)
				}
				agent.users[userID] = struct{}{}
			}
		}

		byName[nameKey] = len(compiled)
		compiled = append(compiled, agent)
	}

	return compiled, byName, nil
}

func parseProviderModel(raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", fmt.Errorf("value is required")
	}
	providerName, modelName, ok := strings.Cut(value, "/")
	providerName = strings.ToLower(strings.TrimSpace(providerName))
	modelName = strings.TrimSpace(modelName)
	if !ok || providerName == "" || modelName == "" {
		return "", "", fmt.Errorf("must use provider/model format")
	}
	return providerName, modelName, nil
}

func parseChannelSelector(raw string) (channelSelector, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return channelSelector{}, fmt.Errorf("value must not be empty")
	}

	parts := strings.Split(value, ":")
	if len(parts) > 4 {
		return channelSelector{}, fmt.Errorf("must use platform[:channel_id[:thread_id[:address]]] format")
	}

	platform := strings.ToLower(strings.TrimSpace(parts[0]))
	switch platform {
	case "discord", "whatsapp", "telegram":
	default:
		return channelSelector{}, fmt.Errorf("unsupported platform %q", platform)
	}

	selector := channelSelector{platform: platform}
	if len(parts) > 1 {
		selector.channelID = strings.TrimSpace(parts[1])
		if selector.channelID == "" {
			return channelSelector{}, fmt.Errorf("channel_id section must not be empty")
		}
	}
	if len(parts) > 2 {
		selector.threadID = strings.TrimSpace(parts[2])
		if selector.threadID == "" {
			return channelSelector{}, fmt.Errorf("thread_id section must not be empty")
		}
	}
	if len(parts) > 3 {
		selector.address = strings.TrimSpace(parts[3])
		if selector.address == "" {
			return channelSelector{}, fmt.Errorf("address section must not be empty")
		}
	}

	return selector, nil
}

func normalizeAgentName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
