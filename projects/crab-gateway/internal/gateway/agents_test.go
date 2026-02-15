package gateway

import "testing"

func TestCompileAgentConfigsRejectsInvalidModel(t *testing.T) {
	_, _, err := compileAgentConfigs([]AgentConfig{
		{Name: "assistant", Model: "anthropic"},
	})
	if err == nil {
		t.Fatalf("expected invalid model error")
	}
}

func TestCompileAgentConfigsRejectsInvalidChannelSelector(t *testing.T) {
	_, _, err := compileAgentConfigs([]AgentConfig{
		{
			Name:     "assistant",
			Model:    "anthropic/claude-sonnet-4-20250514",
			Channels: []string{"email"},
		},
	})
	if err == nil {
		t.Fatalf("expected invalid channel selector error")
	}
}

func TestCompileAgentConfigsBuildsLookupByName(t *testing.T) {
	compiled, byName, err := compileAgentConfigs([]AgentConfig{
		{
			Name:         "Assistant",
			Model:        "openai/gpt-4o-mini",
			Channels:     []string{"discord:ops"},
			Users:        []string{"user-1"},
			WorkspaceDir: "/srv/workspaces/assistant",
		},
	})
	if err != nil {
		t.Fatalf("compile agents: %v", err)
	}
	if len(compiled) != 1 {
		t.Fatalf("expected one agent, got %d", len(compiled))
	}
	index, ok := byName["assistant"]
	if !ok {
		t.Fatalf("expected normalized name lookup")
	}
	if index != 0 {
		t.Fatalf("expected lookup index 0, got %d", index)
	}
	if compiled[0].providerName != "openai" || compiled[0].modelName != "gpt-4o-mini" {
		t.Fatalf("unexpected provider/model: %s/%s", compiled[0].providerName, compiled[0].modelName)
	}
	if compiled[0].workspaceDir != "/srv/workspaces/assistant" {
		t.Fatalf("unexpected workspace_dir %q", compiled[0].workspaceDir)
	}
}
