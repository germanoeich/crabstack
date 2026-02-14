package model

import (
	"context"
	"testing"
)

type stubProvider struct{}

func (s *stubProvider) Complete(_ context.Context, _ CompletionRequest) (CompletionResponse, error) {
	return CompletionResponse{Content: "ok"}, nil
}

func TestRegistryRegisterAndGet(t *testing.T) {
	registry := NewRegistry()
	provider := &stubProvider{}

	registry.Register(" OpenAI ", provider)

	got, ok := registry.Get("openai")
	if !ok {
		t.Fatalf("expected provider to be found")
	}
	if got != provider {
		t.Fatalf("expected exact provider instance")
	}
}

func TestRegistryGetMissing(t *testing.T) {
	registry := NewRegistry()
	if _, ok := registry.Get("missing"); ok {
		t.Fatalf("expected missing provider")
	}
}

func TestRegistryRegisterIgnoresInvalidInput(t *testing.T) {
	registry := NewRegistry()
	registry.Register("", &stubProvider{})
	registry.Register("openai", nil)

	if _, ok := registry.Get("openai"); ok {
		t.Fatalf("expected no provider to be registered")
	}
}

func TestRegistryRegisterFactoryAndNew(t *testing.T) {
	registry := NewRegistry()
	expected := &stubProvider{}
	seenAPIKey := ""

	registry.RegisterFactory("anthropic", func(apiKey string) Provider {
		seenAPIKey = apiKey
		return expected
	})

	provider, ok := registry.New("Anthropic", "secret-key")
	if !ok {
		t.Fatalf("expected provider to be created from factory")
	}
	if provider != expected {
		t.Fatalf("expected factory-created provider")
	}
	if seenAPIKey != "secret-key" {
		t.Fatalf("expected api key to be forwarded to factory")
	}
}

func TestRegistryNewMissingFactory(t *testing.T) {
	registry := NewRegistry()
	if _, ok := registry.New("openai", "key"); ok {
		t.Fatalf("expected missing factory")
	}
}

func TestRegistryNewFactoryReturnsNil(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterFactory("openai", func(string) Provider { return nil })

	if _, ok := registry.New("openai", "key"); ok {
		t.Fatalf("expected false when factory returns nil provider")
	}
}
