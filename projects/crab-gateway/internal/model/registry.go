package model

import (
	"strings"
	"sync"
)

type ProviderFactory func(apiKey string) Provider

type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	factories map[string]ProviderFactory
}

func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		factories: make(map[string]ProviderFactory),
	}
}

func (r *Registry) Register(name string, provider Provider) {
	if r == nil || provider == nil {
		return
	}
	key := normalizeProviderName(name)
	if key == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[key] = provider
}

func (r *Registry) Get(name string) (Provider, bool) {
	if r == nil {
		return nil, false
	}
	key := normalizeProviderName(name)
	if key == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	provider, ok := r.providers[key]
	return provider, ok
}

func (r *Registry) RegisterFactory(name string, factory func(apiKey string) Provider) {
	if r == nil || factory == nil {
		return
	}
	key := normalizeProviderName(name)
	if key == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[key] = factory
}

func (r *Registry) New(name, apiKey string) (Provider, bool) {
	if r == nil {
		return nil, false
	}
	key := normalizeProviderName(name)
	if key == "" {
		return nil, false
	}

	r.mu.RLock()
	factory, ok := r.factories[key]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}

	provider := factory(apiKey)
	if provider == nil {
		return nil, false
	}
	return provider, true
}

func normalizeProviderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
