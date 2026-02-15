package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

const (
	defaultHTTPTimeout = 10 * time.Second
	maxErrorBodyBytes  = 1 << 20
)

type Option func(*WebhookSubscriber)

type WebhookSubscriber struct {
	name       string
	URL        string
	httpClient *http.Client
	logger     *log.Logger
	filter     func(types.EventType) bool
}

func New(name string, url string, logger *log.Logger, opts ...Option) *WebhookSubscriber {
	sub := &WebhookSubscriber{
		name:       strings.TrimSpace(name),
		URL:        strings.TrimSpace(url),
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
		logger:     logger,
	}
	if sub.name == "" {
		sub.name = "webhook"
	}
	for _, opt := range opts {
		if opt != nil {
			opt(sub)
		}
	}
	return sub
}

func WithHTTPClient(client *http.Client) Option {
	return func(s *WebhookSubscriber) {
		if client != nil {
			s.httpClient = client
		}
	}
}

func WithEventFilter(filter func(types.EventType) bool) Option {
	return func(s *WebhookSubscriber) {
		s.filter = filter
	}
}

func (s *WebhookSubscriber) Name() string {
	return s.name
}

func (s *WebhookSubscriber) Handle(ctx context.Context, event types.EventEnvelope) error {
	if s.filter != nil && !s.filter(event.EventType) {
		return nil
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}

	limited := io.LimitReader(resp.Body, maxErrorBodyBytes+1)
	errorBody, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("webhook status=%d read body: %w", resp.StatusCode, err)
	}
	truncated := ""
	if len(errorBody) > maxErrorBodyBytes {
		errorBody = errorBody[:maxErrorBodyBytes]
		truncated = " (truncated)"
	}
	return fmt.Errorf("webhook status=%d body=%q%s", resp.StatusCode, string(errorBody), truncated)
}
