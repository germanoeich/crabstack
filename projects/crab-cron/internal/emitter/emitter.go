package emitter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

const postTimeout = 10 * time.Second

type HTTPEventEmitter struct {
	httpClient *http.Client
	eventsURL  string
}

func NewHTTPEventEmitter(gatewayHTTPURL string, httpClient *http.Client) *HTTPEventEmitter {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: postTimeout}
	}
	return &HTTPEventEmitter{
		httpClient: httpClient,
		eventsURL:  eventsEndpoint(gatewayHTTPURL),
	}
}

func (e *HTTPEventEmitter) EmitEvent(ctx context.Context, envelope types.EventEnvelope) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal event envelope: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.eventsURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if readErr != nil {
			return fmt.Errorf("gateway returned %s", resp.Status)
		}
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("gateway returned %s: %s", resp.Status, msg)
	}

	return nil
}

func eventsEndpoint(gatewayHTTPURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(gatewayHTTPURL))
	if err != nil {
		return strings.TrimRight(strings.TrimSpace(gatewayHTTPURL), "/") + "/v1/events"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	trimmed := strings.TrimSpace(parsed.Path)
	if trimmed == "" || trimmed == "/" {
		parsed.Path = "/v1/events"
		return parsed.String()
	}
	parsed.Path = strings.TrimRight(trimmed, "/") + "/v1/events"
	return parsed.String()
}
