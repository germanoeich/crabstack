package toolclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"crabstack.local/projects/crab-gateway/internal/model"
	"crabstack.local/projects/crab-sdk/types"
)

type HostConfig struct {
	Name    string
	BaseURL string
}

type Client struct {
	hosts      []HostConfig
	httpClient *http.Client
	logger     *log.Logger
	mu         sync.RWMutex
	toolRoutes map[string]string
	toolDefs   map[string]model.ToolDefinition
}

type Option func(*Client)

func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		if client != nil {
			c.httpClient = client
		}
	}
}

func New(logger *log.Logger, hosts []HostConfig, opts ...Option) *Client {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	c := &Client{
		hosts: normalizeHosts(hosts),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger:     logger,
		toolRoutes: make(map[string]string),
		toolDefs:   make(map[string]model.ToolDefinition),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

func (c *Client) Discover(ctx context.Context) error {
	routes := make(map[string]string)
	defs := make(map[string]model.ToolDefinition)

	for _, host := range c.hosts {
		if err := ctx.Err(); err != nil {
			return err
		}
		discoveryURL := host.BaseURL + "/v1/tools"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err != nil {
			c.logger.Printf("tool discovery warning host=%s err=%v", host.Name, err)
			continue
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.logger.Printf("tool discovery warning host=%s url=%s err=%v", host.Name, discoveryURL, err)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			message := strings.TrimSpace(string(body))
			if message == "" {
				message = http.StatusText(resp.StatusCode)
			}
			c.logger.Printf("tool discovery warning host=%s status=%d msg=%s", host.Name, resp.StatusCode, message)
			continue
		}

		var parsed types.ToolDiscoveryResponse
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed)
		_ = resp.Body.Close()
		if decodeErr != nil {
			c.logger.Printf("tool discovery warning host=%s err=decode response: %v", host.Name, decodeErr)
			continue
		}

		for _, tool := range parsed.Tools {
			name := strings.TrimSpace(tool.Name)
			if name == "" {
				continue
			}
			if prev, exists := routes[name]; exists && prev != host.BaseURL {
				c.logger.Printf("tool discovery warning duplicate tool=%s prev_host=%s host=%s", name, prev, host.BaseURL)
			}
			routes[name] = host.BaseURL
			defs[name] = model.ToolDefinition{
				Name:        name,
				Description: tool.Description,
				InputSchema: cloneRawMessage(tool.InputSchema),
			}
		}
	}

	c.mu.Lock()
	c.toolRoutes = routes
	c.toolDefs = defs
	c.mu.Unlock()
	return nil
}

func (c *Client) AvailableTools() []model.ToolDefinition {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tools := make([]model.ToolDefinition, 0, len(c.toolDefs))
	for _, tool := range c.toolDefs {
		tools = append(tools, model.ToolDefinition{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: cloneRawMessage(tool.InputSchema),
		})
	}
	sort.Slice(tools, func(i, j int) bool {
		return tools[i].Name < tools[j].Name
	})
	return tools
}

func (c *Client) Call(ctx context.Context, req types.ToolCallRequest) (types.ToolCallResponse, error) {
	toolName := strings.TrimSpace(req.ToolName)
	if toolName == "" {
		return types.ToolCallResponse{}, fmt.Errorf("tool_name is required")
	}

	c.mu.RLock()
	baseURL, ok := c.toolRoutes[toolName]
	c.mu.RUnlock()
	if !ok {
		return types.ToolCallResponse{}, fmt.Errorf("unknown tool: %s", toolName)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return types.ToolCallResponse{}, fmt.Errorf("marshal tool call request: %w", err)
	}

	callURL := baseURL + "/v1/tools/call"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, callURL, bytes.NewReader(body))
	if err != nil {
		return types.ToolCallResponse{}, fmt.Errorf("build tool call request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return types.ToolCallResponse{}, fmt.Errorf("call tool host: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		return types.ToolCallResponse{}, fmt.Errorf("tool host status %d: %s", resp.StatusCode, message)
	}

	var parsed types.ToolCallResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return types.ToolCallResponse{}, fmt.Errorf("decode tool call response: %w", err)
	}
	return parsed, nil
}

func normalizeHosts(hosts []HostConfig) []HostConfig {
	normalized := make([]HostConfig, 0, len(hosts))
	for _, host := range hosts {
		name := strings.TrimSpace(host.Name)
		baseURL := strings.TrimSpace(host.BaseURL)
		baseURL = strings.TrimSuffix(baseURL, "/")
		if baseURL == "" {
			continue
		}
		normalized = append(normalized, HostConfig{Name: name, BaseURL: baseURL})
	}
	return normalized
}

func cloneRawMessage(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	copied := make(json.RawMessage, len(raw))
	copy(copied, raw)
	return copied
}
