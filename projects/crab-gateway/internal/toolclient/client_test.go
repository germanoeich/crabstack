package toolclient

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"crabstack.local/projects/crab-sdk/types"
)

func TestDiscoverMultipleHostsWithDifferentTools(t *testing.T) {
	hostOne := newToolHostServer(t, []types.ToolDescriptor{
		{Name: "memory.append", Description: "append", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "memory.query", Description: "query", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}, nil)
	defer hostOne.Close()

	hostTwo := newToolHostServer(t, []types.ToolDescriptor{
		{Name: "cron.list", Description: "list", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}, nil)
	defer hostTwo.Close()

	client := New(log.New(io.Discard, "", 0), []HostConfig{
		{Name: "memory", BaseURL: hostOne.URL},
		{Name: "cron", BaseURL: hostTwo.URL},
	})

	if err := client.Discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}

	tools := client.AvailableTools()
	gotNames := make([]string, 0, len(tools))
	for _, tool := range tools {
		gotNames = append(gotNames, tool.Name)
	}
	wantNames := []string{"cron.list", "memory.append", "memory.query"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("unexpected tool names: got=%v want=%v", gotNames, wantNames)
	}
}

func TestDiscoverWithUnreachableHostContinues(t *testing.T) {
	reachable := newToolHostServer(t, []types.ToolDescriptor{
		{Name: "memory.append", Description: "append", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}, nil)
	defer reachable.Close()

	client := New(log.New(io.Discard, "", 0), []HostConfig{
		{Name: "memory", BaseURL: reachable.URL},
		{Name: "down", BaseURL: "http://127.0.0.1:1"},
	})

	if err := client.Discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}

	tools := client.AvailableTools()
	if len(tools) != 1 || tools[0].Name != "memory.append" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
}

func TestDiscoverOverlappingToolNamesLastHostWins(t *testing.T) {
	var oneCalls atomic.Int32
	var twoCalls atomic.Int32

	hostOne := newToolHostServer(t, []types.ToolDescriptor{
		{Name: "shared", Description: "host-one", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}, func(w http.ResponseWriter, req types.ToolCallRequest) {
		oneCalls.Add(1)
		_ = json.NewEncoder(w).Encode(types.ToolCallResponse{
			Version:  types.VersionV1,
			CallID:   req.CallID,
			ToolName: req.ToolName,
			Status:   types.ToolCallStatusOK,
		})
	})
	defer hostOne.Close()

	hostTwo := newToolHostServer(t, []types.ToolDescriptor{
		{Name: "shared", Description: "host-two", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}, func(w http.ResponseWriter, req types.ToolCallRequest) {
		twoCalls.Add(1)
		_ = json.NewEncoder(w).Encode(types.ToolCallResponse{
			Version:  types.VersionV1,
			CallID:   req.CallID,
			ToolName: req.ToolName,
			Status:   types.ToolCallStatusOK,
		})
	})
	defer hostTwo.Close()

	client := New(log.New(io.Discard, "", 0), []HostConfig{
		{Name: "one", BaseURL: hostOne.URL},
		{Name: "two", BaseURL: hostTwo.URL},
	})
	if err := client.Discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}

	tools := client.AvailableTools()
	if len(tools) != 1 {
		t.Fatalf("expected one tool, got %d", len(tools))
	}
	if tools[0].Description != "host-two" {
		t.Fatalf("expected host-two description, got %q", tools[0].Description)
	}

	_, err := client.Call(context.Background(), types.ToolCallRequest{
		Version:  types.VersionV1,
		CallID:   "call_1",
		ToolName: "shared",
		TenantID: "tenant_1",
		Args:     map[string]any{},
		Context:  types.ToolCallContext{AgentID: "agent", SessionID: "session"},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if oneCalls.Load() != 0 {
		t.Fatalf("expected first host not to receive call")
	}
	if twoCalls.Load() != 1 {
		t.Fatalf("expected second host to receive one call, got %d", twoCalls.Load())
	}
}

func TestCallKnownToolSuccess(t *testing.T) {
	server := newToolHostServer(t, []types.ToolDescriptor{
		{Name: "memory.query", Description: "query", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}, func(w http.ResponseWriter, req types.ToolCallRequest) {
		if req.ToolName != "memory.query" {
			t.Fatalf("unexpected tool name: %s", req.ToolName)
		}
		_ = json.NewEncoder(w).Encode(types.ToolCallResponse{
			Version:  types.VersionV1,
			CallID:   req.CallID,
			ToolName: req.ToolName,
			Status:   types.ToolCallStatusOK,
			Result:   map[string]any{"value": "ok"},
		})
	})
	defer server.Close()

	client := New(log.New(io.Discard, "", 0), []HostConfig{{Name: "memory", BaseURL: server.URL}})
	if err := client.Discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}

	resp, err := client.Call(context.Background(), types.ToolCallRequest{
		Version:  types.VersionV1,
		CallID:   "call_1",
		ToolName: "memory.query",
		TenantID: "tenant_1",
		Args:     map[string]any{"q": "x"},
		Context:  types.ToolCallContext{AgentID: "agent", SessionID: "session"},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if resp.Status != types.ToolCallStatusOK {
		t.Fatalf("unexpected status: %s", resp.Status)
	}
	if got, _ := resp.Result["value"].(string); got != "ok" {
		t.Fatalf("unexpected result: %+v", resp.Result)
	}
}

func TestCallKnownToolErrorStatus(t *testing.T) {
	server := newToolHostServer(t, []types.ToolDescriptor{{Name: "memory.query"}}, func(w http.ResponseWriter, _ types.ToolCallRequest) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("tool backend unavailable"))
	})
	defer server.Close()

	client := New(log.New(io.Discard, "", 0), []HostConfig{{Name: "memory", BaseURL: server.URL}})
	if err := client.Discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}

	_, err := client.Call(context.Background(), types.ToolCallRequest{
		Version:  types.VersionV1,
		CallID:   "call_1",
		ToolName: "memory.query",
		TenantID: "tenant_1",
		Args:     map[string]any{},
		Context:  types.ToolCallContext{AgentID: "agent", SessionID: "session"},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCallUnknownToolError(t *testing.T) {
	client := New(log.New(io.Discard, "", 0), nil)

	_, err := client.Call(context.Background(), types.ToolCallRequest{
		Version:  types.VersionV1,
		CallID:   "call_1",
		ToolName: "missing.tool",
		TenantID: "tenant_1",
		Args:     map[string]any{},
		Context:  types.ToolCallContext{AgentID: "agent", SessionID: "session"},
	})
	if err == nil {
		t.Fatalf("expected unknown tool error")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAvailableToolsReturnsExpectedDefinitionFormat(t *testing.T) {
	server := newToolHostServer(t, []types.ToolDescriptor{
		{
			Name:        "memory.append",
			Description: "Append memory",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}}}`),
		},
	}, nil)
	defer server.Close()

	client := New(log.New(io.Discard, "", 0), []HostConfig{{Name: "memory", BaseURL: server.URL}})
	if err := client.Discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}

	tools := client.AvailableTools()
	if len(tools) != 1 {
		t.Fatalf("expected one tool, got %d", len(tools))
	}
	if tools[0].Name != "memory.append" || tools[0].Description != "Append memory" {
		t.Fatalf("unexpected tool definition: %+v", tools[0])
	}
	if string(tools[0].InputSchema) != `{"type":"object","properties":{"text":{"type":"string"}}}` {
		t.Fatalf("unexpected input schema: %s", string(tools[0].InputSchema))
	}
}

func newToolHostServer(t *testing.T, tools []types.ToolDescriptor, onCall func(http.ResponseWriter, types.ToolCallRequest)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tools":
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(types.ToolDiscoveryResponse{
				Version: types.VersionV1,
				Service: "test-service",
				Tools:   tools,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tools/call":
			if onCall == nil {
				t.Fatalf("unexpected call request")
			}
			var req types.ToolCallRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode call request: %v", err)
			}
			onCall(w, req)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}
