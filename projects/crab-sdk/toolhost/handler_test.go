package toolhost

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdktypes "crabstack.local/projects/crab-sdk/types"
)

func TestToolsDiscovery(t *testing.T) {
	server := newTestServer(t, echoHandler{})
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/tools")
	if err != nil {
		t.Fatalf("get tools discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code got=%d want=%d", resp.StatusCode, http.StatusOK)
	}

	var discovery DiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("decode discovery response: %v", err)
	}

	if discovery.Version != sdktypes.VersionV1 {
		t.Fatalf("discovery version got=%q want=%q", discovery.Version, sdktypes.VersionV1)
	}
	if discovery.Service != "test-service" {
		t.Fatalf("discovery service got=%q want=%q", discovery.Service, "test-service")
	}
	if len(discovery.Tools) != 1 {
		t.Fatalf("discovery tools length got=%d want=1", len(discovery.Tools))
	}
	if discovery.Tools[0].Name != "echo" {
		t.Fatalf("discovery tool name got=%q want=%q", discovery.Tools[0].Name, "echo")
	}
}

func TestToolCallValidRequest(t *testing.T) {
	server := newTestServer(t, echoHandler{})
	defer server.Close()

	status, body := postCall(t, server.URL, validRequest("echo"))
	if status != http.StatusOK {
		t.Fatalf("status code got=%d want=%d body=%s", status, http.StatusOK, string(body))
	}

	var resp ToolCallResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode tool call response: %v", err)
	}
	if resp.Status != ToolCallStatusOK {
		t.Fatalf("status got=%q want=%q", resp.Status, ToolCallStatusOK)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode result payload: %v", err)
	}
	if result["value"] != "hello" {
		t.Fatalf("result value got=%v want=%q", result["value"], "hello")
	}
}

func TestToolCallUnknownTool(t *testing.T) {
	server := newTestServer(t, echoHandler{})
	defer server.Close()

	status, body := postCall(t, server.URL, validRequest("missing.tool"))
	if status != http.StatusOK {
		t.Fatalf("status code got=%d want=%d body=%s", status, http.StatusOK, string(body))
	}

	var resp ToolCallResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode tool call response: %v", err)
	}
	if resp.Status != ToolCallStatusError {
		t.Fatalf("status got=%q want=%q", resp.Status, ToolCallStatusError)
	}
	if resp.Error == nil || resp.Error.Code != ToolErrorCodeToolNotFound {
		t.Fatalf("error code got=%v want=%q", resp.Error, ToolErrorCodeToolNotFound)
	}
}

func TestToolCallInvalidJSON(t *testing.T) {
	server := newTestServer(t, echoHandler{})
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/tools/call", bytes.NewBufferString("{"))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post invalid json: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status code got=%d want=%d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestToolCallMissingRequiredFields(t *testing.T) {
	server := newTestServer(t, echoHandler{})
	defer server.Close()

	reqPayload := map[string]any{
		"version":   sdktypes.VersionV1,
		"call_id":   "call-1",
		"tool_name": "echo",
		"args": map[string]any{
			"value": "hello",
		},
		"context": map[string]any{
			"agent_id":   "agent-1",
			"session_id": "session-1",
		},
	}

	status, body := postCall(t, server.URL, reqPayload)
	if status != http.StatusOK {
		t.Fatalf("status code got=%d want=%d body=%s", status, http.StatusOK, string(body))
	}

	var resp ToolCallResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode tool call response: %v", err)
	}
	if resp.Status != ToolCallStatusError {
		t.Fatalf("status got=%q want=%q", resp.Status, ToolCallStatusError)
	}
	if resp.Error == nil || resp.Error.Code != ToolErrorCodeInvalidArgs {
		t.Fatalf("error code got=%v want=%q", resp.Error, ToolErrorCodeInvalidArgs)
	}
}

func TestTimeoutEnforcement(t *testing.T) {
	server := newTestServer(t, slowHandler{
		wait:         200 * time.Millisecond,
		timeoutMSMax: 30,
	})
	defer server.Close()

	req := validRequest("slow")
	req["timeout_ms"] = 250

	start := time.Now()
	status, body := postCall(t, server.URL, req)
	elapsed := time.Since(start)

	if status != http.StatusOK {
		t.Fatalf("status code got=%d want=%d body=%s", status, http.StatusOK, string(body))
	}

	var resp ToolCallResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode tool call response: %v", err)
	}
	if resp.Status != ToolCallStatusTimeout {
		t.Fatalf("status got=%q want=%q", resp.Status, ToolCallStatusTimeout)
	}
	if resp.Error == nil || resp.Error.Code != ToolErrorCodeTimeout {
		t.Fatalf("error code got=%v want=%q", resp.Error, ToolErrorCodeTimeout)
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("timeout cap not applied, elapsed=%v", elapsed)
	}
}

func TestToolCallPanicRecovery(t *testing.T) {
	server := newTestServer(t, panicHandler{})
	defer server.Close()

	status, body := postCall(t, server.URL, validRequest("panic"))
	if status != http.StatusOK {
		t.Fatalf("status code got=%d want=%d body=%s", status, http.StatusOK, string(body))
	}

	var resp ToolCallResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode tool call response: %v", err)
	}
	if resp.Status != ToolCallStatusError {
		t.Fatalf("status got=%q want=%q", resp.Status, ToolCallStatusError)
	}
	if resp.Error == nil || resp.Error.Code != ToolErrorCodeInternal {
		t.Fatalf("error code got=%v want=%q", resp.Error, ToolErrorCodeInternal)
	}
}

func TestToolCallDurationPopulated(t *testing.T) {
	server := newTestServer(t, sleepHandler{delay: 25 * time.Millisecond})
	defer server.Close()

	status, body := postCall(t, server.URL, validRequest("sleep"))
	if status != http.StatusOK {
		t.Fatalf("status code got=%d want=%d body=%s", status, http.StatusOK, string(body))
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	if _, ok := raw["duration_ms"]; !ok {
		t.Fatalf("duration_ms is missing from response")
	}

	var resp ToolCallResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode tool call response: %v", err)
	}
	if resp.DurationMS <= 0 {
		t.Fatalf("duration_ms got=%d want > 0", resp.DurationMS)
	}
}

func newTestServer(t *testing.T, handlers ...ToolHandler) *httptest.Server {
	t.Helper()

	host := NewToolHost("test-service", log.New(io.Discard, "", 0))
	for _, handler := range handlers {
		host.Register(handler)
	}
	return httptest.NewServer(host.Handler())
}

func validRequest(toolName string) map[string]any {
	return map[string]any{
		"version":   sdktypes.VersionV1,
		"call_id":   "call-1",
		"tool_name": toolName,
		"tenant_id": "tenant-1",
		"args": map[string]any{
			"value": "hello",
		},
		"context": map[string]any{
			"agent_id":   "agent-1",
			"session_id": "session-1",
		},
	}
}

func postCall(t *testing.T, baseURL string, req any) (int, []byte) {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, baseURL+"/v1/tools/call", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("post /v1/tools/call: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, respBody
}

type echoHandler struct{}

func (echoHandler) Name() string {
	return "echo"
}

func (echoHandler) Definition() ToolDefinition {
	return ToolDefinition{
		Name:             "echo",
		Description:      "Echo input args",
		InputSchema:      json.RawMessage(`{"type":"object"}`),
		OutputSchema:     json.RawMessage(`{"type":"object"}`),
		TimeoutMSDefault: 2000,
		TimeoutMSMax:     10000,
		Idempotent:       true,
		SideEffects:      false,
	}
}

func (echoHandler) Execute(_ context.Context, req ToolCallRequest) ToolCallResponse {
	return ToolCallResponse{
		Version:  req.Version,
		CallID:   req.CallID,
		ToolName: req.ToolName,
		Status:   ToolCallStatusOK,
		Result:   req.Args,
	}
}

type slowHandler struct {
	wait         time.Duration
	timeoutMSMax int
}

func (slowHandler) Name() string {
	return "slow"
}

func (h slowHandler) Definition() ToolDefinition {
	return ToolDefinition{
		Name:             "slow",
		Description:      "Slow handler for timeout testing",
		InputSchema:      json.RawMessage(`{"type":"object"}`),
		OutputSchema:     json.RawMessage(`{"type":"object"}`),
		TimeoutMSDefault: 100,
		TimeoutMSMax:     h.timeoutMSMax,
		Idempotent:       true,
		SideEffects:      false,
	}
}

func (h slowHandler) Execute(ctx context.Context, req ToolCallRequest) ToolCallResponse {
	select {
	case <-ctx.Done():
		return ToolCallResponse{
			Version:  req.Version,
			CallID:   req.CallID,
			ToolName: req.ToolName,
			Status:   ToolCallStatusRetryableError,
			Error: &ToolCallError{
				Code:      ToolErrorCodeDependencyUnavailable,
				Message:   ctx.Err().Error(),
				Retryable: true,
			},
		}
	case <-time.After(h.wait):
		return ToolCallResponse{
			Version:  req.Version,
			CallID:   req.CallID,
			ToolName: req.ToolName,
			Status:   ToolCallStatusOK,
			Result:   json.RawMessage(`{"done":true}`),
		}
	}
}

type panicHandler struct{}

func (panicHandler) Name() string {
	return "panic"
}

func (panicHandler) Definition() ToolDefinition {
	return ToolDefinition{
		Name:             "panic",
		Description:      "panic handler",
		InputSchema:      json.RawMessage(`{"type":"object"}`),
		OutputSchema:     json.RawMessage(`{"type":"object"}`),
		TimeoutMSDefault: 100,
		TimeoutMSMax:     1000,
		Idempotent:       false,
		SideEffects:      true,
	}
}

func (panicHandler) Execute(_ context.Context, _ ToolCallRequest) ToolCallResponse {
	panic("boom")
}

type sleepHandler struct {
	delay time.Duration
}

func (sleepHandler) Name() string {
	return "sleep"
}

func (h sleepHandler) Definition() ToolDefinition {
	return ToolDefinition{
		Name:             "sleep",
		Description:      "sleep handler",
		InputSchema:      json.RawMessage(`{"type":"object"}`),
		OutputSchema:     json.RawMessage(`{"type":"object"}`),
		TimeoutMSDefault: 1000,
		TimeoutMSMax:     2000,
		Idempotent:       true,
		SideEffects:      false,
	}
}

func (h sleepHandler) Execute(_ context.Context, req ToolCallRequest) ToolCallResponse {
	time.Sleep(h.delay)
	return ToolCallResponse{
		Version:  req.Version,
		CallID:   req.CallID,
		ToolName: req.ToolName,
		Status:   ToolCallStatusOK,
		Result:   req.Args,
	}
}
