package toolhost

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	sdktypes "crabstack.local/projects/crab-sdk/types"
)

type ToolHandler interface {
	Name() string
	Definition() ToolDefinition
	Execute(ctx context.Context, req ToolCallRequest) ToolCallResponse
}

type ToolHost struct {
	serviceName string
	handlers    map[string]ToolHandler
	logger      *log.Logger
}

func NewToolHost(serviceName string, logger *log.Logger) *ToolHost {
	if logger == nil {
		logger = log.Default()
	}
	return &ToolHost{
		serviceName: strings.TrimSpace(serviceName),
		handlers:    make(map[string]ToolHandler),
		logger:      logger,
	}
}

func (h *ToolHost) Register(handler ToolHandler) {
	if handler == nil {
		panic("toolhost: nil handler")
	}
	name := strings.TrimSpace(handler.Name())
	if name == "" {
		panic("toolhost: empty handler name")
	}
	h.handlers[name] = handler
}

func (h *ToolHost) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.handleHealthz)
	mux.HandleFunc("/v1/tools", h.handleToolsDiscovery)
	mux.HandleFunc("/v1/tools/call", h.handleToolCall)
	return mux
}

func (h *ToolHost) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *ToolHost) handleToolsDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	names := make([]string, 0, len(h.handlers))
	for name := range h.handlers {
		names = append(names, name)
	}
	slices.Sort(names)

	tools := make([]ToolDefinition, 0, len(names))
	for _, name := range names {
		definition := h.handlers[name].Definition()
		if strings.TrimSpace(definition.Name) == "" {
			definition.Name = name
		}
		tools = append(tools, definition)
	}

	resp := DiscoveryResponse{
		Version: sdktypes.VersionV1,
		Service: h.serviceName,
		Tools:   tools,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *ToolHost) handleToolCall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ToolCallRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := assertNoTrailingJSON(decoder); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	req.Version = strings.TrimSpace(req.Version)
	req.CallID = strings.TrimSpace(req.CallID)
	req.ToolName = strings.TrimSpace(req.ToolName)
	req.TenantID = strings.TrimSpace(req.TenantID)

	start := time.Now()
	if req.Version == "" || req.CallID == "" || req.ToolName == "" || req.TenantID == "" {
		writeJSON(w, http.StatusOK, errorResponse(
			req,
			ToolCallStatusError,
			ToolErrorCodeInvalidArgs,
			"missing required fields: version, call_id, tool_name, tenant_id",
			false,
			time.Since(start).Milliseconds(),
		))
		return
	}

	handler, ok := h.handlers[req.ToolName]
	if !ok {
		writeJSON(w, http.StatusOK, errorResponse(
			req,
			ToolCallStatusError,
			ToolErrorCodeToolNotFound,
			"tool not found",
			false,
			time.Since(start).Milliseconds(),
		))
		return
	}

	ctx := r.Context()
	effectiveTimeoutMS := req.TimeoutMS
	if req.TimeoutMS > 0 {
		def := handler.Definition()
		if def.TimeoutMSMax > 0 && req.TimeoutMS > def.TimeoutMSMax {
			effectiveTimeoutMS = def.TimeoutMSMax
		}
		timeout := time.Duration(effectiveTimeoutMS) * time.Millisecond
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		req.TimeoutMS = effectiveTimeoutMS
	}

	var resp ToolCallResponse
	var panicValue any
	execStart := time.Now()
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				panicValue = recovered
			}
		}()
		resp = handler.Execute(ctx, req)
	}()
	duration := time.Since(execStart).Milliseconds()

	if panicValue != nil {
		h.logger.Printf("tool %q panic: %v", req.ToolName, panicValue)
		resp = errorResponse(req, ToolCallStatusError, ToolErrorCodeInternal, "internal error", false, duration)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		resp.Status = ToolCallStatusTimeout
		resp.Result = nil
		resp.Error = &ToolCallError{
			Code:      ToolErrorCodeTimeout,
			Message:   "tool execution timed out",
			Retryable: true,
		}
	}

	if strings.TrimSpace(resp.Version) == "" {
		resp.Version = req.Version
	}
	if strings.TrimSpace(resp.Version) == "" {
		resp.Version = sdktypes.VersionV1
	}
	if strings.TrimSpace(resp.CallID) == "" {
		resp.CallID = req.CallID
	}
	if strings.TrimSpace(resp.ToolName) == "" {
		resp.ToolName = req.ToolName
	}
	if resp.Status == "" {
		if resp.Error != nil {
			resp.Status = ToolCallStatusError
		} else {
			resp.Status = ToolCallStatusOK
		}
	}
	resp.DurationMS = duration

	writeJSON(w, http.StatusOK, resp)
}

func errorResponse(req ToolCallRequest, status ToolCallStatus, code string, message string, retryable bool, durationMS int64) ToolCallResponse {
	version := req.Version
	if version == "" {
		version = sdktypes.VersionV1
	}
	return ToolCallResponse{
		Version:  version,
		CallID:   req.CallID,
		ToolName: req.ToolName,
		Status:   status,
		Error: &ToolCallError{
			Code:      code,
			Message:   message,
			Retryable: retryable,
		},
		DurationMS: durationMS,
	}
}

func assertNoTrailingJSON(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("extra content")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
