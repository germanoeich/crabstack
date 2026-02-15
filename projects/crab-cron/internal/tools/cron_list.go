package tools

import (
	"context"
	"encoding/json"

	"crabstack.local/projects/crab-cron/internal/scheduler"
	"crabstack.local/projects/crab-sdk/toolhost"
)

type CronListHandler struct {
	store scheduler.JobStore
}

func NewCronListHandler(store scheduler.JobStore) *CronListHandler {
	if store == nil {
		panic("cron.list: store is required")
	}
	return &CronListHandler{store: store}
}

func (h *CronListHandler) Name() string {
	return "cron.list"
}

func (h *CronListHandler) Definition() toolhost.ToolDefinition {
	return toolhost.ToolDefinition{
		Name:             h.Name(),
		Description:      "List scheduled cron jobs",
		InputSchema:      json.RawMessage(`{"type":"object","additionalProperties":false}`),
		OutputSchema:     json.RawMessage(`{"type":"object","properties":{"jobs":{"type":"array","items":{"type":"object"}}}}`),
		TimeoutMSDefault: 5000,
		TimeoutMSMax:     10000,
		Idempotent:       true,
		SideEffects:      false,
	}
}

func (h *CronListHandler) Execute(ctx context.Context, req toolhost.ToolCallRequest) toolhost.ToolCallResponse {
	jobs, err := h.store.List(ctx)
	if err != nil {
		return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInternal, "failed to list jobs", false)
	}
	return okResponse(req, h.Name(), map[string]any{"jobs": jobs})
}
