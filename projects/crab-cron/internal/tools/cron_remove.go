package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"crabstack.local/projects/crab-cron/internal/scheduler"
	"crabstack.local/projects/crab-sdk/toolhost"
)

type CronRemoveHandler struct {
	store  scheduler.JobStore
	reload func(context.Context) error
}

func NewCronRemoveHandler(store scheduler.JobStore, reload func(context.Context) error) *CronRemoveHandler {
	if store == nil {
		panic("cron.remove: store is required")
	}
	return &CronRemoveHandler{store: store, reload: reload}
}

func (h *CronRemoveHandler) Name() string {
	return "cron.remove"
}

func (h *CronRemoveHandler) Definition() toolhost.ToolDefinition {
	return toolhost.ToolDefinition{
		Name:             h.Name(),
		Description:      "Remove a cron job",
		InputSchema:      json.RawMessage(`{"type":"object","additionalProperties":false,"required":["job_id"],"properties":{"job_id":{"type":"string"}}}`),
		OutputSchema:     json.RawMessage(`{"type":"object","properties":{"deleted":{"type":"boolean"}}}`),
		TimeoutMSDefault: 5000,
		TimeoutMSMax:     10000,
		Idempotent:       false,
		SideEffects:      true,
	}
}

func (h *CronRemoveHandler) Execute(ctx context.Context, req toolhost.ToolCallRequest) toolhost.ToolCallResponse {
	args, err := parseCronRemoveArgs(req.Args)
	if err != nil {
		return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInvalidArgs, err.Error(), false)
	}

	if err := h.store.Delete(ctx, args.JobID); err != nil {
		if errors.Is(err, scheduler.ErrJobNotFound) {
			return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInvalidArgs, "job not found", false)
		}
		return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInternal, "failed to remove job", false)
	}

	if h.reload != nil {
		if err := h.reload(ctx); err != nil {
			return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInternal, "failed to reload scheduler", false)
		}
	}

	return okResponse(req, h.Name(), map[string]any{"deleted": true})
}

type cronRemoveArgs struct {
	JobID string `json:"job_id"`
}

func parseCronRemoveArgs(raw json.RawMessage) (cronRemoveArgs, error) {
	if len(raw) == 0 {
		return cronRemoveArgs{}, fmt.Errorf("args are required")
	}

	var args cronRemoveArgs
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&args); err != nil {
		return cronRemoveArgs{}, fmt.Errorf("invalid args: %w", err)
	}

	args.JobID = strings.TrimSpace(args.JobID)
	if args.JobID == "" {
		return cronRemoveArgs{}, fmt.Errorf("job_id is required")
	}
	return args, nil
}
