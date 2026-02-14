package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"crabstack.local/projects/crab-cron/internal/scheduler"
	"crabstack.local/projects/crab-sdk/toolhost"
	"crabstack.local/projects/crab-sdk/types"
)

type CronCreateHandler struct {
	store  scheduler.JobStore
	reload func(context.Context) error
}

func NewCronCreateHandler(store scheduler.JobStore, reload func(context.Context) error) *CronCreateHandler {
	if store == nil {
		panic("cron.create: store is required")
	}
	return &CronCreateHandler{store: store, reload: reload}
}

func (h *CronCreateHandler) Name() string {
	return "cron.create"
}

func (h *CronCreateHandler) Definition() toolhost.ToolDefinition {
	return toolhost.ToolDefinition{
		Name:             h.Name(),
		Description:      "Create a cron job",
		InputSchema:      json.RawMessage(`{"type":"object","additionalProperties":false,"required":["name","schedule"],"properties":{"name":{"type":"string"},"schedule":{"type":"string"},"event_type":{"type":"string"},"input":{"type":"object"}}}`),
		OutputSchema:     json.RawMessage(`{"type":"object"}`),
		TimeoutMSDefault: 5000,
		TimeoutMSMax:     10000,
		Idempotent:       false,
		SideEffects:      true,
	}
}

func (h *CronCreateHandler) Execute(ctx context.Context, req toolhost.ToolCallRequest) toolhost.ToolCallResponse {
	args, err := parseCronCreateArgs(req.Args)
	if err != nil {
		return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInvalidArgs, err.Error(), false)
	}

	if _, err := scheduler.ParseCronExpr(args.Schedule); err != nil {
		return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInvalidArgs, fmt.Sprintf("invalid schedule: %v", err), false)
	}

	job := scheduler.Job{
		Name:      args.Name,
		Schedule:  args.Schedule,
		EventType: args.EventType,
		TenantID:  strings.TrimSpace(req.TenantID),
		AgentID:   strings.TrimSpace(req.Context.AgentID),
		SessionID: strings.TrimSpace(req.Context.SessionID),
		Input:     args.Input,
		Enabled:   true,
	}
	if job.EventType == "" {
		job.EventType = types.EventTypeCronTriggered
	}
	if job.TenantID == "" {
		return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInvalidArgs, "tenant_id is required", false)
	}
	if job.AgentID == "" {
		return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInvalidArgs, "context.agent_id is required", false)
	}
	if job.SessionID == "" {
		return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInvalidArgs, "context.session_id is required", false)
	}

	created, err := h.store.Create(ctx, job)
	if err != nil {
		return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInternal, "failed to create job", false)
	}
	if h.reload != nil {
		if err := h.reload(ctx); err != nil {
			return errorResponse(req, h.Name(), toolhost.ToolErrorCodeInternal, "failed to reload scheduler", false)
		}
	}

	return okResponse(req, h.Name(), created)
}

type cronCreateArgs struct {
	Name      string          `json:"name"`
	Schedule  string          `json:"schedule"`
	EventType types.EventType `json:"event_type"`
	Input     map[string]any  `json:"input"`
}

func parseCronCreateArgs(raw json.RawMessage) (cronCreateArgs, error) {
	if len(raw) == 0 {
		return cronCreateArgs{}, fmt.Errorf("args are required")
	}

	var args cronCreateArgs
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&args); err != nil {
		return cronCreateArgs{}, fmt.Errorf("invalid args: %w", err)
	}

	args.Name = strings.TrimSpace(args.Name)
	args.Schedule = strings.TrimSpace(args.Schedule)
	if args.Name == "" {
		return cronCreateArgs{}, fmt.Errorf("name is required")
	}
	if args.Schedule == "" {
		return cronCreateArgs{}, fmt.Errorf("schedule is required")
	}

	return args, nil
}
