package tools

import (
	"context"
	"encoding/json"
	"testing"

	"crabstack.local/projects/crab-cron/internal/scheduler"
	"crabstack.local/projects/crab-sdk/toolhost"
	sdktypes "crabstack.local/projects/crab-sdk/types"
)

func TestCronCreateHandler(t *testing.T) {
	store := scheduler.NewMemoryJobStore()
	reloadCount := 0
	h := NewCronCreateHandler(store, func(context.Context) error {
		reloadCount++
		return nil
	})

	resp := h.Execute(context.Background(), toolhost.ToolCallRequest{
		Version:  sdktypes.VersionV1,
		CallID:   "call-1",
		ToolName: h.Name(),
		TenantID: "tenant-1",
		Args: mustMarshalJSON(t, map[string]any{
			"name":       "heartbeat",
			"schedule":   "*/5 * * * *",
			"event_type": "heartbeat.tick",
			"input": map[string]any{
				"kind": "heartbeat",
			},
		}),
		Context: toolhost.ToolCallContext{
			AgentID:   "assistant",
			SessionID: "session-1",
		},
	})

	if resp.Status != toolhost.ToolCallStatusOK {
		t.Fatalf("status got=%q want=%q error=%v", resp.Status, toolhost.ToolCallStatusOK, resp.Error)
	}
	if reloadCount != 1 {
		t.Fatalf("reload count got=%d want=1", reloadCount)
	}

	var job scheduler.Job
	if err := json.Unmarshal(resp.Result, &job); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if job.ID == "" {
		t.Fatalf("expected created job id")
	}
	if job.Name != "heartbeat" {
		t.Fatalf("job name got=%q want=%q", job.Name, "heartbeat")
	}
	if job.EventType != sdktypes.EventTypeHeartbeatTick {
		t.Fatalf("event type got=%q want=%q", job.EventType, sdktypes.EventTypeHeartbeatTick)
	}
	if !job.Enabled {
		t.Fatalf("created job should be enabled")
	}
}

func TestCronCreateHandlerValidatesSchedule(t *testing.T) {
	store := scheduler.NewMemoryJobStore()
	h := NewCronCreateHandler(store, nil)

	resp := h.Execute(context.Background(), toolhost.ToolCallRequest{
		Version:  sdktypes.VersionV1,
		CallID:   "call-1",
		ToolName: h.Name(),
		TenantID: "tenant-1",
		Args: mustMarshalJSON(t, map[string]any{
			"name":     "broken",
			"schedule": "bad cron",
		}),
		Context: toolhost.ToolCallContext{AgentID: "assistant", SessionID: "session-1"},
	})

	if resp.Status != toolhost.ToolCallStatusError {
		t.Fatalf("status got=%q want=%q", resp.Status, toolhost.ToolCallStatusError)
	}
	if resp.Error == nil || resp.Error.Code != toolhost.ToolErrorCodeInvalidArgs {
		t.Fatalf("error got=%v want invalid args", resp.Error)
	}
}

func TestCronRemoveHandlerMissingJob(t *testing.T) {
	store := scheduler.NewMemoryJobStore()
	h := NewCronRemoveHandler(store, nil)

	resp := h.Execute(context.Background(), toolhost.ToolCallRequest{
		Version:  sdktypes.VersionV1,
		CallID:   "call-1",
		ToolName: h.Name(),
		TenantID: "tenant-1",
		Args:     mustMarshalJSON(t, map[string]any{"job_id": "missing"}),
	})

	if resp.Status != toolhost.ToolCallStatusError {
		t.Fatalf("status got=%q want=%q", resp.Status, toolhost.ToolCallStatusError)
	}
	if resp.Error == nil || resp.Error.Code != toolhost.ToolErrorCodeInvalidArgs {
		t.Fatalf("error got=%v want invalid args", resp.Error)
	}
}

func TestCronRemoveHandlerSuccess(t *testing.T) {
	store := scheduler.NewMemoryJobStore()
	job, err := store.Create(context.Background(), scheduler.Job{
		Name:      "test",
		Schedule:  "* * * * *",
		EventType: sdktypes.EventTypeCronTriggered,
		TenantID:  "tenant-1",
		AgentID:   "assistant",
		SessionID: "session-1",
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}

	reloadCount := 0
	h := NewCronRemoveHandler(store, func(context.Context) error {
		reloadCount++
		return nil
	})

	resp := h.Execute(context.Background(), toolhost.ToolCallRequest{
		Version:  sdktypes.VersionV1,
		CallID:   "call-1",
		ToolName: h.Name(),
		TenantID: "tenant-1",
		Args:     mustMarshalJSON(t, map[string]any{"job_id": job.ID}),
	})
	if resp.Status != toolhost.ToolCallStatusOK {
		t.Fatalf("status got=%q want=%q error=%v", resp.Status, toolhost.ToolCallStatusOK, resp.Error)
	}
	if reloadCount != 1 {
		t.Fatalf("reload count got=%d want=1", reloadCount)
	}

	if _, err := store.Get(context.Background(), job.ID); err == nil {
		t.Fatalf("expected deleted job to be missing")
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if deleted, ok := result["deleted"].(bool); !ok || !deleted {
		t.Fatalf("expected deleted=true result, got %v", result)
	}
}

func TestCronListHandlerReturnsAllJobs(t *testing.T) {
	store := scheduler.NewMemoryJobStore()
	_, err := store.Create(context.Background(), scheduler.Job{
		Name:      "job-1",
		Schedule:  "* * * * *",
		EventType: sdktypes.EventTypeCronTriggered,
		TenantID:  "tenant-1",
		AgentID:   "assistant",
		SessionID: "session-1",
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("create job-1: %v", err)
	}
	_, err = store.Create(context.Background(), scheduler.Job{
		Name:      "job-2",
		Schedule:  "*/5 * * * *",
		EventType: sdktypes.EventTypeCronTriggered,
		TenantID:  "tenant-1",
		AgentID:   "assistant",
		SessionID: "session-1",
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("create job-2: %v", err)
	}

	h := NewCronListHandler(store)
	resp := h.Execute(context.Background(), toolhost.ToolCallRequest{
		Version:  sdktypes.VersionV1,
		CallID:   "call-1",
		ToolName: h.Name(),
		TenantID: "tenant-1",
	})

	if resp.Status != toolhost.ToolCallStatusOK {
		t.Fatalf("status got=%q want=%q error=%v", resp.Status, toolhost.ToolCallStatusOK, resp.Error)
	}

	var result struct {
		Jobs []scheduler.Job `json:"jobs"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(result.Jobs) != 2 {
		t.Fatalf("jobs length got=%d want=2", len(result.Jobs))
	}
}

func mustMarshalJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()

	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return payload
}
