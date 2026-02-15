# Crab Cron Service AGENTS

## Scope
This project runs a standalone cron service process:
- Schedules cron jobs and emits events to the gateway.
- Exposes cron management tools through the tool host protocol.

## Module
- Go module: `crabstack.local/projects/crab-cron`
- Shared SDK dependency: `crabstack.local/projects/crab-sdk`

## Package map
- `cmd/crab-cron`: process bootstrap and graceful shutdown.
- `internal/config`: env config parsing and validation.
- `internal/scheduler`: job model, cron parser, in-memory job store, runtime scheduler.
- `internal/tools`: toolhost handlers for `cron.list`, `cron.create`, `cron.remove`.
- `internal/emitter`: HTTP event emitter to gateway `/v1/events`.

## Config keys
- `CRAB_GATEWAY_HTTP_URL` (default `http://127.0.0.1:8080`)
- `CRAB_CRON_HTTP_ADDR` (default `:8091`)
- `CRAB_CRON_TENANT_ID` (default `default`)
- `CRAB_CRON_AGENT_ID` (default `assistant`)
- `CRAB_CRON_DB_PATH` (default `cron.db`)

## Implementation notes
- Keep behavior aligned with `spec/OVERVIEW.md`, `spec/TOOL_SCHEMA.md`, and `spec/EVENT_SCHEMA.md`.
- Scheduler runs once per second and prevents duplicate fires in the same minute per job.
- Heartbeats are regular cron jobs using `event_type=heartbeat.tick`.
- Current persistence is in-memory; SQLite persistence is a future task.

## Testing requirements
- Keep scheduler tests deterministic with controllable time/ticks.
- Cover cron parser valid/invalid cases and matching behavior for ranges/lists/intervals.
- Cover tool handlers for success/failure paths, especially arg validation and missing jobs.
