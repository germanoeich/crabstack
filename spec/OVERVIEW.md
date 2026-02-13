# Pinchy LLM Agent Toolkit

## Purpose
Pinchy is a modular Go toolkit for running personal/micro-group LLM agents across channels (Discord, WhatsApp, etc) with durable sessions, pluggable subscribers, and remote tools.

## Product constraints (locked)
- Gateway is the orchestration core.
- Supports model access through:
  - API keys
  - Subscription-backed providers (different auth lifecycle)
- Ingress is protocol-agnostic (`http` and `ws` adapters).
- Channel listeners are isolated modules/processes and may run on different hosts.
- Memory is not embedded in the gateway:
  - It runs as a subscriber for turn/event ingestion.
  - It may also expose callable tools via a custom remote tool protocol (non-MCP).
- Cron runs as an external module:
  - Emits scheduled events to gateway.
  - Exposes tools to list/create/remove jobs.
  - Heartbeats are implemented as cron jobs.
- Sessions are durable long-term and managed by gateway.
- Multi-tenant from day one (operator-configured identity mapping; no user account/login system).
- Storage:
  - SQLite default
  - Postgres supported
  - No Redis dependency
- Config is file-driven (YAML source of truth).
- Config changes can be made by agents only via validated tools.
- Full history is stored (not summary-only).
- Security, transport, and pairing are defined in `SECURITY.md`.

## Core architecture
- `gateway-core`
- `ingress adapters` (`http`, `ws`) normalize external events into a canonical envelope.
- `router` selects agent/policies from YAML rules.
- `session manager` owns durable session state and full turn history.
- `turn executor` runs the agent turn lifecycle.
- `model adapters` abstract API-key and subscription-backed auth flows.
- `tool client` calls remote tool hosts.
- `event dispatcher` publishes lifecycle events to subscribers/egress listeners.

- `channel-listeners` (separate process/service)
- Convert platform-specific inbound events into gateway envelope.
- Subscribe to outbound events and transform into platform actions.

- `memory-service` (separate process/service)
- Subscriber for turn history/memory ingest.
- Optional remote tool host (query/append/search/etc).

- `cron-service` (separate process/service)
- Scheduler that emits gateway events.
- Remote tool host (`cron.list`, `cron.create`, `cron.remove`).

## Session and memory model
- Sessions are durable and long-lived in gateway DB.
- Gateway stores `last_active_channel` and uses it as fallback target when an internal event has no explicit output target.
- Memory scope defaults to global.
- Isolation is opt-in per config using `isolation_key`.
- If `isolation_key` is missing, memory resolves to global scope.
- Context composition is layered:
  1. Global agent `.md`
  2. Channel/platform-scoped `.md`
  3. Actor-scoped `.md`
  4. Session/runtime additions

## Multi-tenant model
- Tenancy and identity are operator-defined (phone numbers, usernames, channel IDs, etc).
- Recommended logical runtime key:
  - `tenant_id + agent_id + platform + channel_id + actor_id`
- Recommended memory key:
  - `tenant_id + agent_id + (isolation_key | "global")`

## Consistency and reliability
- Turn execution: strict ordering per session.
- Subscriber dispatch: eventual consistency.
- Delivery semantics: at-least-once + idempotency keys.
- Use an outbox pattern for reliable subscriber delivery.
- Retry with backoff and dead-letter handling for failed subscriber deliveries.

## Config management and safety
- YAML is canonical config.
- Agent applies config changes only via a dedicated tool.
- Apply flow:
  1. Parse + schema validation
  2. Semantic validation
  3. Optional smoke tests
  4. Atomic write + hot reload
  5. Audit record + `config.applied` event
- Always keep revision history and rollback capability (`config.revert`).
- No manual two-phase approval requirement in gateway logic.

## Persistence (minimum tables)
- `sessions`
- `turns` (full request/response payloads)
- `session_bindings` (platform/channel/actor mapping, optional `isolation_key`)
- `config_revisions`
- `event_outbox`
- `tool_calls` (optional but recommended for observability/replay)

## Initial build order
1. Shared contracts (`event`, `tool`, `session`, `config`).
2. Gateway core + HTTP ingress + session persistence.
3. Routing engine + strict per-session turn ordering.
4. Model adapters (API key first, then subscription-backed).
5. Tool protocol client/server basics.
6. Memory service as subscriber + tool host.
7. Cron service (event emitter + tools + heartbeat jobs).
8. WS ingress and additional channel listeners.
