# Crab Discord Listener AGENTS

## Scope
This project runs a standalone Discord listener process that forwards inbound Discord messages to the Crabstack gateway over HTTP.

## Module
- Go module: `crabstack.local/projects/crab-discord`
- Shared types dependency: `crabstack.local/projects/crab-sdk/types`

## Package map
- `cmd/crab-discord`: process bootstrap and graceful shutdown.
- `internal/config`: env config parsing + validation.
- `internal/listener`: Discord session lifecycle, message conversion, and gateway event forwarding.

## Config keys
- `DISCORD_BOT_TOKEN` (required)
- `CRAB_GATEWAY_HTTP_URL` (default `http://127.0.0.1:8080`)
- `CRAB_DISCORD_TENANT_ID` (default `default`)
- `CRAB_DISCORD_AGENT_ID` (default `assistant`)

## Implementation notes
- Inbound Discord messages map to `channel.message.received` envelopes.
- Forwarding is one-way for now: Discord -> Gateway.
- Bot-authored messages are ignored.
- Gateway ingress target is `POST {CRAB_GATEWAY_HTTP_URL}/v1/events`.
- Keep event shapes aligned with `spec/EVENT_SCHEMA.md` and `projects/crab-sdk/types`.

## Testing requirements
- Tests must not require a real Discord connection.
- Keep message conversion logic testable as a pure function.
- Cover bot filtering, attachment mapping, reply mapping, and non-fatal gateway post failures.
