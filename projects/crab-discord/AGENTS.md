# Crab Discord Listener AGENTS

## Scope
This project runs a standalone Discord channel service process:
- Listens to inbound Discord messages and forwards them to the Crabstack gateway over HTTP.
- Receives outbound webhook callbacks from the gateway and posts agent responses back to Discord channels.

## Module
- Go module: `crabstack.local/projects/crab-discord`
- Shared types dependency: `crabstack.local/projects/crab-sdk/types`

## Package map
- `cmd/crab-discord`: process bootstrap and graceful shutdown.
- `internal/chanmap`: in-memory session-to-channel registry shared by listener and consumer.
- `internal/config`: env config parsing + validation.
- `internal/consumer`: webhook receiver for outbound events and Discord send dispatch.
- `internal/listener`: Discord session lifecycle, message conversion, and gateway event forwarding.

## Config keys
- `DISCORD_BOT_TOKEN` (required)
- `CRAB_GATEWAY_HTTP_URL` (default `http://127.0.0.1:8080`)
- `CRAB_DISCORD_TENANT_ID` (default `default`)
- `CRAB_DISCORD_AGENT_ID` (default `assistant`)
- `CRAB_DISCORD_CONSUMER_ADDR` (default `:8090`)

## Implementation notes
- Inbound Discord messages map to `channel.message.received` envelopes.
- Outbound `agent.response.created` webhook events are consumed at `POST /v1/events`.
- Target Discord channel resolution order:
  1. `routing.target.channel_id` (if set)
  2. shared session-to-channel registry (`routing.session_id`)
  3. `source.channel_id` fallback
- Bot-authored messages are ignored.
- Gateway ingress target is `POST {CRAB_GATEWAY_HTTP_URL}/v1/events`.
- Keep event shapes aligned with `spec/EVENT_SCHEMA.md` and `projects/crab-sdk/types`.

## Testing requirements
- Tests must not require a real Discord connection.
- Keep message conversion logic testable as a pure function.
- Cover bot filtering, attachment mapping, reply mapping, and non-fatal gateway post failures.
- Cover outbound webhook handling, event filtering, malformed payload rejection, and missing channel mapping behavior.
