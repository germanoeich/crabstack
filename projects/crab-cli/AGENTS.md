# Crabstack CLI AGENTS

## Scope
This project implements a terminal operator client for Crabstack:
- Trigger gateway-initiated pairing through the admin Unix socket.
- Provide a dedicated pairing test flow that acts as a temporary remote endpoint for full v1 handshake validation.
- Send canonical event envelopes to gateway.
- Perform Codex and Anthropic subscription OAuth login and persist credentials.
- Receive canonical event envelopes from gateway.
- Render interaction via a TUI.

## Module
- Go module: `crabstack.local/projects/crab-cli`
- Shared types dependency: `crabstack.local/lib/types`

## Implementation notes
- Follow contracts from `spec/` and types from `lib/types`.
- Pairing messages must remain compatible with v1 structs.
- Pairing signatures must use canonical payloads that exclude `sig_ed25519`.
- `pair.init` signature payload must match gateway canonical shape (`gateway_id`, `public_key_ed25519`, `nonce`, `issued_at`) and must not include transport-only fields.
- Event transport must use `types.EventEnvelope`.
- `crab pair tool <endpoint> <name>`, `crab pair subscriber <endpoint> <name>`, and `crab pair cli <endpoint> <name>` are gateway-trigger-only:
  - send `POST /v1/pairings` over admin socket
  - map command to request:
    - `component_type` from subcommand (`tool_host` / `subscriber` / `operator`)
    - `component_id` from positional `<name>`
    - `endpoint` from positional `<endpoint>`
  - never host a local websocket endpoint
- `crab event send <text>` sends one `channel.message.received` envelope to `POST /v1/events`:
  - `source.platform=cli`
  - `source.channel_id=cli` by default
  - creates a new `session_id` per invocation
- `crab auth codex` executes subscription OAuth (PKCE + localhost callback + manual fallback):
  - defaults to OpenAI auth endpoints and fixed client id expected by Codex subscription flow
  - validates ChatGPT account claim from access token
  - persists JSON credentials (includes refresh token + expiry) to `~/.crabstack/auth/codex.json` unless overridden
- `crab auth claude` executes Anthropic OAuth (PKCE + localhost callback + manual fallback):
  - supports `--mode max` (authorize via `https://claude.ai/oauth/authorize`, scope `user:inference`) and `--mode console` (authorize via `https://console.anthropic.com/oauth/authorize`, scope `org:create_api_key`)
  - exchanges code at `https://console.anthropic.com/v1/oauth/token` with shared Anthropic OAuth client id
  - persists JSON credentials (includes refresh token + expiry) to `~/.crabstack/auth/claude.json` unless overridden
- `crab auth anthropic` executes subscription OAuth (PKCE + manual code paste):
  - defaults to Anthropic auth endpoints and fixed client id expected by Claude subscription flow
  - prompts for manual auth code (or redirect URL) after browser approval
  - persists JSON credentials (includes refresh token + expiry) to `~/.crabstack/auth/anthropic.json` unless overridden
- `crab pair test` runs full handshake phases:
  - `pair.init`
  - `pair.identity`
  - `pair.challenge`
  - `pair.challenge_response`
  - `pair.csr_request`
  - `pair.csr_issued`
  - `pair.csr_installed`
  - `pair.complete`
- Pair trigger requests must target gateway admin Unix socket (`POST /v1/pairings`).
- `crab pair test` defaults should work without flags in local operator setups.

## Testing requirements
- Pair trigger path (`crab pair`) must be tested independently from local handshake hosting.
- Pairing handshake flow must be tested against a mock gateway WS server.
- Client tests must cover both success and failure paths.
- Pair command tests must cover gateway-admin trigger + CSR handshake completion.
- OAuth auth tests must cover callback capture, manual fallback parsing, token exchange decoding, account metadata extraction, and credential persistence.
- End-to-end gateway+CLI pairing behavior is covered from the root `integration/` module.
