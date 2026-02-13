# Pinchy CLI AGENTS

## Scope
This project implements a terminal operator client for Pinchy:
- Trigger gateway-initiated pairing through the admin Unix socket.
- Act as a temporary remote endpoint for the full v1 pairing handshake.
- Send canonical event envelopes to gateway.
- Receive canonical event envelopes from gateway.
- Render interaction via a TUI.

## Module
- Go module: `pinchy.local/projects/pinchy-cli`
- Shared types dependency: `pinchy.local/lib/types`

## Implementation notes
- Follow contracts from `spec/` and types from `lib/types`.
- Pairing messages must remain compatible with v1 structs.
- Pairing signatures must use canonical payloads that exclude `sig_ed25519`.
- `pair.init` signature payload must match gateway canonical shape (`gateway_id`, `public_key_ed25519`, `nonce`, `issued_at`) and must not include transport-only fields.
- Event transport must use `types.EventEnvelope`.
- `pinchy-cli pair` must run full handshake phases:
  - `pair.init`
  - `pair.identity`
  - `pair.challenge`
  - `pair.challenge_response`
  - `pair.csr_request`
  - `pair.csr_issued`
  - `pair.csr_installed`
  - `pair.complete`
- Pair trigger requests must target gateway admin Unix socket (`POST /v1/pairings`).

## Testing requirements
- Pairing handshake flow must be tested against a mock gateway WS server.
- Client tests must cover both success and failure paths.
- Pair command tests must cover gateway-admin trigger + CSR handshake completion.
- End-to-end gateway+CLI pairing behavior is covered from the root `integration/` module.
