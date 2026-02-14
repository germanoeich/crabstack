# Crab SDK AGENTS

## Scope
This project provides reusable Crabstack SDK code shared by multiple components:
- Pairing handshake flow
- Pairing protocol signing/verification/crypto helpers

## Module
- Go module: `crabstack.local/projects/crab-sdk`
- Shared types package: `crabstack.local/projects/crab-sdk/types`

## Package map
- `pairing`: gateway-triggered pairing flow, local handshake endpoint, CSR exchange flow.
- `protocol`: pairing protocol wire structs and cryptographic helpers (PKCE/sign/verify/challenge encrypt/decrypt).

## Implementation notes
- Keep all pairing behavior aligned with `spec/PAIRING_STRUCTS.md`, `spec/PEER_AUTH_MODEL.md`, and `spec/SECURITY.md`.
- `pairing` should depend on `protocol` + `types`, not application-specific CLI/gateway internals.
- Avoid command/runtime concerns in this module; this SDK should be callable from CLI, services, and listeners.

## Testing requirements
- Keep protocol tests focused on signing/verification and challenge crypto round-trips.
- Keep pairing flow tests covering full handshake + failure modes.
