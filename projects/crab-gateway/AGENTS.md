# Gateway AGENTS

## Scope
This project implements the Crabstack gateway runtime:
- Ingress normalization
- Per-session turn processing
- Session/turn persistence
- Event dispatch to subscribers

## Module
- Go module: `crabstack.local/projects/crab-gateway`
- Shared types dependency: `crabstack.local/lib/types`

## Runtime pipeline
1. `POST /v1/events` accepts canonical envelope.
2. Envelope is validated and queued by `tenant_id:session_id`.
3. Session store is updated (session metadata + last active target context).
4. Turn store records turn start.
5. Turn handler processes event.
6. Turn store records completion/failure.
7. Lifecycle and output events are dispatched to subscribers.
8. Pairing requests are handled by a transport-agnostic pairing service exposed via HTTP and WS adapters.
9. Pairing completes only after CSR issue/install confirmation and then peer activation.

## Config keys
- `CRAB_GATEWAY_HTTP_ADDR` (default `:8080`)
- `CRAB_GATEWAY_DB_DRIVER` (`sqlite` default, `postgres` supported)
- `CRAB_GATEWAY_DB_DSN` (default `gateway.db` for sqlite)
- `CRAB_GATEWAY_ID` (default `gateway-core`)
- `CRAB_GATEWAY_KEY_DIR` (default `.crabstack/keys`)
- `CRAB_GATEWAY_ADMIN_SOCKET_PATH` (default `.crabstack/run/gateway-admin.sock`)
- `CRAB_GATEWAY_PAIR_TIMEOUT` (default `15s`)
- `CRAB_GATEWAY_REQUIRE_MTLS_REMOTE` (default `true`)
- `CRAB_GATEWAY_ALLOW_INSECURE_LOOPBACK_PAIRING` (default `true`, loopback-only dev mode)
- `CRAB_GATEWAY_PAIR_MTLS_CA_FILE` (optional; must be set with cert/key when used)
- `CRAB_GATEWAY_PAIR_MTLS_CERT_FILE` (optional; must be set with ca/key when used)
- `CRAB_GATEWAY_PAIR_MTLS_KEY_FILE` (optional; must be set with ca/cert when used)

## Package map
- `cmd/crab-gateway`: process bootstrap and wiring.
- `internal/config`: env config parsing/validation.
- `internal/db`: shared DB open helpers for sqlite/postgres.
- `internal/httpapi`: HTTP handlers and envelope validation.
- `internal/session`: session scheduling + session/turn storage (Store interface + memory/gorm implementations).
- `internal/pairing`: gateway pairing identity, handshake manager, and paired-peer persistence.
- `internal/pairing/ca.go`: local pairing CA lifecycle and CSR signing.
- `internal/pairing/authorizer`: active-peer + certificate-bound authorization helper for remote adapters/tool clients.
- `internal/gateway`: orchestration service.
- `internal/dispatch`: async subscriber dispatch with retries.
- `internal/subscribers`: subscriber contracts and built-in subscribers.

## Implementation invariants
- Per-session ordering is strict in-process.
- Subscriber delivery is async and retry-based (eventual consistency).
- Session identity key is `tenant_id + session_id`.
- `sessions.last_active_*` must be updated from inbound channel context when present.
- Turns are append-only sequence per session.
- ORM is the persistence baseline for durable store (`GORM`), with driver selected by config.
- Pairing logic lives in `internal/pairing` and must remain protocol-agnostic.
- HTTP/WS are adapters only; handshake/state logic must not live in handler code.
- Public HTTP ingress does not expose pairing routes.
- Pairing trigger routes are exposed on the admin Unix socket transport and require no auth on that local transport.
- Pairing persistence must be success-only: existing active peers cannot be downgraded during a failed re-pair attempt.
- Peer activation persistence occurs only after `pair.complete` is successfully sent.
- `pair.challenge_response.version` must be validated against supported protocol version(s) before activation.
- `pair.identity.remote.component_id` is required and must be non-empty.
- Pairing request `component_id` is required at the admin API boundary and must match `pair.identity.remote.component_id`.
- Pairing WS ingress must reject cross-origin browser upgrades; allow only same-origin or non-browser clients without `Origin`.
- Pairing websocket reads must enforce a strict message size limit to avoid handshake memory exhaustion.
- Pairing handshake reads must share one end-to-end deadline derived from the pairing context timeout.
- Admin pairing websocket ingress must set a request read limit before decoding the first frame.
- Remote pairing over TCP must be gateway-initiated and `wss` only; non-loopback `ws` is rejected.
- For remote pairing, gateway requires configured client certificate material before handshake.
- During pairing, observed TLS certificate fingerprint (when present) must match `pair.identity.remote.mtls_cert_fingerprint`.
- Pairing persists the mTLS fingerprint confirmed in `pair.csr_installed` (must equal gateway-issued cert fingerprint).
- Re-pair attempts against active endpoints fail closed when observed cert fingerprint changes.
- Pairing handshake includes mandatory CSR exchange:
  - remote sends `pair.csr_request` signed with its Ed25519 identity key.
  - gateway issues certificate via local CA and returns signed `pair.csr_issued`.
  - remote confirms installation via signed `pair.csr_installed`.
- Peer activation is atomic and occurs only after CSR install fingerprint equals issued fingerprint.
- Manager must be configured with a `CertificateIssuer`; pairing fails fast when missing.

## Testing requirements
- Every non-trivial package must have direct tests.
- Session/turn stores require sequence and status transition tests.
- HTTP ingress tests must cover valid and invalid envelope cases.
- Scheduler tests must enforce per-session ordering and queue pressure behavior.
- Pairing tests must cover key load, signature verification, challenge crypto, and full handshake flow.
- Pairing tests must cover CSR signing/verification and certificate issuance failure paths.
- Cross-module pairing process behavior is validated by root integration tests in `integration/`.

## Current focus
- Gateway-initiated pairing hardening, including CA-backed mTLS cert issuance and CSR validation.
