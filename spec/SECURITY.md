# Security and Pairing Model

## Scope
This document defines transport security, trust bootstrapping, remote pairing, and authorization boundaries for Crabstack components.

## Transport trust model
- In-host communication:
  - Use Unix domain sockets (including Windows AF_UNIX).
  - No transport auth.
  - No transport encryption.
  - Gateway admin control-plane (including pairing trigger) runs only on this local transport.
- Remote communication:
  - mTLS is required.
  - Plain HTTP/WS is not allowed for runtime traffic.

## Gateway identity at setup
- Generate gateway identity keypair:
  - `ed25519` private key
  - `ed25519` public key
- Generate or load local pairing CA material:
  - CA private key (local only)
  - CA certificate (used as trust anchor for issued remote certs)
- Store gateway private key locally with strict filesystem permissions.
- Gateway public key is operator-distributed to remote components.

## Remote component onboarding
- Remote listener/subscriber/tool-host/operator must be configured with `gateway_public_key_ed25519`.
- Remote component must reject pairing initiation when the gateway signature does not verify.
- Gateway only connects to remote components that are explicitly paired.

## Pairing flow (gateway initiated)
CLI commands:

```bash
crab pair test
crab pair tool wss://10.0.0.1:5225 memory-east
crab pair subscriber wss://10.0.0.2:7443/v1/pair discord-outbound
crab pair cli wss://10.0.0.3:7443/v1/pair gin-laptop
```

Command rules:
- `component_type` is inferred from subcommand (`tool`, `subscriber`, `cli`).
- `cli` maps to `component_type=operator`.
- `component_id` is provided as positional `<name>`.
- `--admin-socket` remains an optional flag for all `crab pair *` commands.
- `crab pair test` must run with sensible defaults so operators can validate pairing quickly.

Flow:
1. Operator/CLI sends pair request to gateway admin Unix socket.
2. Gateway opens outbound pairing session to remote endpoint and sends signed initiation payload.
3. Remote verifies signature using configured gateway public key.
4. Remote sends identity payload and public key material.
5. Gateway sends encrypted challenge.
6. Remote decrypts and echoes challenge plaintext.
7. Remote sends signed CSR request payload (`pair.csr_request`).
8. Gateway validates CSR and issues mTLS certificate from local pairing CA (`pair.csr_issued`).
9. Remote installs issued cert and responds with signed install confirmation (`pair.csr_installed`) that includes issued fingerprint.
10. Gateway validates install confirmation and marks pairing complete.

Notes:
- Pairing initiation is not exposed on public HTTP/WS ingress.
- Gateway is always the active handshake initiator toward remote components.
- Pairing trigger remains local-admin only, including when a remote CLI is paired for management.

## Cryptography requirements
- Ed25519 is signature-only.
- Encrypted challenge must use encryption-capable material:
  - X25519-derived shared key (recommended), or
  - mTLS exporter-based keying material.
- Do not attempt encryption with Ed25519 keys.

## Authorization boundaries
- Listener: ingress write privileges only.
- Subscriber: event stream read privileges only.
- Tool host: callable methods constrained by explicit tool policy.
- Paired CLI (`component_type=operator`) may receive a `cli_admin` role profile for remote management.
- `cli_admin` does not grant remote pairing initiation; pairing stays local admin socket only.
- Remote requests must fail closed if mTLS peer identity does not match a paired record.

## Subscription-backed provider auth states (gateway-internal)
- `valid`
- `expiring`
- `reauth_required`

## Codex subscription OAuth bootstrap (CLI)
- Command: `crab auth codex`
- Uses OAuth authorization code + PKCE against:
  - `https://auth.openai.com/oauth/authorize`
  - `https://auth.openai.com/oauth/token`
- Uses localhost callback (`127.0.0.1:1455/auth/callback`) with manual paste fallback when callback cannot be received.
- Persisted credential file contains:
  - `access_token`
  - `refresh_token`
  - `expires_at`
  - extracted ChatGPT account id claim (`https://api.openai.com/auth.chatgpt_account_id`)
- Default credential path: `~/.crabstack/auth/codex.json`
- Credentials file and parent directory must be created with owner-only permissions.

## Anthropic subscription OAuth bootstrap (CLI)
- Command: `crab auth anthropic`
- Uses OAuth authorization code + PKCE against:
  - `https://platform.claude.com/oauth/authorize`
  - `https://platform.claude.com/v1/oauth/token`
- Uses manual code/redirect paste after browser authorization.
- Persisted credential file contains:
  - `access_token`
  - `refresh_token`
  - `expires_at`
  - provider/account metadata when available (`account_id`, `account_email`, account metadata map)
- Default credential path: `~/.crabstack/auth/anthropic.json`
- Credentials file and parent directory must be created with owner-only permissions.

## Persistence requirements
- Persist paired remote identity metadata and status.
- Suggested stored fields:
  - `component_type`
  - `component_id`
  - `endpoint`
  - `public_key_ed25519`
  - `public_key_x25519`
  - `mtls_cert_fingerprint`
  - `paired_at`
  - `last_seen_at`
  - `status`
- Persist local pairing CA files under gateway key dir (durable across restarts).

## Related docs
- `OVERVIEW.md`
- `PEER_AUTH_MODEL.md`
- `EVENT_SCHEMA.md`
- `TOOL_SCHEMA.md`
- `PAIRING_STRUCTS.md`
