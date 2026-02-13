# Security and Pairing Model

## Scope
This document defines transport security, trust bootstrapping, remote pairing, and authorization boundaries for Pinchy components.

## Transport trust model
- In-host communication:
  - Use Unix domain sockets (including Windows AF_UNIX).
  - No transport auth.
  - No transport encryption.
- Remote communication:
  - mTLS is required.
  - Plain HTTP/WS is not allowed for runtime traffic.

## Gateway identity at setup
- Generate gateway identity keypair:
  - `ed25519` private key
  - `ed25519` public key
- Store gateway private key locally with strict filesystem permissions.
- Gateway public key is operator-distributed to remote components.

## Remote component onboarding
- Remote listener/subscriber/provider/tool-host must be configured with `gateway_public_key_ed25519`.
- Remote component must reject pairing initiation when the gateway signature does not verify.
- Gateway only connects to remote components that are explicitly paired.

## Pairing flow (gateway initiated)
Command example:

```bash
pinchy pair tool ws://10.0.0.1:5225
```

Flow:
1. Gateway opens pairing session and sends signed initiation payload.
2. Remote verifies signature using configured gateway public key.
3. Remote sends identity payload and public key material.
4. Gateway stores remote identity metadata.
5. Gateway sends encrypted challenge.
6. Remote decrypts and echoes challenge plaintext.
7. Gateway validates response and marks pairing complete.

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
- Remote requests must fail closed if mTLS peer identity does not match a paired record.

## Subscription-backed provider auth states
- `valid`
- `expiring`
- `reauth_required`

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

## Related docs
- `OVERVIEW.md`
- `EVENT_SCHEMA.md`
- `TOOL_SCHEMA.md`
- `PAIRING_STRUCTS.md`
