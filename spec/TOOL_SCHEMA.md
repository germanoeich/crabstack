# Remote Tool Protocol (Draft v1, non-MCP)

This protocol lets gateway call remote tools hosted by memory, cron, and other services.

## Transport modes
- Local (same host): Unix domain sockets only.
- Local mode security: no auth and no encryption.
- Remote: mTLS only.
- Remote mode requirement: component must be paired before any `/v1/tools/*` call is accepted.

## Identity and trust
- Gateway setup generates an Ed25519 keypair.
- Gateway public key is distributed to remote components by operator config.
- Remote components must verify gateway-signed pairing initiation using that public key.
- Gateway persists paired component identity and only connects to known paired peers.

## Important crypto note
- Ed25519 is for signatures only.
- Any encrypted challenge step must use encryption-capable key material (for example X25519), or mTLS exporter/keying material.

## Endpoints
- `GET /v1/tools` discovery metadata.
- `POST /v1/tools/call` synchronous execution.
- Optional later: `POST /v1/tools/cancel`.

## Pairing handshake (gateway initiated)
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
- `--admin-socket` is the only pairing transport override flag.
- `crab pair test` uses defaults and is intended for local/operator verification.

### Phase 0: prerequisites
- Gateway exposes local admin Unix socket for control-plane requests.
- CLI/operator sends pair request through admin socket (no auth on local transport).
- Remote component is configured with `gateway_public_key_ed25519`.
- Remote component exposes pairing WS endpoint.
- Pairing trigger endpoints are not exposed on public HTTP/WS ingress.

### Phase 1: signed initiation
Gateway sends over outbound WS:

```json
{
  "type": "pair.init",
  "version": "v1",
  "pairing_id": "01JXYZ...",
  "gateway": {
    "gateway_id": "gw_home",
    "public_key_ed25519": "base64...",
    "nonce": "base64...",
    "issued_at": "2026-02-13T16:00:00Z"
  },
  "sig_ed25519": "base64..."
}
```

Remote must verify `sig_ed25519` against configured gateway public key.

### Phase 2: remote identity response
Remote replies:

```json
{
  "type": "pair.identity",
  "version": "v1",
  "pairing_id": "01JXYZ...",
  "remote": {
    "component_type": "tool_host",
    "component_id": "memory-east-1",
    "public_key_ed25519": "base64...",
    "public_key_x25519": "base64...",
    "mtls_cert_fingerprint": "sha256:..."
  },
  "sig_ed25519": "base64..."
}
```

Gateway verifies signature and stores remote identity metadata.

### Phase 3: proof-of-possession challenge
Gateway sends challenge encrypted for remote:

```json
{
  "type": "pair.challenge",
  "version": "v1",
  "pairing_id": "01JXYZ...",
  "challenge_id": "01JXYZ...",
  "ciphertext": "base64...",
  "aad": "base64..."
}
```

Remote decrypts and echoes plaintext:

```json
{
  "type": "pair.challenge_response",
  "version": "v1",
  "pairing_id": "01JXYZ...",
  "challenge_id": "01JXYZ...",
  "challenge_plaintext": "base64...",
  "sig_ed25519": "base64..."
}
```

### Phase 4: CSR request
Remote sends a signed certificate signing request:

```json
{
  "type": "pair.csr_request",
  "version": "v1",
  "pairing_id": "01JXYZ...",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "sig_ed25519": "base64..."
}
```

### Phase 5: cert issuance
Gateway returns the issued mTLS certificate and chain:

```json
{
  "type": "pair.csr_issued",
  "version": "v1",
  "pairing_id": "01JXYZ...",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "certificate_chain_pem": ["-----BEGIN CERTIFICATE-----..."],
  "serial_number": "abc123",
  "mtls_cert_fingerprint": "sha256:...",
  "not_before": "2026-02-13T16:00:00Z",
  "not_after": "2027-02-13T16:00:00Z",
  "sig_ed25519": "base64..."
}
```

### Phase 6: install confirmation
Remote installs and confirms:

```json
{
  "type": "pair.csr_installed",
  "version": "v1",
  "pairing_id": "01JXYZ...",
  "mtls_cert_fingerprint": "sha256:...",
  "sig_ed25519": "base64..."
}
```

### Phase 7: completion
Gateway responds:

```json
{
  "type": "pair.complete",
  "version": "v1",
  "pairing_id": "01JXYZ...",
  "status": "ok"
}
```

Gateway marks peer as paired and allows mTLS traffic.

## Peer authorization requirements
- Pairing only establishes identity; runtime tool/event permissions are enforced separately.
- Default role behavior:
  - `tool_host`: subscribe `tool.call.requested`, publish `tool.call.completed|tool.call.failed`.
  - `subscriber`: may not consume or publish `tool.call.*` by default.
  - `cli_admin` (paired CLI with `component_type=operator`): can manage runtime/config control-plane but cannot initiate pairing remotely.
- Effective permissions are `role defaults + peer policy overrides + temporary lease scope`, with deny precedence.
- See `PEER_AUTH_MODEL.md` for full peer class and authz contract.

## `GET /v1/tools` response schema

```json
{
  "version": "v1",
  "service": "memory-service",
  "tools": [
    {
      "name": "memory.append",
      "description": "Append memory entries for a scoped context",
      "input_schema": {},
      "output_schema": {},
      "timeout_ms_default": 30000,
      "timeout_ms_max": 120000,
      "idempotent": false,
      "side_effects": true
    }
  ]
}
```

## `POST /v1/tools/call` request schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "crabstack/tool-call-request-v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "call_id",
    "tool_name",
    "tenant_id",
    "args",
    "context"
  ],
  "properties": {
    "version": {
      "type": "string",
      "const": "v1"
    },
    "call_id": {
      "type": "string",
      "description": "UUIDv7 recommended"
    },
    "idempotency_key": {
      "type": "string"
    },
    "tool_name": {
      "type": "string"
    },
    "tenant_id": {
      "type": "string"
    },
    "args": {
      "type": "object"
    },
    "timeout_ms": {
      "type": "integer",
      "minimum": 1,
      "maximum": 120000
    },
    "context": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "agent_id",
        "session_id"
      ],
      "properties": {
        "agent_id": {
          "type": "string"
        },
        "session_id": {
          "type": "string"
        },
        "platform": {
          "type": "string"
        },
        "channel_id": {
          "type": "string"
        },
        "actor_id": {
          "type": "string"
        },
        "isolation_key": {
          "type": "string",
          "description": "Unset means global memory scope"
        },
        "trace_id": {
          "type": "string"
        },
        "request_origin": {
          "type": "string",
          "enum": [
            "agent_turn",
            "cron",
            "operator",
            "system"
          ]
        }
      }
    }
  }
}
```

## `POST /v1/tools/call` response schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "crabstack/tool-call-response-v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "call_id",
    "tool_name",
    "status",
    "duration_ms"
  ],
  "properties": {
    "version": {
      "type": "string",
      "const": "v1"
    },
    "call_id": {
      "type": "string"
    },
    "tool_name": {
      "type": "string"
    },
    "status": {
      "type": "string",
      "enum": [
        "ok",
        "error",
        "retryable_error",
        "timeout"
      ]
    },
    "result": {
      "type": "object"
    },
    "error": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "code": {
          "type": "string"
        },
        "message": {
          "type": "string"
        },
        "details": {
          "type": "object"
        },
        "retryable": {
          "type": "boolean"
        }
      }
    },
    "duration_ms": {
      "type": "integer",
      "minimum": 0
    },
    "logs": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  }
}
```

## Standard error codes
- `TOOL_NOT_FOUND`
- `INVALID_ARGS`
- `UNAUTHORIZED`
- `FORBIDDEN`
- `RATE_LIMITED`
- `DEPENDENCY_UNAVAILABLE`
- `TIMEOUT`
- `INTERNAL`
- `PAIRING_REQUIRED`
- `PAIRING_FAILED`

## Reliability and execution rules
- Gateway sets a timeout per call; host must hard-stop after timeout.
- Calls are retried only when `status=retryable_error` or transport failure.
- Idempotent tools must accept duplicate `idempotency_key` safely.
- Side-effecting tools should return a stable operation identifier for dedupe.
- Remote calls must fail closed when mTLS peer identity does not match a paired record.

## Suggested initial tool set
- Memory host:
  - `memory.append`
  - `memory.query`
  - `memory.delete`
- Cron host:
  - `cron.list`
  - `cron.create`
  - `cron.remove`

## Example: `cron.create` call

```json
{
  "version": "v1",
  "call_id": "01JXYZ...",
  "tool_name": "cron.create",
  "tenant_id": "home",
  "idempotency_key": "cron-create-home-heartbeat-1",
  "args": {
    "name": "heartbeat",
    "schedule": "*/5 * * * *",
    "event_type": "heartbeat.tick",
    "input": {}
  },
  "timeout_ms": 10000,
  "context": {
    "agent_id": "assistant",
    "session_id": "ses_123",
    "platform": "whatsapp",
    "channel_id": "+15551234567",
    "actor_id": "owner",
    "trace_id": "01JXYZ...",
    "request_origin": "agent_turn"
  }
}
```
