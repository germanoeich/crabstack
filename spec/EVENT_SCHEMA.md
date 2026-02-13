# Event Schema (Draft v1)

This defines the canonical envelope every module uses (gateway, listeners, subscribers, cron, memory).

## Envelope JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "pinchy/event-envelope-v1",
  "title": "Pinchy Event Envelope v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "event_id",
    "trace_id",
    "occurred_at",
    "event_type",
    "tenant_id",
    "source",
    "routing",
    "payload"
  ],
  "properties": {
    "version": {
      "type": "string",
      "const": "v1"
    },
    "event_id": {
      "type": "string",
      "description": "UUIDv7 recommended"
    },
    "trace_id": {
      "type": "string",
      "description": "Cross-service correlation id"
    },
    "idempotency_key": {
      "type": "string",
      "description": "Required for externally retried producers"
    },
    "occurred_at": {
      "type": "string",
      "format": "date-time"
    },
    "event_type": {
      "type": "string",
      "enum": [
        "channel.message.received",
        "channel.message.edited",
        "channel.message.deleted",
        "cron.triggered",
        "heartbeat.tick",
        "agent.turn.started",
        "agent.turn.completed",
        "agent.turn.failed",
        "agent.response.created",
        "tool.call.requested",
        "tool.call.completed",
        "tool.call.failed",
        "pairing.started",
        "pairing.completed",
        "pairing.failed",
        "config.applied",
        "config.reverted"
      ]
    },
    "tenant_id": {
      "type": "string"
    },
    "source": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "component_type",
        "component_id"
      ],
      "properties": {
        "component_type": {
          "type": "string",
          "enum": [
            "listener",
            "gateway",
            "subscriber",
            "cron",
            "tool_host",
            "operator"
          ]
        },
        "component_id": {
          "type": "string"
        },
        "platform": {
          "type": "string",
          "description": "discord, whatsapp, slack, etc"
        },
        "channel_id": {
          "type": "string"
        },
        "actor_id": {
          "type": "string"
        },
        "message_id": {
          "type": "string"
        },
        "request_id": {
          "type": "string"
        },
        "peer_id": {
          "type": "string",
          "description": "Paired remote component id, if remote"
        },
        "mtls_cert_fingerprint": {
          "type": "string",
          "description": "Peer cert fingerprint for remote transport"
        },
        "transport": {
          "type": "string",
          "enum": [
            "unix_socket",
            "http",
            "ws",
            "mtls_http",
            "mtls_ws",
            "internal"
          ]
        }
      }
    },
    "routing": {
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
        "isolation_key": {
          "type": "string",
          "description": "If omitted, memory scope defaults to global"
        },
        "target": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "platform": {
              "type": "string"
            },
            "channel_id": {
              "type": "string"
            },
            "thread_id": {
              "type": "string"
            },
            "address": {
              "type": "string",
              "description": "phone number or equivalent"
            }
          }
        },
        "policy_tags": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      }
    },
    "payload": {
      "type": "object"
    },
    "meta": {
      "type": "object",
      "additionalProperties": true
    }
  }
}
```

## Payload contracts (initial)

### `channel.message.received`

```json
{
  "text": "string",
  "attachments": [
    {
      "type": "image|audio|file|video",
      "url": "string",
      "mime_type": "string",
      "name": "string"
    }
  ],
  "reply_to_message_id": "string",
  "raw": {}
}
```

### `cron.triggered`

```json
{
  "job_id": "string",
  "job_name": "string",
  "scheduled_for": "2026-02-13T15:30:00Z",
  "triggered_at": "2026-02-13T15:30:01Z",
  "input": {},
  "reason": "heartbeat|scheduled_task"
}
```

### `agent.response.created`

```json
{
  "response_id": "string",
  "content": [
    {
      "type": "text",
      "text": "string"
    }
  ],
  "actions": [
    {
      "kind": "send_message|react|platform_action",
      "target_override": {},
      "args": {}
    }
  ],
  "usage": {
    "input_tokens": 0,
    "output_tokens": 0,
    "model": "string",
    "provider": "string"
  }
}
```

### `tool.call.requested`

```json
{
  "call_id": "string",
  "tool_name": "string",
  "args": {},
  "timeout_ms": 30000
}
```

### `tool.call.completed`

```json
{
  "call_id": "string",
  "tool_name": "string",
  "status": "ok",
  "result": {},
  "duration_ms": 123
}
```

### `tool.call.failed`

```json
{
  "call_id": "string",
  "tool_name": "string",
  "status": "error|timeout|retryable_error",
  "error": {
    "code": "string",
    "message": "string",
    "retryable": true
  },
  "duration_ms": 123
}
```

### `pairing.started`

```json
{
  "pairing_id": "string",
  "remote_uri": "ws://10.0.0.1:5225",
  "remote_component_type": "tool_host|listener|subscriber|provider"
}
```

### `pairing.completed`

```json
{
  "pairing_id": "string",
  "remote_component_id": "string",
  "remote_component_type": "tool_host|listener|subscriber|provider",
  "remote_public_key_ed25519": "base64...",
  "remote_public_key_x25519": "base64...",
  "mtls_cert_fingerprint": "sha256:..."
}
```

### `pairing.failed`

```json
{
  "pairing_id": "string",
  "remote_uri": "ws://10.0.0.1:5225",
  "error_code": "SIGNATURE_INVALID|CHALLENGE_FAILED|TIMEOUT|UNREACHABLE",
  "error_message": "string"
}
```

### `config.applied`

```json
{
  "revision_id": "string",
  "checksum": "sha256:...",
  "applied_by": "agent|operator",
  "source_platform": "discord",
  "source_channel_id": "string",
  "validation": {
    "schema_valid": true,
    "semantic_valid": true,
    "smoke_test_passed": true
  }
}
```

## Processing rules
- Gateway enforces strict per-session ordering for turn-driving event types.
- Subscriber delivery is at-least-once and may be out of order.
- Consumers must dedupe with `event_id` and/or `idempotency_key`.
- If `routing.target` is missing for internal events, gateway resolves target from session `last_active_channel`.
- Remote events must carry peer identity metadata (`peer_id` and `mtls_cert_fingerprint`) once pairing is complete.

## Go type hints
- Prefer `json.RawMessage` for `payload` and decode by `event_type`.
- Store envelope with immutable canonical JSON in `turns` and `event_outbox`.
- Use typed wrappers for high-frequency events (`channel.message.received`, `agent.response.created`, `cron.triggered`).
