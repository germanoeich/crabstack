# Peer Classes and Authorization Model (Draft v1)

## Scope
This spec defines peer identity lifecycle, peer classes, and authorization behavior for remote and local gateway integrations.

## Goals
- Allow durable paired peers to reconnect without re-pairing.
- Support session-scoped temporary runtime attachments (for example `crab chat new`).
- Enforce role-based least privilege by default.
- Keep pairing control-plane local-only on the admin Unix socket.

## Terminology
- `peer principal`: durable identity established by pairing (`component_type`, `component_id`, keys, cert fingerprint).
- `persistent peer`: durable paired principal expected to reconnect over time.
- `temporary peer lease`: short-lived runtime grant tied to a scope (usually session), optionally bound to a live connection.
- `role`: default permission profile (tool host, subscriber, listener, cli admin).
- `policy`: operator-defined allow/deny overrides for a principal.

## Core decisions
- Pairing is identity bootstrap only; pairing does not create session-scoped runtime grants.
- Runtime privileges are derived from role + policy + optional temporary lease.
- Deny-by-default for all remote peer actions.
- Pairing initiation (`crab pair ...`) remains admin-socket-only.

## Pairing command grammar
Pairing commands:

```bash
crab pair test
crab pair tool <endpoint> <name>
crab pair subscriber <endpoint> <name>
crab pair cli <endpoint> <name>
```

Mapping rules:
- `tool` -> `component_type=tool_host`, `role=tool_host`
- `subscriber` -> `component_type=subscriber`, `role=subscriber`
- `cli` -> `component_type=operator`, `role=cli_admin`
- `<name>` -> `component_id`
- `crab pair test` is a local handshake verification helper.

Notes:
- `crab pair` is never exposed on public ingress.
- Remote peers cannot initiate pairing.

## Peer classes

### Persistent peer
- Created by successful pairing.
- Stored durably.
- Reconnect is allowed without re-pairing when identity checks pass.
- Reconnect updates `last_seen_at`; identity record remains stable unless explicitly rotated/re-paired.

### Temporary peer lease
- Created at runtime after principal authentication.
- Scoped to tenant/agent/session and explicit capabilities.
- Revoked automatically on:
  - lease expiration,
  - owning connection close (when `disconnect_bound=true`),
  - session close,
  - explicit revoke.
- Not a replacement for pairing identity.

## Authentication model

### Local in-host transport
- Unix socket only.
- No transport auth or encryption.
- Treated as trusted local control-plane boundary.

### Remote transport
- mTLS required.
- Gateway resolves principal from paired peer record and mTLS identity metadata.
- Missing/unknown/mismatched identity fails closed.

## Authorization model
Authorization decision inputs:
1. Authenticated principal.
2. Principal role defaults.
3. Principal policy overrides from YAML config.
4. Optional temporary lease scope.
5. Requested action.

Decision rules:
- Default deny.
- Explicit deny overrides allow.
- Temporary lease can only reduce scope (never expand beyond role+policy).

Action namespaces:
- `events.publish:<event_type>`
- `events.subscribe:<event_type>`
- `control.config:*`
- `control.sessions:*`
- `control.peers:*`
- `control.subscriptions:*`

## Default role profiles

| Role | Component Type | Allowed Publish | Allowed Subscribe | Allowed Control |
|---|---|---|---|---|
| `tool_host` | `tool_host` | `tool.call.completed`, `tool.call.failed` | `tool.call.requested` | none |
| `subscriber` | `subscriber` | none | `channel.*`, `cron.*`, `heartbeat.tick`, `agent.*` | none |
| `listener` | `listener` | `channel.message.received`, `channel.message.edited`, `channel.message.deleted` | none | none |
| `cli_admin` | `operator` | any | any | `config.*`, `sessions.*`, `peers.*`, `subscriptions.*` |

`cli_admin` constraints:
- Can manage config, sessions, and subscriptions.
- Cannot trigger pairing remotely.
- Pairing trigger stays local admin socket only.

## Temporary lease model for `crab chat new`
Recommended flow:
1. Paired CLI authenticates as `cli_admin`.
2. CLI requests:
   - session creation (or bind to existing session),
   - temporary producer lease scoped to one session,
   - temporary subscriber lease scoped to same session.
3. CLI publishes `channel.message.received` in that session scope.
4. CLI subscribes to `agent.response.created` (and optional `agent.turn.*`) in that session scope.
5. On session close or disconnect, leases are revoked.

This keeps CLI principal durable while chat wiring remains temporary.

## Persistence requirements
Persistent principal storage (`paired_peers`) should include:
- `component_type`
- `component_id`
- `role`
- `endpoint`
- `public_key_ed25519`
- `public_key_x25519`
- `mtls_cert_fingerprint`
- `status`
- `paired_at`
- `last_seen_at`
- `policy_json` (or equivalent normalized policy tables)

Temporary lease storage (`peer_leases`) should include:
- `lease_id`
- `owner_component_type`
- `owner_component_id`
- `tenant_id`
- `agent_id`
- `session_id`
- `capabilities_json`
- `disconnect_bound`
- `issued_at`
- `expires_at`
- `revoked_at`
- `revoke_reason`

## Config model (YAML-driven)
Operator config should define:
- peer inventory (persistent principals),
- role assignment per peer,
- policy overrides (allow/deny event/control scopes),
- temporary lease defaults (TTL, renewal window, max leases per peer).

Agents may mutate config only through validated config tools.

## Non-goals (v1)
- User account/login model.
- Internet-exposed pairing APIs.
- Capability expansion via temporary lease beyond principal role.
- Provider peer role; providers stay gateway-internal for now.
