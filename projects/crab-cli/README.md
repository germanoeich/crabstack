# crab-cli

Terminal UI client for Crabstack pairing + event exchange.

## What it does
- Runs a TUI (`tview`) interface.
- Sends `channel.message.received` events to gateway.
- Receives gateway `EventEnvelope` messages and renders them live.
- Supports gateway-initiated pairing commands:
  - `crab pair tool <endpoint> <name>`
  - `crab pair subscriber <endpoint> <name>`
  - `crab pair cli <endpoint> <name>`
  - `crab pair test`
- Supports one-shot event send:
  - `crab event send <text>`
- Supports subscription OAuth login:
  - `crab auth codex`
  - `crab auth anthropic`
- Supports catalog-driven command help:
  - `crab help`
  - `crab help <command>`

## Pair External Component (Gateway-Initiated)
From `projects/crab-cli`:

```bash
crab pair tool wss://10.0.0.1:5225/v1/pair memory-east
crab pair subscriber wss://10.0.0.2:7443/v1/pair discord-outbound
crab pair cli wss://10.0.0.3:7443/v1/pair laptop-admin
```

The `pair tool` / `pair subscriber` / `pair cli` commands:
- Calls gateway admin Unix socket `POST /v1/pairings`.
- Sends `component_type` from subcommand and `component_id` from `<name>`.
- Does not host a local websocket endpoint.
- Prints `pairing_id`, endpoint, resolved component identity, and certificate fingerprint.

## Send Event
From `projects/crab-cli`:

```bash
crab event send "hello from cli"
```

The `event send` command:
- Sends one `channel.message.received` envelope to `POST /v1/events`.
- Uses `source.platform=cli` and `source.channel_id=cli` by default.
- Creates a new session id per call (`cli-...`) with sensible defaults for tenant/agent/source fields.

## Codex OAuth Login
From `projects/crab-cli`:

```bash
crab auth codex
```

The `auth codex` command:
- Prints the OpenAI authorize URL.
- Starts a localhost callback listener (`127.0.0.1:1455` by default).
- Falls back to manual paste when callback cannot be received.
- Exchanges the auth code using PKCE.
- Stores credentials JSON at `~/.crabstack/auth/codex.json` by default for gateway consumption (override with `--auth-file`).

## Anthropic OAuth Login
From `projects/crab-cli`:

```bash
crab auth anthropic
```

The `auth anthropic` command:
- Prints the Anthropic authorize URL.
- Uses manual code/redirect paste after browser approval.
- Exchanges the auth code using PKCE.
- Stores credentials JSON at `~/.crabstack/auth/anthropic.json` by default for gateway consumption (override with `--auth-file`).

## Pairing Handshake Test
From `projects/crab-cli`:

```bash
crab pair test
```

The `pair test` command:
- Starts a temporary local WS pairing endpoint.
- Calls gateway admin Unix socket `POST /v1/pairings`.
- Completes full handshake:
  - `pair.init`
  - `pair.identity`
  - `pair.challenge`
  - `pair.challenge_response`
  - `pair.csr_request`
  - `pair.csr_issued`
  - `pair.csr_installed`
  - `pair.complete`
- Prints `pairing_id`, endpoint, and issued certificate fingerprint.
- Uses defaults so it can run without extra args. `-gateway-public-key` is optional; if unset, CLI loads gateway public key from `<CRAB_GATEWAY_KEY_DIR>/gateway_identity.json` (default `.crabstack/keys/gateway_identity.json`).

## Help
From `projects/crab-cli`:

```bash
crab help
crab help event send
```

## Run
From `projects/crab-cli`:

```bash
CRAB_CLI_GATEWAY_PUBLIC_KEY_ED25519='<gateway-ed25519-pub-b64>' \
crab \
  -gateway-ws ws://127.0.0.1:8080/v1/pair
```

Then type into the `Send text>` input and press Enter.
Use `/quit` to exit.

## Protocol notes
- Gateway public key is required and strictly verified for websocket handshake flows (`crab` TUI / `crab pair test`).
- Pair challenge decryption uses the ephemeral key material provided in challenge `aad`.
