# crab-cli

Terminal UI client for Crabstack pairing + event exchange.

## What it does
- Runs a TUI (`tview`) interface.
- Sends `channel.message.received` events to gateway.
- Receives gateway `EventEnvelope` messages and renders them live.
- Supports `pair` command to pair CLI with gateway using full CSR flow.

## Pair CLI With Gateway
From `projects/crab-cli`:

```bash
CRAB_CLI_GATEWAY_PUBLIC_KEY_ED25519='<gateway-ed25519-pub-b64>' \
crab pair \
  -admin-socket .crabstack/run/gateway-admin.sock \
  -component-type tool_host \
  -component-id crab-cli
```

The `pair` command:
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
- Gateway public key is required and strictly verified.
- Pair challenge decryption uses the ephemeral key material provided in challenge `aad`.
