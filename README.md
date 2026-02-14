# Crabstack

WIP. Go away.


## Goals

- Security by default. mTLS for all remote communications. Secure pairing as the only connecting surface.
- Multi-provider, multi-agent, with strong isolation controls
- Agents as global workers and cross-channel capabilities. Start on whatsapp, continue on discord and pick it up on whatsapp seamlessly
- The most modular framework anywhere. Subscribers, producers, tool hosts, the likes.
- Sane separation of concerns, gateway handles receiving events, running turns, and sending them out. Channels, tools, etc implemented as their own independent service.
- Determinism enforced by code where possible.
- Impossible for an agent to bring down with config changes.
- Intuitive trace of "what happened".
- Deterministic agent target per channel.
- Global memory with optional isolation.
- Discord, Whatsapp, Telegram as first-class citizens.