# AGENTS.md

## Bootstrap
This repository is organized for a modular Go codebase with multiple projects/packages.

## Repository structure
- `spec/`: product and protocol specifications.
- `integration/`: root-level end-to-end tests that exercise multiple modules together.
- `lib/types/`: standalone shared Go module for protocol/domain types (`module crabstack.local/lib/types`).
- `projects/`: implementation projects/modules (gateway, listeners, services, shared libs, etc).
- `go.work`: root workspace file to wire local modules together.

## Spec index
- `spec/OVERVIEW.md`
- `spec/SECURITY.md`
- `spec/PEER_AUTH_MODEL.md`
- `spec/EVENT_SCHEMA.md`
- `spec/TOOL_SCHEMA.md`
- `spec/PAIRING_STRUCTS.md`

Files in docs/ are not sources-of-truth, and may lag behind. Always refer to spec/ files instead.

## Working conventions
- Treat files under `spec/` as source of truth for behavior/contracts.
- Keep code under `projects/` aligned with `spec/` contracts.
- Keep root integration tests in `integration/` focused on gateway+client process behavior (real sockets, real DB).
- When adding or renaming spec documents, update this index in the same change.
- Tests are mandatory. Ensure the test cases match reality and cover as many edge cases as possible. A feature is not complete if its not heavily tested.
- AGENTS.md files are present in every project and in some other subdirectories. ALWAYS read them when working on a specific project, and keep them updated to match reality. 

## Configuration
- Configuration is primarily done with .yaml files. Each yaml key should have an accompanying ENV_VAR.
- CLI commands can define flags, like `--agent-id <id>`. These flags should never have a ENV_VAR option, unless they also have a yaml key dedicated to them.
- Positional CLI arguments should never have a flag or ENV_VAR version of them.

## Code style & quality
- All code must follow single-responsibility patterns, be clear on what it does and optimize for readability.
- All code must be modular regardless of its use in other files/projects. Always assume code will be reused, and write it for reusability.
- Private & public apis are contracts. Use private APIs as barriers to avoid details and assumptions from leaking into consumers. Consider the best shape for a caller when exposing public methods. A config consumer should not have to know where a config file lives, its format or any other internals. It should be able to ask for a config key and receive a value.