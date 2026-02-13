# AGENTS.md

## Bootstrap
This repository is organized for a modular Go codebase with multiple projects/packages.

## Repository structure
- `spec/`: product and protocol specifications.
- `lib/types/`: standalone shared Go module for protocol/domain types (`module pinchy/lib/types`).
- `projects/`: implementation projects/modules (gateway, listeners, services, shared libs, etc).
- `go.work`: root workspace file to wire local modules together.

## Spec index
- `spec/OVERVIEW.md`
- `spec/SECURITY.md`
- `spec/EVENT_SCHEMA.md`
- `spec/TOOL_SCHEMA.md`
- `spec/PAIRING_STRUCTS.md`

## Working conventions
- Treat files under `spec/` as source of truth for behavior/contracts.
- Keep code under `projects/` aligned with `spec/` contracts.
- When adding or renaming spec documents, update this index in the same change.
- Tests are mandatory. Ensure the test cases match reality and cover as many edge cases as possible. A feature is not complete if its not heavily tested.
- AGENTS.md files are present in every project and in some other subdirectories. ALWAYS read them when working on a specific project, and keep them updated to match reality. 