# AGENTS.md

## Scope
These instructions apply to everything under `docs/`.

## Audience split
- Default audience is **operators**.
- Integration/developer content lives under `docs/integrations/`.
- If a topic has both audiences, keep the operator page concise and task-oriented, and link to the integration page for contracts and protocol details.

## Source of truth
- Treat `spec/` as canonical.
- Keep docs aligned with:
  - `spec/OVERVIEW.md`
  - `spec/SECURITY.md`
  - `spec/PEER_AUTH_MODEL.md`
  - `spec/EVENT_SCHEMA.md`
  - `spec/TOOL_SCHEMA.md`
  - `spec/PAIRING_STRUCTS.md`
- If specs change, update docs in the same change.

## Format requirements
- Use `.mdx` for docs pages.
- Every `.mdx` file must start with frontmatter containing:
  - `title`
  - `description`
- Keep content practical and decision-focused.

## Writing style
- Lead with operations impact and concrete steps.
- Avoid unnecessary protocol/type detail in operator docs.
- Put low-level contracts, schemas, and flow internals in `docs/integrations/`.
- Call out tradeoffs, risks, and unknowns directly.

## Collaboration preferences
- When requests are unclear or there are meaningful implementation options, ask clarifying questions in one batch before writing large changes.
- Do not assume user intent when the repo reality suggests otherwise; confirm and then proceed.
