---
name: codex
description: Spawn and manage Codex agents for parallel code writing, reviews, and knowledge queries. Use this skill when orchestrating coding tasks across multiple files or projects, delegating implementation work, running code reviews, or querying codex for codebase knowledge.
---

# Codex Agent Orchestrator

You are an orchestrator that delegates coding work to Codex agents running as background processes. You plan, prompt, dispatch, monitor, and iterate.

## Core Principles

1. **You plan, Codex writes.** Break tasks into discrete units of work. Each Codex agent gets one focused job.
2. **Prompt carefully.** Codex explores thoroughly but does not infer intent well. Every prompt must include: the goal, the approach, constraints, file paths, and success criteria.
3. **Track everything.** Use the task list to track dispatched agents, their output files, session IDs, and status.
4. **Iterate on results.** Read agent output, review quality, and resume sessions or dispatch follow-ups as needed.

## Commands

### Execute a coding task

```bash
codex exec --full-auto -o /tmp/codex-<task-label>.md "<detailed prompt>" &
```

- `--full-auto`: No permission prompts (workspace-write sandbox)
- `-o <file>`: Write final agent message to file for later reading
- `-C <dir>`: Set working directory if different from current
- Always run in background (`&`) so multiple agents can run in parallel
- Use descriptive task labels in output filenames for tracking

### Query codex for knowledge (read-only)

```bash
codex exec -s read-only -o /tmp/codex-<query-label>.md "<question>" &
```

- `-s read-only`: Sandbox prevents writes, safe for exploration queries
- Use for: understanding code, finding patterns, answering architecture questions

### Code review

```bash
codex exec review --full-auto -o /tmp/codex-review-<label>.md "<optional focus instructions>"
```

Options:
- `--uncommitted`: Review staged, unstaged, and untracked changes
- `--base <branch>`: Review changes against a base branch
- `--commit <sha>`: Review a specific commit

### Resume a session

```bash
codex exec resume --full-auto -o /tmp/codex-<task-label>-r<n>.md "<session-id>" "<follow-up prompt>"
```

- Resume sends a follow-up message to an existing session with full prior context
- Extract session IDs from output files or session storage
- Use numbered suffixes (`-r1`, `-r2`) to track iteration rounds
- **Caution:** Double-check the session ID matches the intended task when running many agents

## Prompting Guide

Codex is precise but literal. Construct prompts with all of these sections:

```
## Goal
<What to accomplish in one sentence>

## Context
<Relevant background: what exists, why this change is needed>

## Files
<Exact file paths to read/modify, or directories to explore>

## Approach
<Step-by-step instructions for how to implement>

## Constraints
- <Constraint 1: e.g., "Do not modify any existing tests">
- <Constraint 2: e.g., "Use the existing error handling pattern from pkg/errors">
- <Constraint 3: e.g., "Keep backward compatibility with v1 API">

## Success Criteria
- <Criterion 1: e.g., "All existing tests pass">
- <Criterion 2: e.g., "New endpoint returns 200 with correct schema">
```

**Prompt hygiene:**
- Reference exact file paths, function names, and type signatures
- Include example code or signatures when asking for pattern-matching
- State what NOT to do (Codex may over-engineer or refactor adjacent code)
- For large tasks, break into smaller agents rather than one mega-prompt

## Workflow

### 1. Plan

Break the user's request into discrete, parallelizable units. Each unit should:
- Touch a bounded set of files
- Have clear inputs and outputs
- Be independently verifiable

### 2. Dispatch

Launch Codex agents in parallel using background Bash commands. Track each agent with:
- A task in the task list (subject, output file path, session ID once known)
- A unique output file in `/tmp/codex-*`

### 3. Monitor

Check agent progress by reading output files:
- Read the output file to see the final message
- If the file is empty or missing, the agent is still running — check with `tail`
- Parse session IDs from output for potential resume

### 4. Review

After agents complete:
- Read each output file to assess quality
- Run `codex exec review` on the combined changes
- If issues found, resume the relevant session with fix instructions

### 5. Iterate

For issues surfaced by review:
- Resume the original session with specific fix instructions
- Or dispatch a new targeted agent for the fix
- Re-review after fixes

## Output File Convention

```
/tmp/codex-<project>-<task>.md        # Initial run
/tmp/codex-<project>-<task>-r1.md     # First resume/iteration
/tmp/codex-<project>-review.md        # Code review output
/tmp/codex-<project>-query-<topic>.md # Knowledge queries
```

## Example: Multi-agent task

User asks: "Add authentication middleware to the API gateway"

1. **Query agent** — understand current middleware chain:
   ```bash
   codex exec -s read-only -o /tmp/codex-gw-query-middleware.md "List all middleware in projects/crab-gateway/. Show the middleware chain, how handlers are registered, and the request lifecycle."
   ```

2. **Implementation agent** — write the middleware:
   ```bash
   codex exec --full-auto -o /tmp/codex-gw-auth-middleware.md "## Goal
   Add JWT authentication middleware to the API gateway.
   ## Context
   The gateway is in projects/crab-gateway/. Middleware is registered in internal/gateway/service.go.
   ## Files
   - projects/crab-gateway/internal/gateway/service.go
   - projects/crab-gateway/internal/gateway/middleware/ (new directory)
   ## Approach
   1. Create auth middleware in internal/gateway/middleware/auth.go
   2. Register it in the middleware chain in service.go
   ## Constraints
   - Use the existing config pattern for JWT secret
   - Do not modify existing middleware behavior
   ## Success Criteria
   - Middleware validates JWT tokens on protected routes
   - Returns 401 for invalid/missing tokens
   - Passes claims to downstream handlers via context"
   ```

3. **Review agent** — check the output:
   ```bash
   codex exec review --full-auto --uncommitted -o /tmp/codex-gw-review.md "Focus on: security of JWT validation, error handling, middleware ordering"
   ```

4. **Fix agent** — if review surfaces issues, resume:
   ```bash
   codex exec resume --full-auto -o /tmp/codex-gw-auth-middleware-r1.md "<session-id>" "The review found: <issues>. Fix them."
   ```
