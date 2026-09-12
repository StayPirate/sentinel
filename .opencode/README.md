# OpenCode Tooling

This directory contains the OpenCode agent, command, and skill definitions
for the Sentinel project. This README serves as a quick-reference catalog.

`AGENTS.md` is the always-on operational kernel. It owns safety gates,
reviewer triggers, and cumulative authority routing. Detailed product,
architecture, and convention rules remain in their authoritative documents
and are loaded explicitly when a task matches their routes.

`opencode.json` does not inject `docs/architecture.md` or
`docs/conventions.md` globally. Primary agents and fresh subagents apply the
routes in `AGENTS.md` independently; a child session must not assume that it
inherits files read by its parent. OpenCode configuration-time files are not
hot-reloaded, so restart OpenCode after changing this policy, the project
configuration, prompts, agents, commands, or skills.

For localized work, agents read the complete governing contract rather than
mechanically loading every line of each supporting file. That contract includes
the affected section and its nested content, governing scope, applicable
defaults and invariants, required references, and relevant reverse references.
Full-document and full-owning-specification requirements still apply where
`AGENTS.md` says so, and uncertain impact expands the read rather than narrowing
it by assumption.

## Primary Agents

Primary agents are the main interaction modes, switchable with the Tab key.
They are configured in `opencode.json`.

| Agent | Scope | Permissions |
|-------|-------|-------------|
| **Plan** | Analysis and planning | Read-only (built-in) |
| **Spec** | Specifications, project policy, and OpenCode configuration | Edit: `docs/**`, `AGENTS.md`, `.opencode/**`, `opencode.json`; shell: Git/GitHub workflow, read-only inspection, tests |
| **Code** | Implementation, tests, CI/CD, infrastructure | Edit: all files (`docs/**` requires confirmation) |

- **Plan** — read-only mode for analysis, planning, and discussion without
  making changes. Uses the OpenCode built-in Plan agent.
- **Spec** — writes and maintains feature specifications, cross-cutting
  documentation, project policy, and OpenCode configuration. It can run
  non-mutating verification and manage its GitHub workflow, but cannot modify
  implementation code. Prompt:
  `.opencode/prompts/spec.md`
- **Code** — implements features from specifications, writes tests, and
  maintains all executable artifacts. Must signal unresolved behavioral or
  contract gaps, while retaining freedom over compliant internal technical
  choices. Prompt:
  `.opencode/prompts/code.md`

## Subagents

All subagents are defined in `.opencode/agents/`. Every subagent is a
**read-only reviewer**: it analyzes code or specifications and reports
findings without modifying files. All writing is owned by the primary
agents.

All reviewer agents apply the proportionality filter in `AGENTS.md`
(legacy Guardrail 26) before reporting findings. Speculative, unnecessary,
over-documenting, or disproportionate findings are omitted rather than turned
into project requirements. The agent that invoked a reviewer independently
evaluates every received finding before acting on it, per `AGENTS.md` (Quality
and findings).

Reviewer prompts use a flexible shared anatomy: role, finding filter,
applicable scope or exclusions, authority loading, specialist procedure or
checks, and output. Specialized protocols retain the structure and vocabulary
their work requires; conformance classes, external-contract methods, integrity
review levels, and domain-specific verdicts are not forced into one generic
template. Every report identifies concrete evidence and ends with an explicit
verdict or recommendation.

Every reviewer keeps OpenCode file editing disabled while ordinary Bash
commands inherit OpenCode's default allow behavior. Common mutation-oriented
filesystem command families are denied as defense in depth; these rules are
not a complete read-only shell sandbox, and `edit: deny` independently blocks
OpenCode edit, write, and patch tools. The `git`, `gh`, and `glab` command
families are default-denied, then narrowly scoped read-only forms are allowed
afterward under OpenCode's last-match-wins evaluation. The CI/CD and test
reviewers additionally run local verification commands, while the external
contract verifier can query upstream services and intentionally allows
`git clone` for remote contract inspection. Role extensions follow the shared
family denies. `backend/tests/test_opencode_agent_permissions.py` keeps the
baseline, ordering, comment, and three role-specific profiles synchronized
across all reviewer definitions.

Change-triggered reviews begin from the declared scope and diff, then expand
through applicable contracts and demonstrated dependencies. They use targeted
repository-wide searches for callers, consumers, registrations, and reverse
references instead of treating every invocation as a repository-wide audit.
The primary agent may resume the same reviewer child session for a follow-up
delta only while its role, base, scope, authorities, and retained context remain
valid; otherwise it starts a fresh reviewer session. Reports keep positive
summaries brief while preserving scope, limitations, evidence, and verdicts.

| Agent | Type | Trigger | Purpose |
|-------|------|---------|---------|
| `@api-convention-reviewer` | Reviewer | Guardrail 20 | Verifies API endpoint definitions in specs conform to project conventions |
| `@api-parity-reviewer` | Reviewer | Guardrail 12 | Verifies the REST API exposes all operations defined in feature specifications |
| `@cicd-reviewer` | Reviewer | Guardrail 5 | Reviews CI/CD artifacts (workflows, Dockerfile, compose, git hooks, release-please config) for convention conformity and pipeline coherence |
| `@data-model-reviewer` | Reviewer | Guardrail 8 | Reviews data model changes for simplicity, consistency, and conventions |
| `@design-reviewer` | Reviewer | Guardrail 26 | Applies a simplicity-first review to new or substantially modified feature specs |
| `@docs-placement-reviewer` | Reviewer | Guardrail 21 | Verifies rules and patterns are placed in the most appropriate location (not misplaced or duplicated) |
| `@docs-reviewer` | Reviewer | Guardrail 9 | Reviews documentation completeness and coherence with implementation |
| `@external-contract-verifier` | Reviewer | On-demand | Verifies external structures and documented destination-field mappings against recorded or live upstream contracts |
| `@fetcher-compliance-reviewer` | Reviewer | Guardrail 14 | Verifies scheduled fetchers use the applicable BaseFetcher, BaseCVEFetcher, or BaseGitFetcher lifecycle, metrics, and registry contracts |
| `@security-reviewer` | Reviewer | Guardrail 10 | Reviews code for security vulnerabilities and insecure patterns |
| `@spec-coherence-reviewer` | Reviewer | Guardrail 15 | Detects contradictions and inconsistencies across feature specifications |
| `@spec-conformance-reviewer` | Reviewer | Pre-PR (unconditional) | Verifies a pull request implements what its issue and owning specs require, and introduces no unspecified behavior |
| `@spec-gap-analyzer` | Reviewer | Guardrail 17 | Identifies uncovered functional cases and missing edge-case handling in specs |
| `@test-reviewer` | Reviewer | Guardrail 6 | Reviews new feature/module tests and bug regression tests for coverage, audit assertions, and testing conventions |
| `@identity-integrity-reviewer` | Reviewer | Guardrail 11 | Verifies identity audit integrity and centralized service ownership, reporting undefined RoleMapping persistence ownership as a specification gap |
| `@ticket-integrity-reviewer` | Reviewer | Guardrail 11 | Verifies Ticket audit event/no-event contracts, centralized mutation ownership, locking, and transaction hygiene |

`@spec-conformance-reviewer` is the only subagent whose trigger is a moment
rather than a kind of change: it runs on every pull request, before the pull
request is opened or marked ready. It can also be invoked manually with an
explicit pull request reference, including on closed pull requests. It is not
conditional on changed paths; its trigger is owned by the `AGENTS.md` Reviewer
Trigger Matrix and mirrored in `.opencode/prompts/code.md` and
`.opencode/prompts/spec.md`.

### Model Tiering

All reviewer subagents are pinned to
`google-vertex/claude-sonnet-5@default`. A single default-model tier keeps
review costs predictable while ensuring reviews do not inherit the invoking
primary agent's model.

## Commands

Commands are defined in `.opencode/commands/` and invoked with `/command-name`.

| Command | Purpose |
|---------|---------|
| `/idea` | Add a new idea to the brainstorming list in `docs/drafts/ideas.md` |

## Skills

Skills are defined in `.opencode/skills/` and provide guided, multi-step
workflows for common tasks. They are loaded automatically when a task matches
their description.

| Skill | Purpose |
|-------|---------|
| `new-api-endpoint` | Guided workflow for adding/modifying an endpoint in an existing feature (schema, service, thin route, tests, and reviews) |

## Directory Structure

```
.opencode/
├── agents/           # Subagent definitions (one .md file per agent)
├── commands/         # Slash command definitions
├── prompts/          # Primary agent prompt files
│   ├── spec.md       # Spec agent instructions
│   └── code.md       # Code agent instructions
├── skills/           # Multi-step workflow definitions
├── package.json      # Plugin dependency (@opencode-ai/plugin)
└── README.md         # This file
```
