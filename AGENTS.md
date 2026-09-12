# Sentinel Agent Instructions

Sentinel is a FastAPI, PostgreSQL, Celery, and Redis platform for managing
security updates for SUSE and openSUSE distributions. This repository contains
the backend and its product specifications; the frontend is maintained
separately.

This file is the always-on operational policy for OpenCode agents. It owns
safety gates, workflow, reviewer triggers, and authority routing. It summarizes
but does not replace these authorities:

- `docs/features/**` owns product behavior.
- `docs/architecture.md` owns system boundaries and architectural decisions.
- `docs/conventions.md` owns technical, documentation, and Git conventions.
- Cross-cutting documents such as `docs/api-spec.md`, `docs/data-model.md`,
  `docs/configuration.md`, `docs/data-sources.md`, and `docs/deployment.md` own
  the contracts indicated by their names.

When authorities conflict, stop and report the conflict rather than choosing
silently. A more specific product specification governs its feature, while
cross-cutting documents govern their stated shared concerns.

## Always-on Safety Kernel

### Explicit loading and workspace awareness

Ordinary references to files do not load them. Explicitly read every authority
required by the routing rules below. Read only what the task needs, but read the
complete named section, including its nested subsections and any authority that
it directly requires. Do not recursively follow merely informational links.

For localized work, the unit of required reading is the **complete governing
contract**, not mechanically the entire file that contains it. A complete
governing contract includes:

- the document's scope and authority rules that determine how to interpret the
  affected content;
- the complete affected section, including nested subsections;
- applicable defaults, invariants, exceptions, and definitions declared
  elsewhere in the same document;
- sections of directly invoked authorities needed to interpret or change the
  contract; and
- relevant reverse references whose callers, consumers, or dependent contracts
  could be affected by the change.

Use contents tables, heading searches, symbol searches, and references to locate
these parts before reading them. Search results and summaries are navigation
aids, not substitutes for reading the resulting contract. Expand to the
complete document when the contract boundary is unclear, the change affects a
document-wide invariant, or targeted inspection reveals broader coupling. The
explicit full-document and full-owning-specification requirements below still
take precedence.

Inspect the actual filesystem, not only tracked files. Ignored and untracked
files may contain important local work. Read an existing file before
overwriting or modifying it.

Routes are cumulative: apply every matching route. If the scope expands, route
again and complete the additional reads before proceeding in the expanded
area. Plan, Explore, primary agents, and fresh reviewer subagents each route
independently; never assume that a child session inherited a parent's reads.

### Change-scoped review and incremental follow-up

For a review tied to a change, start from the declared scope and diff, then read
the complete governing contracts and implementation dependencies needed to
assess that change. Use targeted repository-wide searches to discover reverse
references, duplicate registrations, callers, consumers, and invariant impact;
do not turn those searches into exhaustive file reads unless a match or an
applicable contract requires it. A specialist review is not a whole-repository
audit unless its trigger, the change's demonstrated impact, or the user
explicitly requires one. If the impact cannot be bounded confidently, expand
the review rather than assuming locality.

The declared scope is the caller's stated task together with the tracking
issue's Scope, Acceptance criteria, and later scope decisions when an issue
exists. The diff shows the submitted change but does not override an explicit
scope commitment or deferral.

The primary agent may resume the same reviewer child session for a follow-up to
the same work item when the reviewer role, repository base, declared scope, and
applicable authorities are unchanged and the prior context remains available.
Pass the new diff or changed material and the previous findings; the reviewer
must reread changed contracts and code, verify the resolutions, and check the
delta for regressions. Start a fresh reviewer session when any validity
condition fails, the earlier context was compacted or is uncertain, or the
review scope changed materially. Session reuse never allows a reviewer to rely
on the primary agent's unverified summary or skip a mandatory review. Separate
per-spec sessions required for full-repository coherence or gap analysis remain
independent.

Reviewer reports prioritize findings and evidence. Keep positive summaries to
one concise statement and omit empty optional finding categories unless the
specialist output contract requires a fixed table or section. Always retain the
reviewed scope, material limitations, concrete evidence for each finding, and
the required verdict or recommendation.

### Stop conditions before retained work

Before modifying implementation under `backend/`, locate and read the complete
owning specification under `docs/features/`. Never implement absent or
insufficient product behavior. If implementation requires inventing behavior,
guarantees, contract semantics, security or data-integrity requirements, or an
architectural boundary, stop and identify the exact gap, plausible resolutions,
the smallest recommended resolution, completed work, and blocked work. Wait for
the user's decision. Equivalent internal mechanisms that preserve every
contract are implementation choices, not specification gaps.

Before writing any file, verify its placement against the actual repository and
the authoritative architecture/conventions. Core locations are:

| Content | Location |
|---|---|
| Feature specifications | `docs/features/<domain>/` |
| Architecture, API, schema, configuration, sources, deployment, conventions | Corresponding `docs/*.md` authority |
| Models / schemas / API / services / tasks / CLI | `backend/app/{models,schemas,api/v1,services,tasks,cli}/` |
| Migrations / backend utilities / tests | `backend/alembic/versions/`, `backend/scripts/`, `backend/tests/` |
| Repository orchestration / Git hooks / OpenCode tooling | `scripts/`, `.githooks/`, `.opencode/` |
| TLS certificates / drafts / review archive | `backend/certs/`, `docs/drafts/`, `docs/reviews/` |

If a requested location is wrong, stop, identify the correct location, and ask
whether to use it.

All repository file content must be in English regardless of conversation
language; converse in the user's language when practical. All examples,
fixtures, snippets, comments, and test data must use fictional personal
identifiers. Before retaining data from an external system, sanitize every
personal identifier; if uncertain whether a value is personal, treat it as
such.

Before consolidating, extracting, or generalizing a rule, inspect all likely
owners and duplicates, explain whether the rule is feature-specific or
cross-cutting, present the smallest placement options, and obtain explicit user
confirmation. Do not generalize from one speculative use case.

### Architectural backstops

These are early stop conditions; `docs/architecture.md` remains authoritative:

- Backend layers depend only in the documented direction. Business logic and
  database operations belong in services; API, CLI, and task boundaries remain
  thin; Core has no application imports.
- PostgreSQL is the source of persistent truth. Redis state is ephemeral,
  TTL-bounded or reconstructible, and must not become authoritative.
- Runtime containers are stateless and deployment-agnostic. All process roles
  use one image with different entrypoints.
- Celery has no result backend; durable outcomes belong in PostgreSQL.
- Scheduled integrations use the fetcher infrastructure. Continuous event
  consumers are a distinct integration pattern and must not be forced into a
  fetcher solely because they receive external data.
- Database access is async-only. Do not introduce a synchronous engine or
  driver without explicit human approval after proving the async model
  insufficient.

### Git and irreversible operations

Never push to `master`, force-push, create or push tags, bypass hooks, execute
`git reset --hard` or `git clean -fd`, perform another destructive Git
operation, or merge a PR without explicit authorization in the current
conversation. Tags are owned by release-please.

Whenever reading an issue or PR, read both its description and comments; either
view alone is incomplete. Use `gh` for GitHub work. SUSE GitLab inspection is
read-only: use `glab` with an explicit repository and read comments when
available.

Concrete modification intent, before the first retained edit, automatically
starts the complete work-item and topic-branch workflow in
`docs/conventions.md` (Git Conventions): fetch `origin/master`, inspect and
report worktree conflicts, select or create the issue, and create or confirm the
correct topic branch from current `origin/master`. Pure exploration, analysis,
brainstorming, and review without retained changes do not create an issue or
branch. Never edit on `master`.

Before the first push, report the branch and scope. Before opening a PR, report
the intended Conventional Commits title and PR body, changed files,
`@spec-conformance-reviewer` verdict, and any unresolved findings or risks.
Before merge, present the PR number and title, CI status, reviewer results, and
unresolved risks, then wait for an instruction that explicitly names that PR.
Approval of changes is not merge authorization. After a confirmed squash
merge, synchronize and prune local refs and delete the merged local topic
branch; this specific cleanup is permitted despite the general destructive-Git
gate above.

### Quality and findings

Every code change must add or update tests for its changed behavior; a
demonstrably non-behavioral change may rely on existing coverage. Apply the
owning specification and `docs/features/platform/testing-strategy.md`, including
happy, error, authorization, boundary, audit, and regression cases that apply.
Run focused checks and the full backend suite before completion unless the
testing strategy explicitly defines a narrower complete suite for the artifact.
Do not skip required tests at the user's request; explain the requirement. Do
not declare completion while required tests, static checks, reviewers, or
contract verification remain incomplete.

Invoke every reviewer selected by the trigger matrix below, from the primary
agent's own session, after any delegated Task work has returned. OpenCode's
Task tool enforces a subagent nesting limit (`subagent_depth`, default `1`
in this project): a session started via Task cannot itself invoke another
subagent, and its own attempt to call Task fails with a depth-limit error. A
task must never route around this — for example by shelling out to a new
OpenCode process such as `opencode run` — to simulate invoking a reviewer or
another subagent; that is a prohibited workaround. If delegated work
implicates a reviewer trigger, the task must report that in its result text
instead of attempting to invoke it.

After a task returns, the primary agent is responsible for validating the
delegated changes, either by inspecting them directly, by invoking the
reviewers the trigger matrix requires for that kind of change, or both. The
trigger matrix's own conditions remain the sole authority on which reviewers
are mandatory for a given change; delegating work to a task neither adds nor
removes that obligation, and only the primary agent may invoke a reviewer.

Reviewer findings are hypotheses: independently verify each against the actual
authority and scenario. Discard speculative, already handled, obvious,
over-documenting, or disproportionate findings. Use the smallest sufficient
correction. A resolution that adds a table, state, abstraction, dependency,
configuration option, exception hierarchy, workflow branch, or substantial
specification machinery requires a user decision before implementation.
Confirmed Critical or High security findings are mandatory and cannot be
discarded as disproportionate. Do not implement discarded findings; mention
materially important discards and their rationale in the PR summary.

### Legacy guardrail references

Existing prompts, skills, and reviewer definitions may use these stable numeric
references. They name the rules in this file and do not create separate
authority:

| Guardrail | Current owner |
|---|---|
| 1 | Specs-first stop under Stop conditions |
| 2, 4, 21, 23 | Placement, language/PII, and rule-generalization stops |
| 3 | Feature behavior/spec coherence route and owning Git conventions |
| 5, 6, 8-20, 22, 24 | Applicable authority route and Reviewer Trigger Matrix |
| 25 | Git and irreversible operations plus GitHub and release workflow |
| 26 | Quality and findings |

## Cumulative Authority Routing

Complete applicable reads before the first concrete recommendation, retained
edit, external-evidence capture, reviewer finding, or governed workflow action.
Minimal inspection needed to classify the task may occur first. For localized
work, read the complete governing contract as defined above. Read the complete
document for a new feature, architectural boundary, cross-layer design, broad
refactor, genuinely cross-cutting change, or whenever the governing contract
cannot be bounded confidently.

### Product and architecture

- **Feature behavior or implementation:** read the complete owning feature
  specification and the complete governing contract from every cross-cutting
  authority it directly invokes before planning behavior or editing. Also read
  the API-first design constraint before defining a consumer-facing operation,
  and ensure every required operation and query capability has an API surface.
  Recheck the owning spec during conformance review.
- **New feature, architecture boundary, cross-layer dependency, persistence
  choice, runtime process, or integration classification:** read complete
  `docs/architecture.md` before recommending a design or starting retained
  workflow. Also read the owning feature specification when behavior is
  involved.
- **Package affectedness, eligibility, or delivery:** read
  `docs/features/packages/package-model.md` (Three Orthogonal Dimensions)
  before permitting one dimension to depend on another. Only documented gates,
  observations, and post-mutation reconciliation may combine dimensions.
- **CVSS use:** read `docs/features/tickets/cvss-scoring.md` before selecting a
  score. Severity and eligibility use different documented resolution
  cascades; never substitute one or hardcode a CVSS version.

### Backend implementation

- **Any backend Python:** read `docs/architecture.md` (Backend Layer
  Architecture), the owning feature specification, and applicable sections of
  `docs/conventions.md` (Python (Backend)) before planning or editing.
- **API endpoint or schema:** additionally read complete `docs/api-spec.md`,
  the applicable authorization contract and Endpoint Permission Map in
  `docs/features/identity/rbac.md`, and the FastAPI, Pydantic, and testing
  convention sections before proceeding. Verify and update the Permission Map
  for endpoint additions/removals, method/path/access changes, and changed
  owning-section anchors.
- **Model, migration, enum, constraint, relationship, or timestamp:** read the
  relevant entity and Notes in `docs/data-model.md`, plus Timestamps &
  Timezones, SQLAlchemy Conventions, and Enum Storage Strategy in
  `docs/conventions.md`. The data-model contract must precede implementation.
- **Mutation, transaction, lock, audit, or post-commit effect:** read the owning
  service specification and complete Transaction and Locking conventions.
  For audited data, also read
  `docs/features/platform/audit-trail-infrastructure.md`, its Audit Trail Index,
  the domain audit spec, and Audit Trail Testing before planning, editing, or
  reviewing. Mutations and their audit events are atomic; audit history never
  drives current operational state.
- **Ticket mutation:** read the applicable ticket/package service specs before
  editing. Gate-relevant package/track/product writes go through
  `package_service`; CVSS/severity writes through `ticket_mutations`; other
  ticket lifecycle writes through `ticket_service`. Use the documented
  reconciliation chain.
- **Identity mutation:** read `docs/features/identity/user-service.md` and the
  relevant identity/audit specs. User and role lifecycle writes go through
  `user_service`; API-key writes go through `api_key_service`.
- **CLI or synchronous entrypoint:** read complete CLI Conventions,
  `docs/features/platform/cli-infrastructure.md`, and the sync-to-async and
  cross-loop lifecycle sections before proceeding. A synchronous invocation
  uses one `asyncio.run()`; repeated long-lived-process invocations must dispose
  the shared pooled engine as specified.
- **Celery task, worker, or Beat lifecycle:** read the relevant infrastructure
  spec, Backend Layer Architecture, and sync/cross-loop conventions before
  proceeding.
- **Fetcher:** read the complete applicable governing contracts in
  `docs/features/platform/fetcher-infrastructure.md`, including classification,
  the relevant base lifecycle, documentation, registry, and task integration;
  add settings, HTTP, schedule, concurrency, stale-run, or audit contracts when
  the change implicates them. Also read the applicable governing contracts in
  the CVE and Git fetcher infrastructure specifications, the complete owning
  fetcher spec, and the registry entry in `docs/data-sources.md`.
  `BaseGitFetcher` subclasses use inherited delta-flow hooks and do not override
  `execute()`. Distinguish documented sub-operation tasks from independently
  scheduled fetchers. Read an infrastructure specification completely when a
  new base abstraction or cross-cutting lifecycle change prevents a narrower
  contract boundary.
- **Redis, cache, distributed guard, or post-commit publication:** read the
  complete Redis and Transaction Hygiene conventions, the architecture
  persistence decisions, and the owning feature's key, TTL, value, and
  degradation contract before proceeding.

### Integrations, configuration, and operations

- **External service, networking, request/response parser, or fixture:** read
  the owning integration/fetcher spec, the source entry in
  `docs/data-sources.md`, `docs/features/platform/networking.md`, and External
  Integration Contract Verification before proceeding. Live verification is
  mandatory when reachable; compare every consumed field, sanitize before
  saving, write contract tests first, and record evidence. If unreachable,
  identify every documentation-only field. A live/spec contradiction is a
  specification gap.
- **SUSE internal URL:** attempt access; do not assume it is unreachable.
  Exploratory OBS/IBS CLI calls use `secbox osc -A https://api.suse.de`, never
  bare `osc`, `build.suse.de`, supplied credentials, application code, or
  modification of `~/.oscrc`.
- **Configuration or environment variable:** read its owning feature spec,
  `docs/configuration.md`, Configuration Management, and the architecture
  configuration constraint before proceeding. For secrets or
  credential-bearing URLs, also read Secret Field Typing and logging's secrets
  policy.
- **Shell script, hook, workflow, Dockerfile, compose file, CI-consumed script,
  `.dockerignore`, backend dependency/build configuration, or release
  configuration:** read complete Shell Scripting and the applicable CI
  Pipeline, container, deployment, testing, and Release Process sections before
  proceeding. Inspect interacting workflows as one pipeline and update affected
  workflows in the same PR.
- **Python runtime change:** read complete Runtime Version, its checklist, and
  the deployment software/image requirements before editing any version
  consumer.

### Specifications, policy, and OpenCode

- **Feature-spec writing:** read complete Specification Writing, the affected
  spec and related authorities before recommending or editing. For functions,
  apply Function Specification Completeness; for API-facing service errors,
  apply Service Exception Conventions and the `docs/api-spec.md` error registry.
- **API, schema, configuration, source, deployment, or CLI contract:** read the
  complete governing contract in the corresponding cross-cutting document
  before changing it. Read that document completely when adding or changing a
  shared convention, document-wide invariant, or contract whose impact cannot
  be bounded confidently.
- **Roadmap language in behavioral documentation:** read Roadmap Independence
  before proceeding. Planning identifiers belong in planning artifacts or
  issues, not behavioral authorities.
- **Rule placement or generalization:** apply the always-on placement stop above
  and read Specification Writing plus every candidate owner before presenting
  options.
- **OpenCode agent, prompt, command, skill, configuration, or policy:** read
  affected definitions, `opencode.json`, and `.opencode/README.md`; load the
  `customize-opencode` skill before proceeding. Validate resolved configuration
  and restart OpenCode before behavioral conclusions because configuration-time
  files are not hot-reloaded.
- **Reviewer work:** read the reviewer's definition, the applicable trigger
  below, every route matching the reviewed change, the issue/PR including
  comments, changed files, and the complete governing contracts before
  producing findings or a verdict. Apply Change-scoped review and incremental
  follow-up; reviewer-specific broader reads still take precedence.

### GitHub and release workflow

- **Issue selection, branch, commit, push, PR, release, or merge:** before the
  first such action, read complete Git Conventions and the always-on Git gates.
  Read Release Process for releases. A concrete work item normally uses one
  issue, one branch from current `origin/master`, and one squash-merged PR.
- **Specification gap workflow:** read the complete spec-first sequencing and
  combined-PR rules in Git Conventions before creating a branch. The default is
  a documentation issue/PR merged first, followed by a separate implementation
  issue/branch from updated `origin/master`. A combined PR is permitted only
  when the spec change is a limited refinement discovered during implementation
  rather than an absent new feature or contract, forms the same logical unit as
  the code, and has no in-flight dependents that require it to land first. New
  state machines, entities, or security models require a separate specification
  PR. Use the implementation branch and disclose the combined approach in the
  PR. If the user requests combination despite a failed condition, name the
  failure and trade-off and obtain explicit confirmation before proceeding.

## Reviewer Trigger Matrix

Run these reviewers after the relevant work and before completion. Apply stated
skip rules in the named guardrail/authority; cosmetic changes do not trigger a
review unless the reviewer definition says otherwise.

| Change | Required reviewer |
|---|---|
| Every PR, before opening and again before marking a substantively changed draft ready | `@spec-conformance-reviewer` |
| Workflow, Dockerfile, `.dockerignore`, compose, hook, CI-consumed script, or release-please configuration | `@cicd-reviewer` |
| New feature/module tests or a bug regression test | `@test-reviewer` |
| New/changed model, migration, or `docs/data-model.md` | `@data-model-reviewer` |
| New/changed API endpoint implementation, auth/authz, secrets, user-controlled input, external integration, or security-sensitive dependency | `@security-reviewer` |
| Ticket mutation code/spec | `@ticket-integrity-reviewer` |
| Identity mutation code/spec | `@identity-integrity-reviewer` |
| New/changed fetcher | `@fetcher-compliance-reviewer` |
| External contract implementation | `@external-contract-verifier` |
| Significant documented behavior, API, model/service contract, architecture/integration, or multiple docs | `@docs-reviewer` |
| New feature spec or substantive business-rule, state, data-flow, entity, shared-model, or cross-feature API change | `@spec-coherence-reviewer`; skip an isolated single-spec change with no related-spec impact |
| New/substantially changed feature spec | `@spec-gap-analyzer` and `@design-reviewer`; for gap-analyzer findings, High gaps block implementation, Medium gaps are resolved in the same PR, and Low gaps may be deferred |
| Feature spec endpoint definition or semantic API-convention change in `docs/api-spec.md` | `@api-convention-reviewer` |
| New/changed API endpoint or consumer-facing operation, including CLI/task-only operations | Evaluate `@api-parity-reviewer` |
| Feature spec adds potentially shared rules or related multi-spec content | `@docs-placement-reviewer` |

For full-repository spec coherence or gap analysis, invoke the relevant
reviewer once per specification in independent sessions. Follow each reviewer
definition's scope and output contract.

## Completion and Pull Requests

For every code change, satisfy the complete testing strategy and all applicable
lint, formatting, type, migration, shell, container, and artifact checks. For
documentation, run checks required by the applicable testing strategy. After
OpenCode tooling changes, verify `.opencode/README.md`, resolved
agents/configuration/skills, and restart behavior.

Do not call work complete until applicable authorities, tests, checks,
reviewers, and external-contract evidence are satisfied and all accepted
findings are resolved. Class A, class B, and contract-touching class D
conformance findings block completion.
