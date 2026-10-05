# Contributing to Sentinel

Thank you for your interest in contributing to Sentinel!
This guide covers everything you need to get started.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code.
Please report unacceptable behavior to security@suse.com.

## How to Contribute

### Reporting Bugs

1. Check the [existing issues](https://github.com/StayPirate/sentinel/issues) to avoid duplicates
2. Open a new issue using the **Bug Report** template
3. Include steps to reproduce, expected behavior, and actual behavior
4. Add the Sentinel version and your environment details

### Suggesting Features

1. Check the [existing issues](https://github.com/StayPirate/sentinel/issues) and [feature specifications](docs/features/) to see if it has been discussed
2. Open a new issue using the **Feature Request** template
3. Describe the problem you are trying to solve and the proposed solution

### Submitting Code Changes

1. **Fork** the repository and create a topic branch from `master`
2. Follow the [branch naming conventions](#branch-naming)
3. Make your changes following the [coding standards](#coding-standards)
4. Write tests for your changes (see [Testing](#testing))
5. Ensure all checks pass locally (see [Pre-Submission Checklist](#pre-submission-checklist))
6. Open a **pull request** against `master`

## Development Setup

### Prerequisites

- **Python 3.14** (managed via [uv](https://docs.astral.sh/uv/))
- **Docker Engine or Docker Desktop with Docker Compose 2.32.2+** (for local
  PostgreSQL and Redis, automatic test provisioning, and the image-smoke suite)

### Quick Start

```bash
# Clone your fork
git clone git@github.com:<your-username>/sentinel.git
cd sentinel

# Install Python dependencies
cd backend && uv sync

# Start local infrastructure (PostgreSQL + Redis)
cd .. && ./scripts/dev-env.sh up

# Run database migrations
cd backend && uv run alembic upgrade head

# Run the test suite
uv run pytest
```

### Enable Git Hooks

The repository ships local git hooks in `.githooks/`.
Activating them gives you fast pre-commit feedback before CI runs:

```bash
git config --local core.hooksPath .githooks
```

What the hooks do:

| Hook | Checks |
|------|--------|
| `pre-commit` | ruff lint, ruff format, mypy, unit tests, shellcheck/shfmt (if installed), gitleaks secret scanning |
| `commit-msg` | Validates Conventional Commits format, breaking-marker policy, and 72-character subject limit |
| `pre-push` | Full test suite including the local process system suite, in one parallel run; blocks direct pushes to `master` and local tag pushes |
| `post-checkout` / `post-merge` / `post-rewrite` | Auto-syncs the Python virtualenv when `uv.lock` changes |

The hooks degrade gracefully: optional tools (`shellcheck`, `shfmt`, `gitleaks`) produce a warning if missing, but do not block the operation.
CI remains the authoritative gate.

## Coding Standards

Sentinel follows strict coding conventions documented in [docs/conventions.md](docs/conventions.md).
The key points are:

### Language

- All code, comments, docstrings, and documentation **must be in English**

### Python Style

- **Formatter**: ruff format (black-compatible, 88-character line length)
- **Linter**: ruff check
- **Type hints**: required on all function signatures (mypy strict mode)
- **Imports**: sorted by ruff (isort-compatible)

### Architecture

- **Thin API handlers**: validate input, call service, return response
- **Business logic in services**: all logic lives in `app/services/`
- **Validation in schemas**: use Pydantic schemas in `app/schemas/`

See the full [Architecture](docs/architecture.md) document for the layer structure and dependency rules.

## Branch Naming

| Prefix      | Use                         |
|-------------|-----------------------------|
| `feature/`  | New features                |
| `fix/`      | Bug fixes                   |
| `docs/`     | Documentation changes       |
| `refactor/` | Code refactoring            |
| `chore/`    | Infrastructure, config, deps|
| `ci/`       | CI/CD pipeline changes      |
| `test/`     | Test-only changes           |

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type[(scope)]: description
```

- Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`
- Add `!` before `:` only to `feat` or `fix` when the change is breaking:
  `feat!: description` or `fix(scope)!: description`
- Keep the first line under 72 characters
- Use imperative mood: "add feature" not "added feature"

Examples:

```
feat: add CVE severity filtering to dashboard
fix: correct CVSS score parsing for NVD API v2
feat(api)!: remove a deprecated response field
docs: update data model with Product table
test: add integration tests for CVE sync service
```

Pull request titles follow the same format and must stay under 72 characters (validated by CI).
Only `feat` and `fix` commits trigger releases or appear in generated release
notes. Before `1.0.0`, a breaking `feat!` or `fix!` advances the minor version;
after `1.0.0`, it advances the major version. See the authoritative
[Release Process](docs/deployment.md#release-process), including the intentional
`1.0.0` graduation procedure.

## Testing

Every code change **must** include tests.
The project uses pytest with async support.

### Running Tests

```bash
cd backend

# Run the default suite in a single process
uv run pytest

# Run it in parallel workers
uv run pytest -n auto --maxprocesses 8 --max-worker-restart 0

# Also include the local process system suite (as the pre-push hook does)
uv run pytest -m "not image" -n auto --maxprocesses 8 --max-worker-restart 0

# Run with coverage
uv run pytest --cov

# Run specific test file
uv run pytest tests/api/v1/test_health.py

# Run tests matching a pattern
uv run pytest -k "test_create_user"

# Run the built-image smoke suite (from the repository root; requires
# Docker Engine or Docker Desktop with Docker Compose 2.32.2+)
cd .. && make smoke
```

Repository-managed development and test tooling supports Docker Compose only.
This does not make the published OCI image Docker-specific: consumers may
deploy the same image with Podman, Kubernetes, or another compatible runtime at
their discretion.

### Test Requirements

- **New API endpoints**: test happy path, validation errors, auth/permissions
- **New models**: test creation, constraints, relationships
- **New services**: test business logic, edge cases, error handling
- **Bug fixes**: add a regression test that reproduces the bug

### Test Markers

```python
@pytest.mark.unit          # Fast, isolated (no DB, no Redis)
@pytest.mark.integration   # Tests with real PostgreSQL
@pytest.mark.e2e           # Full HTTP request/response cycle
```

See [Testing Strategy](docs/features/platform/testing-strategy.md) for the full testing conventions.

## Pre-Submission Checklist

Before opening a pull request, verify:

```bash
cd backend

# Lint
uv run ruff check .
uv run ruff format --check .

# Type check
uv run mypy .

# Tests
uv run pytest
```

All four checks run in CI and must pass for a PR to be merged.

## Pull Request Process

1. Fill in the PR template completely
2. Link the PR to a tracking issue using `Closes #<issue>` in the description
3. Ensure CI passes on your branch
4. Request review from a maintainer
5. PRs are **squash-merged** — the PR title becomes the commit message on `master`

## Spec-First Workflow

Sentinel follows a **specs-first** development model: feature specifications in `docs/features/` define behavioral contracts before implementation begins.

### When does this affect you?

| Change type | Spec required? |
|-------------|---------------|
| Bug fix that corrects a deviation from an existing spec | No — fix directly |
| Infrastructure, CI, dependencies, cosmetic changes | No |
| New feature or behavioral change covered by an existing spec | No new spec, but the implementation must conform to it |
| New feature or behavioral change **not** covered by any spec | Yes — spec PR first, then implementation |

### In practice

- **Opening an issue** (bug or feature request) never requires a spec.
  Describe the problem or idea; the maintainers will help determine whether a specification is needed.
- **Submitting a code PR** that changes observable behavior requires either an existing spec that covers it, or a preceding documentation PR that adds one.
- When in doubt, open the issue first and discuss the approach with the maintainers.

See [docs/conventions.md](docs/conventions.md) (Function Specification Completeness) for the full rules on what specifications cover and what remains an implementation choice.

## Developer Utilities

### IBS RabbitMQ Event Capture

`scripts/capture-ibs-rabbitmq.py` connects to the IBS RabbitMQ broker and captures raw events into an append-only JSONL file. It is used for external contract verification during IBS integration development.

The script manages its own dependencies via [PEP 723](https://peps.python.org/pep-0723/) inline metadata — no manual install required:

```bash
# See all options
uv run scripts/capture-ibs-rabbitmq.py --help

# Capture all request/review events for 3 days
uv run scripts/capture-ibs-rabbitmq.py \
    --routing-key 'suse.obs.request.#' \
    --duration 259200

# Inventory of every event type for 1 hour (5 samples per key)
uv run scripts/capture-ibs-rabbitmq.py \
    --routing-key 'suse.obs.#' \
    --duration 3600 \
    --max-samples 5
```

Output defaults to `${XDG_RUNTIME_DIR}/sentinel/ibs-rabbitmq/` (or `/tmp/sentinel-<uid>/ibs-rabbitmq/`). Override with `--output`.

**Important**: output files contain unmodified IBS event payloads with real usernames and internal data. They must not be committed to the repository or shared externally. Only sanitized and minimized fixtures belong under `backend/tests/fixtures/`.

## Working with OpenCode

This project includes first-class [OpenCode](https://opencode.ai) configuration.
Using OpenCode is entirely optional — you can contribute with any editor or workflow — but it provides a streamlined experience for this repository.

### What it provides

- **`AGENTS.md`** contains the operational rules that guide the AI agents (guardrails, gap protocol, reviewer invocation, git workflow).
- **`.opencode/`** defines subagents (automated reviewers), commands, and skills.
- When working in OpenCode, the agents automatically:
  - verify that a specification exists before implementing a feature;
  - invoke the applicable reviewer subagents based on the type of change (security, data model, API parity, test quality, etc.);
  - enforce the project's git and commit conventions.

### Reviewer subagents

The project defines 15+ read-only reviewer subagents that analyze code or specifications and report findings without modifying files.
They are invoked automatically by the primary agents when their trigger conditions are met.

See [`.opencode/README.md`](.opencode/README.md) for the full inventory of agents, their triggers, and model tiering.

### Choosing models

The repository pins no model for any agent, so OpenCode works with whichever providers your client has.
To choose the models and reasoning-effort variants per agent, copy [`.opencode/opencode.example.jsonc`](.opencode/opencode.example.jsonc) to `.opencode/opencode.jsonc` (ignored by Git), adjust it, and restart OpenCode.
Without that file, primary agents use your default model and reviewers inherit the model of the agent that invokes them.

## License

By contributing to Sentinel, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
