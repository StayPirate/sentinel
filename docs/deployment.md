# Deployment Guide

Operational guide for deploying and configuring Sentinel across
environments: local development, staging, and production.

For environment variable reference, see `docs/configuration.md`.
For architectural decisions and design constraints, see
`docs/architecture.md`.

## Contents

- [Prerequisites](#prerequisites)
  - [Software Requirements](#software-requirements)
  - [Network Access (Staging/Production)](#network-access-stagingproduction)
- [External Service Registration](#external-service-registration)
  - [IdP Client Registration (id.suse.com)](#idp-client-registration-idsusecom)
- [Environments](#environments)
  - [Local Development](#local-development)
  - [Staging Deployment](#staging-deployment)
  - [Production Deployment](#production-deployment)
- [CI Pipeline](#ci-pipeline)
  - [Workflow Inventory](#workflow-inventory)
  - [Workflow Conventions](#workflow-conventions)
  - [Container Build Conventions](#container-build-conventions)
- [Release Process](#release-process)
  - [Platform Version and Source of Truth](#platform-version-and-source-of-truth)
  - [Semantic Versioning Policy](#semantic-versioning-policy)
  - [Pre-1.0 Policy](#pre-10-policy)
  - [1.0.0 Graduation](#100-graduation)
  - [How It Works](#how-it-works)
  - [Creating a Release](#creating-a-release)
  - [Squash Merge](#squash-merge)
  - [Changelog](#changelog)
  - [Pipeline Chain](#pipeline-chain)
  - [Version Locations](#version-locations)
  - [Image Tag Semantics](#image-tag-semantics)
  - [Release Supply-Chain Artifacts](#release-supply-chain-artifacts)
  - [API Documentation Publication](#api-documentation-publication)
  - [Container Image Retention](#container-image-retention)
  - [Configuration Files](#configuration-files)
  - [Repository Secrets](#repository-secrets)
- [Process Architecture](#process-architecture)
  - [Container Images](#container-images)
  - [Singleton Processes](#singleton-processes)
  - [Celery Worker Pool Requirement](#celery-worker-pool-requirement)
  - [Startup Ordering](#startup-ordering)
  - [Git Worker Volume](#git-worker-volume)
  - [Timezone and Locale Requirements](#timezone-and-locale-requirements)
  - [Clock Synchronization](#clock-synchronization)
- [Operations](#operations)
  - [Database Migrations](#database-migrations)
  - [CLI Operational Access](#cli-operational-access)
  - [Health Checks](#health-checks)
  - [Redis Durability, Memory, and Persistence](#redis-durability-memory-and-persistence)
  - [CVSS Recalculation Recovery](#cvss-recalculation-recovery)
  - [Log Aggregation](#log-aggregation)
  - [Image Vulnerability Monitoring](#image-vulnerability-monitoring)
  - [Python Forward-Compatibility Check](#python-forward-compatibility-check)
  - [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Software Requirements

| Component | Minimum Version | Purpose |
|-----------|----------------|---------|
| Docker Engine or Docker Desktop | No independent floor | Repository-managed local development and test container runtime; must support the required Compose plugin |
| Docker Compose CLI plugin | 2.32.2+ | Repository-managed development and test orchestration |
| PostgreSQL | 18+ | Primary database |
| Redis | 8+ | Session cache, Celery broker, rate limiting |
| Git | 2.25+ | Git-based CVE fetcher operations (git worker container only) |
| [uv](https://docs.astral.sh/uv/getting-started/installation/) | 0.11+ | Manages the Python 3.14 interpreter and all backend dependencies for local development (see "Quick Start" below). Development only |
| [gh](https://cli.github.com/) | any recent release | Strongly recommended, development only — manages issues, pull requests, and GitHub Flow from the command line. See `docs/conventions.md` (Git Conventions) |
| [glab](https://gitlab.com/gitlab-org/cli) | any recent release | Optional, development only — interacts with SUSE-internal GitLab repositories, issues, and merge requests (e.g., SMELT, SMASH). Requires authentication against `gitlab.suse.de`. See `AGENTS.md` (Local Environment) |
| [shellcheck](https://www.shellcheck.net/) | match `ci.yml` (shell-lint) | Optional, development only — lints shell scripts via the pre-commit hook; CI enforces regardless. See `docs/conventions.md` (Shell Scripting) |
| [shfmt](https://github.com/mvdan/sh) | match `ci.yml` (shell-lint) | Optional, development only — formats shell scripts via the pre-commit hook. Match the CI version to avoid formatting drift. See `docs/conventions.md` (Shell Scripting) |
| [actionlint](https://github.com/rhysd/actionlint) | match `ci.yml` (shell-lint) | Optional, development only — validates GitHub Actions workflows locally before pushing. See `docs/conventions.md` (Shell Scripting) |
| [gitleaks](https://github.com/gitleaks/gitleaks) | any recent release | Optional, development only — scans staged changes for secrets via the pre-commit hook. Local-only; no CI job performs secret scanning. See `docs/features/platform/testing-strategy.md` (Pre-Commit Hooks) |

Repository tooling uses one Docker Compose minimum rather than maintaining
different local toolchains. The image-smoke harness determines the 2.32.2 floor
because it requires `--pull never` for both `up` and one-shot `run` operations.
Simpler development-stack commands use that same supported baseline. See
`docs/features/platform/testing-strategy.md` (Image / Container Smoke Testing)
for the full justification.

### Network Access (Staging/Production)

Sentinel requires outbound access to:

| Service | Host | Port | Purpose |
|---------|------|------|---------|
| SUSE IdP | `id.suse.com` | 443 | SSO authentication (OIDC) |
| IBS API | `api.suse.de` | 443 | Build service integration |
| IBS RabbitMQ | `rabbit.suse.de` | 5671 | Real-time event consumption |
| SMELT | `smelt.suse.de` | 443 | Product/package data |
| AIMAAS | `aimaas.suse.de` | 443 | Product lifecycle, CVSS thresholds |
| NVD | `services.nvd.nist.gov` | 443 | CVE data |
| GitHub | `github.com` | 443 | MITRE cvelistV5 repository clone/fetch |
| git.kernel.org | `git.kernel.org` | 443 | Linux kernel vulnerability repo clone/fetch |

---

## External Service Registration

### IdP Client Registration (id.suse.com)

Before SSO authentication works, you must register Sentinel as an OIDC
client on the SUSE identity provider (`id.suse.com`).

#### Steps

1. Request a new OIDC client registration (contact the IdP
   administrators or use the self-service portal if available)
2. Provide the following client configuration:
   - **Client type**: Confidential (server-side application)
   - **Grant type**: Authorization Code
   - **Scopes**: `openid profile email`
   - **Redirect URIs** (register all environments that will use this
     client):
     - `https://sentinel.suse.de/auth/callback` (production)
     - `https://sentinel-staging.suse.de/auth/callback` (staging)
     - `http://localhost:5173/auth/callback` (local development)
3. After registration, you will receive:
   - `client_id` — set as `SSO_CLIENT_ID`
   - `client_secret` — set as `SSO_CLIENT_SECRET`

#### Environment-Specific Configuration

Each Sentinel instance must set `SSO_REDIRECT_URI` to the value matching
its environment:

| Environment | `SSO_REDIRECT_URI` |
|-------------|-------------------|
| Production | `https://sentinel.suse.de/auth/callback` |
| Staging | `https://sentinel-staging.suse.de/auth/callback` |
| Local dev | `http://localhost:5173/auth/callback` |

The IdP validates that the `redirect_uri` in each authorization request
matches one of the registered URIs. A mismatch causes the IdP to reject
the request with a `redirect_uri_mismatch` error.

All environments share the same `SSO_CLIENT_ID` and `SSO_CLIENT_SECRET`
— only `SSO_REDIRECT_URI` differs.

---

## Environments

### Local Development

Repository-managed local development uses Docker Engine or Docker Desktop with
the Docker Compose CLI plugin. Podman compatibility wrappers, standalone
`docker-compose`, and command-selection overrides are not supported. This
tooling policy is separate from the deployment-agnostic OCI image contract.

#### Quick Start

```bash
# Install dependencies (downloads Python 3.14 and creates
# backend/.venv automatically if not already present)
cd backend && uv sync

# (Optional) Enable the repository's local git hooks for fast pre-commit
# feedback. Scoped to this repo via --local; does not affect other repos.
# See docs/features/platform/testing-strategy.md (Pre-Commit Hooks).
git config --local core.hooksPath .githooks

# Start PostgreSQL + Redis containers
./scripts/dev-env.sh up

# Run database migrations
cd backend && uv run alembic upgrade head

# Start the backend API server
cd backend && uv run uvicorn app.main:app --reload --port 8000

# Start Celery worker (separate terminal)
# --pool=prefork is explicit here for clarity — it is also Celery's own
# default. See "Celery Worker Pool Requirement" below: no other pool is
# supported.
cd backend && uv run celery -A app.celery_app worker --pool=prefork

# Start Celery Beat scheduler (separate terminal)
cd backend && uv run celery -A app.celery_app beat
# Note: the redbeat scheduler class is configured in the Celery app
# settings (beat_scheduler). No --scheduler CLI flag is needed.
```

#### Local Environment Variables

Create `backend/.env` for local development:

```bash
# Required (app refuses to start without this)
JWT_SECRET_KEY=local-development-secret-minimum-32-characters

# Connection settings (defaults work with scripts/dev-env.sh)
DATABASE_URL=postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1

# SSO (optional for local — omit to disable SSO)
SSO_ISSUER_URL=https://id.suse.com
SSO_CLIENT_ID=<your-client-id>
SSO_CLIENT_SECRET=<your-client-secret>
SSO_REDIRECT_URI=http://localhost:5173/auth/callback

# CORS
CORS_ORIGINS=http://localhost:5173

# Debug
DEBUG=true
```

#### Creating the First Local User

With SSO disabled (no SSO env vars), create a local admin user via CLI:

```bash
cd backend && uv run python -m app.cli manage-user create \
  --username admin \
  --email admin@example.com \
  --role admin
```

### Staging Deployment

#### Configuration Checklist

| Setting | Value | Notes |
|---------|-------|-------|
| `DATABASE_URL` | Staging PostgreSQL connection string | Dedicated staging DB |
| `JWT_SECRET_KEY` | Unique per environment (>= 32 chars) | Never reuse across environments |
| `REDIS_URL` | Staging Redis instance | |
| `SSO_ISSUER_URL` | `https://id.suse.com` | Same IdP for all environments |
| `SSO_CLIENT_ID` | Same as production | Single client registration |
| `SSO_CLIENT_SECRET` | Same as production | Single client registration |
| `SSO_REDIRECT_URI` | `https://sentinel-staging.suse.de/auth/callback` | Must match IdP registration |
| `CORS_ORIGINS` | `https://sentinel-staging.suse.de` | |
| `DEBUG` | `false` | Never enable debug in staging |
| `IBS_API_URL` | `https://api.suse.de` | |
| `IBS_USERNAME` / `IBS_PASSWORD` | Service account credentials | |
| `IBS_RABBITMQ_URL` | Credential-bearing AMQPS URL | Supply through the environment or secret store; never log it |

#### Deployment Steps

1. **Database**: ensure PostgreSQL is running and accessible
2. **Redis**: ensure Redis is running and accessible
3. **Run migrations** (one-shot, before starting API):
   ```bash
    docker run --rm --env-file .env sentinel:latest \
     alembic upgrade head
   ```
4. **Start all runtime processes** defined in
   [Container Images](#container-images) — each as a separate
   container/process
5. **Verify health**:
   - `GET /health` — liveness (API process is running)
   - `GET /ready` — readiness (PostgreSQL + Redis reachable)
6. **Verify SSO**: navigate to the login page, confirm "Login with SUSE
   SSO" button appears, complete a test login

#### Staging-Specific Notes

- Staging auto-deployment from the `master` branch is deferred until
  the deployment target (Kubernetes, Docker Compose on VM, or cloud
  service) is decided. The current process is manual. When the target
  is known, a deployment workflow will be added to the CI pipeline
  following [Workflow Conventions](#workflow-conventions)
- IBS/RabbitMQ integration is active — staging receives real events
- Run the IBS RabbitMQ consumer as its own singleton process. It requires
  PostgreSQL, uses Redis only for best-effort status heartbeat publication,
  and has no Celery app or broker dependency

### Production Deployment

#### Configuration Checklist

Same as staging, with these differences:

| Setting | Value | Notes |
|---------|-------|-------|
| `SSO_REDIRECT_URI` | `https://sentinel.suse.de/auth/callback` | Production URI |
| `CORS_ORIGINS` | `https://sentinel.suse.de` | |
| `JWT_SECRET_KEY` | Unique production secret | Different from staging |

#### Deployment Steps

1. **Database migrations**: run as a one-shot job BEFORE deploying new
   application containers. Never run migrations automatically on API
   startup (multiple replicas could conflict).
2. **Deploy all runtime processes** defined in
   [Container Images](#container-images)
3. **Health checks**: configure orchestrator to use `/health` (liveness)
   and `/ready` (readiness)
4. **Verify**: confirm all services are healthy, check logs for errors

#### Pre-Production Checklist

Before the first production deployment:

- [ ] IdP client registered with production redirect URI
- [ ] `JWT_SECRET_KEY` generated (cryptographically random, >= 32 chars)
- [ ] PostgreSQL provisioned and accessible
- [ ] Redis provisioned and accessible
- [ ] IBS service account created (`IBS_USERNAME` / `IBS_PASSWORD`)
- [ ] IBS RabbitMQ credential-bearing URL supplied securely
- [ ] SUSE Trust Root CA present in the built image, both at its
      repository-relative path and installed into the system trust store
      (automated by the Dockerfile build — see
      `docs/features/platform/networking.md`, Trust Store Layering;
      verified by `backend/tests/image/test_networking.py`)
- [ ] DNS configured for `sentinel.suse.de`
- [ ] TLS certificate provisioned for `sentinel.suse.de`
- [ ] Reverse proxy / ingress configured to route `/api` to backend
- [ ] Rate limiting configured on the reverse proxy (see
      `docs/drafts/open-points.md`, OP-2)
- [ ] CORS origins set correctly
- [ ] Log aggregation configured (see Log Aggregation, below)
- [ ] Backup strategy for PostgreSQL defined

#### Production-Specific Notes

- Production is deployed manually from version tags (`v*`). A deployment
  workflow will be added when the infrastructure target is decided
- Celery Beat is a singleton — ensure only one instance runs
- `JWT_SECRET_KEY` rotation invalidates all active sessions (plan for
  off-peak maintenance window). In-flight SSO logins are also affected
  (max 10 minutes of disruption)

---

## CI Pipeline

Continuous integration and delivery are implemented entirely with GitHub
Actions. This section is the authoritative reference for which workflows
exist and for the conventions every workflow and container build must
follow.

Closely related topics are owned elsewhere and are not repeated here:
the full trigger chain — how a merge propagates to a release and to a
published image — is documented in [Pipeline Chain](#pipeline-chain),
the tags those images carry in
[Image Tag Semantics](#image-tag-semantics), and the deployment targets
they feed in [Environments](#environments).

### Workflow Inventory

| Workflow | Trigger | Purpose | Blocking |
|----------|---------|---------|----------|
| `ci.yml` | Push to `master`, pull request, manual | Backend quality gates — see `docs/features/platform/testing-strategy.md` (CI Pipeline) for the authoritative gate composition | Yes |
| `pr-metadata.yml` | Pull request opened, edited, reopened, or synchronized | Validates PR title format/length and issue linkage per `docs/conventions.md` (Pull Request Requirements) | Yes |
| `release-please.yml` | `workflow_run` after a successful CI run on `master` | Creates and updates the Release PR; on merge creates the version tag and GitHub Release | Yes (release path) |
| `build-images.yml` | `workflow_run` after a successful CI run on `master`; push of a `v*` tag | Builds the backend image once, runs the image smoke and SBOM gates, and publishes the same digest to `ghcr.io`; version-tag runs also publish release SBOM and provenance attestations | Yes (publish gate) |
| `deploy-api-docs.yml` | Push of a `v*` tag | Publishes the OpenAPI contract and API documentation site to GitHub Pages | Yes (release path) |
| `image-scan.yml` | Weekly schedule, manual | Scans the published image for OS-level vulnerabilities and opens or updates a tracking issue | No |
| `python-forward-compat.yml` | Weekly schedule, manual | Runs the test suite on the next Python minor version and reports the result through its Actions status and logs | No |
| `renovate-validation.yml` | Pull request opened, synchronized, or reopened; manual | Validates `renovate.jsonc` and performs a read-only Renovate dependency lookup in a pinned container | No |
| `cleanup-images.yml` | Weekly schedule, manual | Bounds the pool of untagged image versions in the registry | No |
| `scorecard.yml` | Push to `master`, weekly schedule, manual | Runs the official OpenSSF Scorecard action and publishes results to Code Scanning and the public Scorecard dataset | No |

**Blocking** means a failure prevents the merge, release, or publication
that the workflow gates. Non-blocking workflows never fail a merge and
never touch the publish path: `image-scan.yml`,
`python-forward-compat.yml`, and
`renovate-validation.yml` are early-warning mechanisms,
`cleanup-images.yml` is scheduled registry maintenance, and
`scorecard.yml` is an external security-posture scan that never fails
the run because of scan findings.

**Static Application Security Testing (SAST).** CodeQL is enabled via
GitHub's repository-level Default Setup (Settings → Code security →
Code scanning), not a custom workflow in this repository. GitHub
manages the trigger schedule, language detection, and query suite
directly; there is no `.github/workflows/codeql.yml` file to maintain.
Default Setup and a custom CodeQL workflow are mutually exclusive —
enabling one requires the other to be absent.

### Workflow Conventions

**Pinned action references.** Every `uses:` reference MUST be pinned by
full commit SHA, with a trailing `# vX.Y.Z` comment naming the version
the SHA corresponds to (e.g. `actions/checkout@<sha> # v7.0.1`). Mutable
references (`@main`, `@master`, any branch name) and tag references
(major-version tags such as `@v7`, or exact release tags such as
`@v9.0.0`) MUST NOT be used — a tag, even an exact release tag, can be
force-moved by the upstream maintainer to point at different content
without the repository owner's action; a commit SHA cannot.

The same principle applies to tools a workflow installs itself — whether
downloaded directly or requested through an action's `version:` input.
Their versions MUST be pinned explicitly and MUST NOT be left to resolve
to the latest available release.

Renovate (`renovate.jsonc`, `github-actions` manager) tracks the
SHA-pinned actions and opens a PR bumping both the SHA and the
trailing version comment when a new release is published. It also
tracks `with:` version inputs of commonly used community-maintained
actions (e.g. `astral-sh/setup-uv`'s `version:` input) — no additional
configuration is required for either pinning style. Dependency updates
are managed by the hosted Mend Renovate GitHub App reading `renovate.jsonc`
from the repository root; no workflow in this repository runs the hosted bot
or creates its dependency-update PRs. The separate advisory validation
workflow is described below.

`renovate-validation.yml` is a separate, advisory repository check. It runs
on every pull request rather than maintaining a whitelist of Renovate-managed
paths, validates `renovate.jsonc` in strict mode, and performs a read-only
lookup with the official Renovate container pinned by version and digest. The
workflow has read-only repository permissions, cannot create branches or pull
requests, and is not a required merge check. A failure is intentionally
visible as a red Actions status while remaining non-blocking; the Mend-hosted
Renovate App remains the only component that creates dependency-update PRs.

**Testcontainers image references.** The `testcontainers`-provisioned
PostgreSQL and Redis images used by `backend/tests/conftest.py` (see
`docs/features/platform/testing-strategy.md`, Database Provisioning)
are plain string arguments in Python code, not a
Dockerfile/compose/workflow declaration — none of Renovate's built-in
managers detect them. A `customManagers` regex entry in `renovate.jsonc`
tracks these references instead, matching a
`# renovate: depName=<name>` hint comment placed directly above each
`*Container(...)` call. Adding a new testcontainers-provisioned service
follows the same pattern: add the hint comment immediately above the
container instantiation.

This repository extends the `config:recommended` preset, which adds
`**/vendor/**`, `**/examples/**`, `**/__tests__/**`, `**/test/**`,
`**/tests/**`, and `**/__fixtures__/**` to Renovate's default
`ignorePaths` (`**/node_modules/**`, `**/bower_components/**`). The
inherited `**/tests/**` pattern silently excludes
`backend/tests/conftest.py` from every manager — including the custom
one above — before `managerFilePatterns` is ever evaluated:
`ignorePaths` is a root-level-only setting in Renovate and cannot be
scoped per manager or per `packageRules` entry. `renovate.jsonc`
therefore redefines `ignorePaths` explicitly, keeping every default
pattern except `**/tests/**`. Do not reintroduce that pattern — doing
so breaks testcontainers image tracking again with no error or warning
from Renovate, since an ignored file is silently absent from dependency
extraction rather than rejected.

**No secrets in workflow files.** Credentials MUST be supplied through
GitHub Secrets and referenced via `${{ secrets.* }}` — never written as
literals. Literal values are permitted only for obviously non-production
test fixtures consumed by ephemeral service containers (for example the
CI database password and the `JWT_SECRET_KEY` placeholder used by the
`backend-test` job), and such values MUST be self-evidently unusable
outside CI. No CI job performs secret scanning — the optional local
`gitleaks` pre-commit hook is the only automated check (see
[Software Requirements](#software-requirements)) — so this convention is
enforced by review.

**Least-privilege permissions.** Every workflow MUST declare an explicit
top-level `permissions:` block, set to fully restrictive (`{}`) or to a
read-only scope, rather than relying on the repository default. The
top-level block MUST NOT grant write access to a sensitive scope —
`actions`, `checks`, `contents`, `deployments`, `packages`,
`security-events`, or `statuses` (the scopes the OpenSSF Scorecard
Token-Permissions check treats as sensitive, since each one enables a
concrete escalation such as committing unreviewed code or publishing a
package). A job that needs write access to one of these declares it in
its own `permissions:` block instead, scoped to that job only. Other
write scopes (for example `issues` or `pull-requests`) are not
security-sensitive in this sense and MAY remain at the top level on a
single-job workflow.

**Concurrency.** Workflows that create a release or publish an artifact
— those marked `Yes (release path)` or `Yes (publish gate)` in the
inventory above — MUST NOT use `cancel-in-progress`. Cancelling a
partially completed release or push leaves the Release PR or the
registry in an indeterminate state. `ci.yml` is deliberately exempt: it
publishes nothing, and cancelling a superseded run simply means the
downstream `workflow_run` never fires.

**Service containers for test dependencies.** Jobs that run the test
suite in-process MUST obtain PostgreSQL and Redis from GitHub Actions
service containers declared with health-check options, never from
externally hosted or shared instances. This keeps every run isolated and
reproducible. Artifact suites that exercise the built image are the
exception: the Docker Engine and Docker Compose-based image-smoke harness
supplies its own stack through `docker-compose.smoke.yml` so that the container
under test reaches its dependencies exactly as it would at runtime — see
`docs/features/platform/testing-strategy.md` (Image / Container Smoke Testing).
This harness choice does not change the deployment-agnostic OCI image contract.

**Shell inside workflows.** Shell embedded in `run:` steps follows the
Shell Scripting rules in `docs/conventions.md` — including `actionlint`
validation and extraction into `scripts/` once a block grows beyond
simple orchestration.

### Container Build Conventions

**Multi-stage builds.** `backend/Dockerfile` separates a `builder` stage
from a `runtime` stage so that build tooling and build-time dependencies
never reach the published runtime layer. The runtime stage MUST run as a
non-root user.

**Single image, multiple entrypoints.** All process roles are built from
this one image — see [Container Images](#container-images) for the
canonical role enumeration and `docs/architecture.md` for the rationale.
Per-role image variants MUST NOT be introduced.

**Base image version.** The Python base image version comes from the
global `ARG PYTHON_VERSION`. See `docs/conventions.md` (Runtime Version)
for the source-of-truth rules, the build-argument pass-through, and the
CI drift check.

**Base image pinning.** The `python:${PYTHON_VERSION}-slim` base image
is pinned by digest (`python:3.14-slim@sha256:...`) in both Dockerfile
stages, in addition to the tag — the tag documents the intent (Python
3.14, slim variant) while the digest guarantees immutability. Both
values are supplied through Dockerfile `ARG` values (`PYTHON_VERSION`,
`PYTHON_BASE_DIGEST`); Renovate's `dockerfile` manager expands `ARG`
references natively and proposes a PR refreshing `PYTHON_BASE_DIGEST`
whenever the upstream digest for the current tag changes. A dedicated
`packageRule` in `renovate.jsonc` matches the `python` package name
across every manager that tracks the interpreter version (`dockerfile`
for this base image, `pyenv` for `backend/.python-version`, `pep621`
for `backend/pyproject.toml` `requires-python`) and disables major/minor
updates uniformly — bumping the Python interpreter version itself
remains the deliberate, manual process described in
`docs/conventions.md` (Runtime Version, Version Bump Checklist), since
it requires re-validating dependency support across the Celery stack
and other C/Rust-extension packages, not just refreshing a digest.
Patch-level freshness for this base image continues to flow through
the automated digest refresh described above, unaffected by that rule.
Base image freshness against known vulnerabilities is monitored
separately by the weekly Trivy scan — see Image Vulnerability
Monitoring below.

**Test code exclusion.** The runtime image MUST NOT contain test code.
`backend/tests/` is excluded by `.dockerignore` and is never copied
into any Dockerfile stage. No runtime environment variable, alternate
image target, compose override that changes image contents, or
test-fetcher-enabled runtime variant may be introduced to make test
code executable inside the shipped image. The local process system
test suite (see `docs/features/platform/testing-strategy.md`, Local
Process System Testing) uses the normal local installation with
test-owned process launchers — it does not require changes to the
shipped image.

---

## Release Process

Sentinel uses [release-please](https://github.com/googleapis/release-please)
to automate versioning, changelog generation, and GitHub Releases. The
process is driven entirely by Conventional Commit messages on the
`master` branch.

### Platform Version and Source of Truth

Sentinel uses a single platform version following [Semantic Versioning
2.0.0](https://semver.org/). All runtime process roles are built from the same
Docker image and share that version. Fetchers are built-in classes rather than
independently deployable plugins, so per-component versioning would not match
the deployment model.

The version in `backend/pyproject.toml` is the source of truth for released
application code. `backend/app/main.py` reads it dynamically through
`importlib.metadata.version("sentinel")`. Release-please updates that version,
the matching `backend/uv.lock` entry, and its current-version record in
`.release-please-manifest.json` atomically in a Release PR. It creates
`v<major>.<minor>.<patch>` tags after that PR is merged; downstream image and
API-documentation workflows consume those tags.

The release-please package remains scoped to `backend/`. A commit is considered
for a platform release only when it changes a path under `backend/`. Expanding
release participation to repository-wide commits requires a separate policy
decision.

### Semantic Versioning Policy

Sentinel is a deployed platform, not a library. Release signals and resulting
version changes are:

| Commit on `master` | Current version | Result |
|--------------------|-----------------|--------|
| `fix:` | Any | Patch (`X.Y.Z` → `X.Y.Z+1`) |
| `feat:` | Any | Minor (`X.Y.Z` → `X.Y+1.0`) |
| `fix!:` or `feat!:` | `0.x.y` | Next minor (`0.x.y` → `0.x+1.0`) |
| `fix!:` or `feat!:` | `1.x.y` or later | Next major (`X.y.z` → `X+1.0.0`) |
| `docs:`, `chore:`, `ci:`, `test:`, `refactor:` | Any | No release on their own |

The semantic meaning of the three release levels is:

| Bump | Product meaning |
|------|-----------------|
| Major | Breaking REST API changes, database migrations requiring manual operator intervention, or fundamental architectural changes after `1.0.0` |
| Minor | New API endpoints, fetchers, features, non-breaking database migrations, or CLI commands |
| Patch | Bug fixes, security patches, performance improvements, or operational fixes |

Only `feat` and `fix` appear in generated release notes, under Features and Bug
Fixes. The other accepted repository commit types are hidden, so a set
containing only those types does not create or keep a non-empty Release PR.
Sentinel uses `!` as its only supported breaking-change marker and permits it
only on `feat` and `fix` in PR titles and local commit subjects. Maintainers
review every generated Release PR before merge; that review is the final check
that the proposed version and release notes match the merged changes.

### Pre-1.0 Policy

While the version is `0.x.y`:

- the API is not considered stable;
- breaking `feat!` and `fix!` changes advance the minor version and never
  produce `1.0.0` automatically; and
- consumers should pin exact versions rather than version ranges.

No ordinary Conventional Commit can graduate Sentinel to `1.0.0`. Graduation
is an intentional operator decision using the procedure below.

### 1.0.0 Graduation

Sentinel reaches `1.0.0` only when all of these conditions are verified:

1. **Production operational**: a production instance is deployed and serving
   real users.
2. **Core ingestion functional**: the NVD and MITRE fetchers and at least one
   additional core CVE source are implemented and running in production.
3. **Ticket lifecycle complete**: ingestion, analysis, and resolution work
   end-to-end.
4. **Authentication operational**: local authentication and SSO are implemented
   and operational in production.
5. **API stability demonstrated**: the REST API v1 surface has had no breaking
   changes for at least four weeks of production operation.
6. **Schema stability demonstrated**: the database schema has had no breaking
   migration requiring manual intervention for at least two consecutive minor
   releases.

After recording evidence for every criterion in a dedicated work item, use a
substantive `feat` or `fix` PR that genuinely changes `backend/` and add this
standalone footer to the final squash commit body:

```
Release-As: 1.0.0
```

The PR title remains an accurate `feat` or `fix` description of its substantive
change; `Release-As` supplies the exceptional target version. Before confirming
the squash merge, verify that GitHub's generated commit body contains the
footer. A footer present only in the PR description is not sufficient. A
`chore` commit cannot be used for graduation because hidden changelog types do
not keep a Release PR non-empty. Do not create an artificial backend marker or
edit release-please configuration or manifest state to force participation; if
no substantive releasable backend change is appropriate, create a dedicated
work item to decide the release mechanism instead.

After that PR reaches `master`, review and merge the generated `1.0.0` Release
PR through the normal explicit merge-authorization gate. From `1.0.0` onward,
breaking changes require a major version and the API versioning policy in
`docs/api-spec.md` (Versioning) takes full effect.

### How It Works

1. Developers merge PRs to `master` using conventional commits
   (`feat:`, `fix:`, etc.). Squash merge is required so the PR title
   becomes the commit message (see Squash Merge below)
2. The `release-please` GitHub Action
   (`.github/workflows/release-please.yml`) analyzes new commits and
   creates (or updates) a **Release PR** with:
   - Version bump in `backend/pyproject.toml`
   - Updated `CHANGELOG.md`
   - Summary of all changes since the last release
3. The Release PR stays open and is updated automatically as more
   commits land on `master`
4. When the team decides to release, a maintainer merges the Release PR
5. On merge, release-please:
   - Creates a git tag (`v<major>.<minor>.<patch>`)
   - Creates a GitHub Release with release notes
6. The tag triggers `build-images.yml`, which builds the Docker image
   once, runs the blocking image smoke-test and SBOM gates against that
   exact artifact, and only on success pushes the same image digest to
   `ghcr.io` with semver tags. The workflow then publishes the release
   SBOM and signed attestations described below. A failing pre-publication
   gate prevents image publication
   (see `docs/features/platform/testing-strategy.md`, Image / Container
   Smoke Testing)

### Creating a Release

To create a release, merge the open Release PR. No manual version
bumping, tagging, or changelog editing is required.

To request a specific version outside the ordinary mapping, use the
`Release-As` footer in the final squash commit message:

```
feat: complete the final pre-1.0 backend capability

Release-As: 1.0.0
```

Use the accurate `feat` or `fix` description of the substantive backend change
that carries the footer. This footer does not require or authorize hand-editing
`release-please-config.json` or `.release-please-manifest.json`. For `1.0.0`,
follow the graduation gate above. The commit must genuinely touch `backend/`
to participate in the currently scoped release package.

### Squash Merge

All PRs to `master` MUST use squash merge — it is the only allowed
merge method (merge commits and rebase merge are disabled at the
repository level). This keeps the git history linear and gives
release-please a clean, single commit to analyze per PR. With squash
merge, the PR title becomes the commit message — ensure it follows the
Conventional Commits format defined in `docs/conventions.md` (Git
Conventions).

### Changelog

`CHANGELOG.md` (repository root) is maintained automatically by
release-please. Do not edit it manually. New release entries contain only
Features and Bug Fixes and link to commits and PRs; historical entries are not
rewritten when this policy changes. The changelog lives at
the repository root while the version bump it accompanies
(`backend/pyproject.toml`, `backend/uv.lock`) stays scoped to the
`backend` release-please package — see `changelog-path` in
`release-please-config.json`.

### Pipeline Chain

```
master branch commits (via squash-merge PR)
     │
     ▼
CI (ci.yml) — all quality gates
     │ (on success)
     ▼
release-please.yml (workflow_run, gated behind CI)
     → creates/updates Release PR
     │ (on merge)
     ▼
creates git tag (v*) + GitHub Release
     │
     ▼
build-images.yml (workflow_run, gated behind CI on master; also push tags)
     → builds image once → image smoke-test gate → SBOM gate
     → pushes same digest to ghcr.io (only if gate passes)
     → version tags: publishes SBOM asset + signed SBOM/provenance attestations
     │
     ▼
manual deployment from tag (staging/production)
```

### Version Locations

| Location | Mechanism |
|----------|-----------|
| `backend/pyproject.toml` | Updated by release-please (source of truth) |
| `backend/app/main.py` | Reads dynamically via `importlib.metadata` |
| Git tag | Created by release-please (`v1.2.3`) |
| Docker image tag | Derived from git tag by `build-images.yml` |
| GitHub Release | Created by release-please with changelog |
| Release SBOM | Generated from the final image by `build-images.yml` and attached to the GitHub Release |
| Signed attestations | Generated by `build-images.yml` for the immutable release image digest and published through GitHub Artifact Attestations and GHCR |
| `CHANGELOG.md` (repository root) | Updated by release-please |
| `backend/uv.lock` | Updated by release-please |

### Image Tag Semantics

`build-images.yml` publishes images to `ghcr.io/<repo>` under distinct
tags depending on which trigger produced the build. Each tag has exactly
one meaning — there is no overlap between what the `master` build
produces and what a version-tag build produces:

| Tag | Produced by | Meaning |
|-----|-------------|---------|
| `master` | Every merge to `master` (`workflow_run` trigger, via `type=ref,event=branch`) | Latest CI-green `master` HEAD. Not a release artifact — content changes on every merge |
| `latest` | Highest semver tag pushed so far (`push: tags: v*` trigger, via `docker/metadata-action`'s default `flavor: latest=auto`) | The most recently published release. Only ever produced by a version-tag build |
| `X.Y.Z` | Version tag push (`push: tags: v*`) | The exact release version |
| `X.Y` | Version tag push (`push: tags: v*`) | Floating pointer to the latest patch release within that minor version |

**Why `master` never produces `latest`**: `docker/metadata-action` derives
`latest` exclusively from its semver `flavor: latest=auto` default, which
only activates on the semver-tag trigger path. The `master`-triggered
path only matches the `type=ref,event=branch` rule, producing the
`master` tag alone. No explicit raw `latest` rule is declared in the
`tags:` input — adding one would make both trigger paths produce
`latest` independently, racing each other with no deterministic winner
and leaving `latest` pointing at `master` HEAD after every subsequent
merge instead of the last release. `latest` is therefore reliable for
consumers (e.g., `image-scan.yml`, manual deployments) that expect it to
track "the last release," not "the tip of master."

### Release Supply-Chain Artifacts

Every version-tag build publishes three related but distinct supply-chain
records for the released OCI image:

| Record | Meaning | Publication |
|--------|---------|-------------|
| CycloneDX SBOM | Inventory of components found in the final runtime image | `sentinel-<version>.sbom.cdx.json` asset on the corresponding GitHub Release; `<version>` omits the tag's `v` prefix, for example `sentinel-1.2.3.sbom.cdx.json` |
| Signed SBOM attestation | Authenticated claim that the CycloneDX document describes the named image digest | GitHub Artifact Attestations and an OCI attestation associated with the image in GHCR |
| Signed build provenance | Authenticated SLSA provenance identifying the source repository, commit, workflow, and workflow run that asserted the image digest | GitHub Artifact Attestations and an OCI attestation associated with the image in GHCR |

The immutable subject of both attestations is
`ghcr.io/<owner>/<repository>@sha256:<digest>`, never `latest`, `master`, or
another mutable tag. The GitHub Release asset contains the same validated SBOM
passed to the SBOM-attestation action. The SBOM is external to the image and
does not change its runtime contents.

#### SBOM format and scope

The authoritative release inventory is CycloneDX 1.7 JSON generated with Syft
from the final, locally loaded image after the image smoke test and before the
first registry push. Scanning the final image covers installed Python and
Debian packages while excluding builder-only tools and development
dependencies that are absent from the runtime stage. All runtime process roles
share this image, so they share one SBOM.

`backend/uv.lock` remains the dependency-resolution source for Python builds,
but an export from that lockfile is not a release SBOM: it does not cover the
OS layer and does not prove what was installed in the released image. Sentinel
does not publish a second Python-only or SPDX SBOM unless a concrete consumer
requires one.

The SBOM is a component inventory, not a vulnerability report. Vulnerability
matches change as advisory databases evolve and are evaluated separately by
tools such as Trivy, Grype, or Dependency-Track. A component's presence does
not by itself establish that Sentinel is affected by every vulnerability
associated with that component; a future VEX record may communicate that
assessment without changing the inventory.

#### Trigger and gate semantics

SBOM generation and validation run against the locally loaded image in pull
request CI and in every `build-images.yml` execution. Pull-request and `master`
SBOMs are retained as seven-day workflow artifacts for inspection and are not
release records. Only a `v*` tag build uploads the versioned GitHub Release
asset and creates signed SBOM and provenance attestations. The complete SBOM
gate is defined in `docs/features/platform/testing-strategy.md` (SBOM Gate).

A failure in generation or validation prevents image publication. After all
tags are pushed, the workflow obtains and cross-checks the registry-reported
digest for every tag. A missing or mismatched digest fails the build job before
any attestation is created. On a version-tag build, release-asset upload and
both attestations run in a separate release-metadata job. Failure of that job
fails the workflow but cannot revoke the image already published by its
successful prerequisite job. In that state, consumers MUST treat the release
metadata as incomplete. Maintainers repair it by rerunning failed jobs, which
reuses the successful build job's digest and SBOM artifact instead of
rebuilding. The rerun replaces the same-named GitHub Release asset and may add
equivalent attestations for the same digest.

Both attestations are stored in GitHub's Attestations API and as OCI referrers
alongside the subject image in GHCR. The API copy supports normal repository-
scoped verification; the OCI copy supports registry-native discovery and
verification and can travel with tooling that preserves OCI referrers. Sentinel
does not request a GitHub artifact storage record because that feature applies
only to organization-owned repositories.

#### Consumer discovery and verification

The downloadable inventory is listed under **Assets** on the version's GitHub
Release. Consumers should use an exact version tag only to discover the image,
then retain the digest-qualified reference returned by the registry for both
verification and deployment:

The commands below require Docker with the Buildx CLI plugin, `jq`, and an
authenticated GitHub CLI (`gh`).

```bash
set -euo pipefail

TAGGED_IMAGE="ghcr.io/staypirate/sentinel:0.6.0"
IMAGE_NAME="${TAGGED_IMAGE%:*}"
DIGEST="$(docker buildx imagetools inspect "$TAGGED_IMAGE" \
  --format '{{json .Manifest}}' | jq -er '.digest')"
IMAGE="${IMAGE_NAME}@${DIGEST}"
docker pull "$IMAGE"

# Verify SLSA build provenance from Sentinel's release workflow.
gh attestation verify "oci://$IMAGE" \
  --repo StayPirate/sentinel \
  --signer-workflow StayPirate/sentinel/.github/workflows/build-images.yml

# Verify the signed CycloneDX SBOM claim.
gh attestation verify "oci://$IMAGE" \
  --repo StayPirate/sentinel \
  --signer-workflow StayPirate/sentinel/.github/workflows/build-images.yml \
  --predicate-type https://cyclonedx.org/bom

# Configure every runtime role to use this exact $IMAGE value for deployment.
```

Add `--bundle-from-oci` to either verification command to retrieve and verify
the registry-side OCI copy instead of querying GitHub's Attestations API.

An exact-version tag such as `0.6.0` expresses release identity, but remains a
registry lookup reference and can technically be repointed unless a separate
publisher-side control prevents it. Reusing the resolved `name@sha256:digest`
value closes the tag-movement window between verification and deployment and
keeps an existing deployment on the verified artifact. It does not by itself
prevent the publisher from associating the same nominal version with another
digest later; exact-version tag immutability is a separate release control.

Verification checks the Sigstore-backed signer identity, predicate type, and
subject digest. Build provenance establishes which repository commit and
workflow run asserted that digest; it does not prove reproducibility or by
itself enumerate every build input. Consumers needing the signed material
offline can download the attestation bundle and trusted roots with `gh
attestation download` and `gh attestation trusted-root` before entering the
offline environment.

### API Documentation Publication

On every version release (version tag push), the OpenAPI contract and an
interactive API documentation site are published to GitHub Pages. API
consumers — including the frontend application developed in a separate
repository — depend on this publication as the authoritative,
machine-readable contract reference.

### Container Image Retention

Untagged container image versions in the package registry are subject to
bounded retention: only a fixed number of the most recent untagged
versions are kept; older untagged versions are removed on a weekly
schedule. Tagged images (`master`, `latest`, semver release tags) are
never subject to cleanup — only the pool of untagged versions (produced
as a side effect of re-tagging on every push) is bounded.

### Configuration Files

Release automation uses two files at the repository root with distinct
ownership:

- `release-please-config.json` — hand-authored release policy and package
  configuration; change it only through a reviewed policy/automation PR
- `.release-please-manifest.json` — release-please-maintained current-version
  state; do not edit it manually

`Release-As` is commit metadata and requires no edit to either file. The
`extra-files` entry that keeps `backend/uv.lock` atomic with
`backend/pyproject.toml` is part of the hand-authored policy (see Version
Locations above).

### Repository Secrets

The `release-please.yml` workflow requires a repository secret named
`RELEASE_TOKEN` containing a Fine-Grained Personal Access Token (or
GitHub App token) with `contents: write`, `issues: write`, and
`pull-requests: write` permissions. The default `GITHUB_TOKEN` cannot
be used because tags created by it do not trigger downstream workflows
(a GitHub Actions limitation to prevent recursive runs).

The `ci.yml` workflow optionally uses a repository secret named
`CODECOV_TOKEN` for uploading test coverage reports to Codecov. The
upload step is non-blocking (`fail_ci_if_error: false`) — if the
secret is not configured, coverage will silently not be uploaded but
CI will still pass. Obtain the token from
[codecov.io](https://codecov.io) after linking the repository.

---

## Process Architecture

### Container Images

All runtime processes run from the same OCI image with different
entrypoint commands — see `docs/architecture.md` (Single Docker image,
multiple entrypoints) for the rationale. This is the canonical
enumeration of all process roles.

**Runtime processes** (long-running):

| Process | Role | Scalable |
|---------|------|----------|
| API server (uvicorn) | HTTP request handling | Yes (multiple replicas) |
| Celery worker | Background task execution | Yes (multiple workers) |
| Git worker (Celery) | Git-based fetcher execution | No (single, volume affinity — see [Git Worker Volume](#git-worker-volume)) |
| Celery Beat | Periodic task scheduling | No (singleton) |
| IBS RabbitMQ consumer | Real-time event consumption | No (singleton — see `docs/features/integrations/ibs-rabbitmq-integration.md`) |

**One-shot jobs:**

- Alembic migration job — see [Database Migrations](#database-migrations)

### Singleton Processes

Celery Beat and the IBS RabbitMQ consumer are singleton processes.
Running multiple instances causes duplicate task scheduling or duplicate
event processing. The git worker is constrained to a single instance by
volume affinity (ReadWriteOnce), not by a logical singleton requirement.

Local environments run one instance of each. Kubernetes deployments must
enforce singleton constraints unless a future design introduces
distributed locking or leader election.

The IBS RabbitMQ consumer is a standalone process, not a Celery worker. It
does not import the Celery application or fetcher registry, consume or publish
Celery messages, or depend on `CELERY_BROKER_URL`, Redbeat, or a Celery result
backend. PostgreSQL is required for authoritative selection and reconciliation.
Redis is non-authoritative and is used only through `REDIS_URL` for the
best-effort consumer heartbeat.

When enabled, the consumer validates configuration, verifies PostgreSQL, starts
the best-effort heartbeat, and then connects and establishes its fixed AMQP
topology. Transient RabbitMQ failures reconnect with exponential backoff from 5
seconds to a 300-second cap; permanent TLS, authentication, authorization, or
topology failures exit non-zero for operator correction and orchestrator
restart. On SIGTERM or SIGINT, the consumer stops new deliveries, gives its one
in-flight handler at most 30 seconds to finish, then cancels incomplete work and
closes AMQP resources best-effort. `IBS_RABBITMQ_ENABLED=false` exits cleanly
without connecting to PostgreSQL, Redis, IBS, or RabbitMQ.

### Celery Worker Pool Requirement

Every Sentinel worker process (Celery worker and Git worker — see
[Container Images](#container-images)) MUST run with the `prefork`
execution pool. No other pool implementation (`solo`, `threads`,
`gevent`, `eventlet`, or a custom pool) is supported.

**Why**: the fetcher framework's Running Stale Threshold (see
`docs/features/platform/fetcher-infrastructure.md`, Stale Run
Detection) depends on the Celery hard time limit reliably terminating
the worker process that executes a fetcher run. This guarantee only
holds under `prefork`:

- `solo`, `threads`, and `eventlet` do not enforce the hard time limit
  at all — a task exceeding it continues running indefinitely.
- `gevent` enforces a cooperative timeout that does not terminate a
  blocking task, so it cannot provide the same guarantee either.

Under any of these pools, a fetcher run that never terminates could be
declared stale and finalized while still executing, allowing a second
concurrent instance of the same fetcher to start — violating the
single-instance invariant (see
`docs/features/platform/fetcher-infrastructure.md`, Concurrency
Control).

**Enforcement**: every Celery worker process validates its own
resolved pool implementation at startup, before the fetcher config
bootstrap runs and before the consumer starts accepting tasks. A
worker started with an incompatible pool fails fast with a critical
log identifying the offending pool and exits with a non-zero status —
see `docs/features/platform/fetcher-infrastructure.md` (Worker
Startup Handler) for the exact mechanism.

Operator-facing worker commands MUST pass `--pool=prefork` explicitly
(or omit `--pool`, since `prefork` is Celery's own default) — see the
Quick Start command in [Local Development](#local-development) and the
active `worker` service and the currently-commented-out `git-worker`
service definition in `docker-compose.smoke.yml`.

### Startup Ordering

Successful completion of the external Alembic migration job is a hard
prerequisite for every runtime process. A failed or incomplete migration MUST
prevent runtime startup. After migrations complete, all runtime processes
(API server, Celery worker, Git worker, Celery Beat, IBS RabbitMQ consumer)
MAY start in any order. No inter-process startup dependency exists.

This property is guaranteed by the following mechanisms:

- **`bootstrap_fetcher_configs()`** runs in every registry-consuming process
  (general worker, Git worker, Beat, API server) after importing the shared
  fetcher discovery module, and uses `INSERT ... ON CONFLICT DO NOTHING` — Beat
  does
  not depend on workers or the API having created `FetcherConfig` records
  first. If Beat starts first, it creates them; if a worker starts first,
  Beat's bootstrap is a no-op (records already exist); if all start
  simultaneously, the first `INSERT` wins and concurrent duplicates are
  no-ops. The function receives a caller-supplied `AsyncSession`, flushes
  without committing, and leaves transaction ownership to the calling
  startup workflow (see
  `docs/features/platform/fetcher-infrastructure.md`, FetcherConfig).
  Worker and Beat signal handlers that invoke bootstrap live under
  `app/tasks/` (not `app/core/`) — see `docs/architecture.md` (Backend
  Layer Architecture).
- **`system_setting` seeding** uses `ON CONFLICT DO NOTHING` (Alembic
  data migration is the primary mechanism; FastAPI lifespan is
  defense-in-depth). The API lifespan completes this bootstrap transaction
  before serving requests. Database, schema, bootstrap, or commit failure
  aborts API startup rather than allowing degraded request serving; see
  `docs/features/platform/system-settings.md` (Bootstrap).
- **The IBS RabbitMQ consumer** first verifies PostgreSQL, then starts its
  best-effort Redis heartbeat and connects to RabbitMQ. PostgreSQL failure is
  fatal because domain reconciliation cannot proceed. Redis connection or
  heartbeat-write failure is monitoring degradation: it logs a warning and
  consumption continues. RabbitMQ unavailability enters the consumer's bounded
  reconnect loop, so it operates independently of Beat and workers.
- **Other runtime roles** apply their own feature-defined infrastructure
  dependency and degradation contracts. No process silently waits for another
  application process.

If a future change introduces an inter-process startup dependency, this
section MUST be updated with the new constraint and the deployment
manifests (Docker Compose, Kubernetes) adjusted accordingly.

See `docs/features/platform/fetcher-infrastructure.md` (Startup
Reconciliation, Complete Beat Startup Sequence) for the Beat-specific
startup sequence detail.

The self-contained image-smoke stack MUST enforce the migration prerequisite
directly: its API service depends on the one-shot `migrate` service reaching
successful completion, in addition to infrastructure health. An unsuccessful
migration therefore prevents the API container from starting; simple
concurrent startup of `api` and `migrate` is not conformant. The artifact gate
verifies both directions of this ordering; see
`docs/features/platform/testing-strategy.md` (Image / Container Smoke Testing).

### Git Worker Volume

The git worker requires a persistent volume mounted at
`$GIT_CLONE_BASE_DIR` (default: `/var/lib/sentinel/git`). This volume
stores bare clones of external git repositories used by CVE fetchers.

| Property | Value |
|----------|-------|
| Minimum capacity | 8 GB |
| Access mode | ReadWriteOnce (single worker) |
| Backup | Not required — recoverable cache (fetchers re-clone if lost) |

Bare clones have no working tree — accidental checkout expansion
(which could consume ~4 GB for cvelistV5 alone) is structurally
impossible.

See `docs/features/platform/git-fetcher-infrastructure.md` (Volume
Requirements, Recovery, Worker Affinity) for volume layout, recovery
procedures, and worker affinity configuration.

### Timezone and Locale Requirements

All Sentinel runtime processes (see [Container Images](#container-images))
MUST operate with UTC as the system timezone. This is enforced
at two levels:

1. **Celery configuration**: the application sets `timezone = "UTC"` and
   `enable_utc = True` in the Celery config. The Celery app factory
   validates these at module import time and raises a `RuntimeError` if
   overridden — this prevents any Celery-based process from starting
    with incorrect timezone configuration (see
    `docs/features/platform/fetcher-infrastructure.md`, Startup
    Validation)

2. **Container timezone**: set `TZ=UTC` in the container environment (or
   leave unset — most base images default to UTC). This ensures that
   system-level time functions (`datetime.now()`, file timestamps, log
   entries) are consistent with the Celery scheduler

The Celery import-time validation applies only to Celery-based roles. The IBS
RabbitMQ consumer does not import the Celery application; its UTC requirement
is enforced by the process/container environment and its own UTC datetime
handling.

**Why this matters**: all fetcher cron schedules are expressed in UTC.
Some external data sources publish at specific UTC times (e.g., EPSS at
13:31 UTC daily). A timezone misconfiguration causes fetchers to run at
incorrect wall-clock times, potentially before upstream data is
available.

#### Locale for git worker containers

Containers running the git worker (git-based CVE fetchers) SHOULD set
`LC_ALL=C` in their environment as a secondary defense. The primary
guarantee is code-level: `git_operations.py` injects `LC_ALL=C`,
`GIT_TERMINAL_PROMPT=0`, and `TZ=UTC` into every git subprocess call
(see `docs/features/platform/git-fetcher-infrastructure.md`, Module
Invariants — Rule 3). The container-level setting serves as
defense-in-depth in case a future code path invokes git outside the
centralized module.

Recommended container environment for git workers:

```
TZ=UTC
LC_ALL=C
GIT_TERMINAL_PROMPT=0
```

### Clock Synchronization

All application instances in a multi-instance deployment must have their
system clocks synchronized via NTP (or an equivalent time
synchronization protocol). Sentinel relies on timestamps for several
security and correctness mechanisms:

- SSO state parameter validation (10-minute TTL window)
- JWT `exp` and `iat` claim verification
- Session expiration enforcement
- Cache TTL calculations (discovery document, JWKS)

Clock skew between instances can shorten or lengthen time-based windows
unpredictably. For example, if the instance generating an SSO state has
a clock 2 minutes ahead of the instance processing the callback, the
effective validity window shrinks from 10 minutes to 8 minutes. While
modern NTP-synced servers typically maintain sub-second accuracy (making
this negligible in practice), operators must ensure NTP is configured
and running on all hosts.

---

## Operations

### Database Migrations

Migrations are managed by Alembic and must be run explicitly:

```bash
# Apply all pending migrations
alembic upgrade head

# Check current migration state
alembic current

# Create a new migration
alembic revision --autogenerate -m "description"
```

**Rules**:
- Never run migrations automatically on API container startup
- Always run migrations as a separate step before deploying new code
- In Kubernetes: use a Job that runs before the Deployment rollout
- In a container runtime: run as a one-shot container before starting services

#### Migration Failure Recovery

**Recovery strategy: fix-forward.** Sentinel does not support `alembic
downgrade` in production. When a migration fails, the operator corrects
the root cause (network issue, disk space, code bug) and re-runs
`alembic upgrade head`. Migrations are not required to implement a
functional `downgrade()` function.

**PostgreSQL transactional DDL.** PostgreSQL executes DDL statements
(`CREATE TABLE`, `ALTER TABLE`, `DROP COLUMN`, etc.) inside
transactions. If a migration fails for any reason, the transaction is
rolled back automatically — the schema returns to its pre-migration
state. This eliminates the most dangerous failure mode (partially
applied schema changes) that affects other databases.

**Diagnostics.** After a migration failure, run `alembic current` to
determine the database state. If it reports the pre-migration revision,
the transactional rollback succeeded and the schema is intact. If it
reports an unexpected state, compare the `alembic_version` table
contents against the actual schema objects to assess the situation
before re-running.

**Deployment model: stop-the-world.** All application processes (API
server, Celery workers, Celery Beat, IBS consumer) must be stopped
before running migrations, then restarted with the new code version.
There is no requirement for backward compatibility between the schema
of version N and the application code of version N-1. This simplifies
migration authoring — schema changes do not need to be split across
multiple releases to maintain compatibility with running code.

#### Post-Deployment Recovery

When a deployment succeeds (migrations applied, new code running) but a
critical application bug is discovered afterward, the recovery strategy
is also fix-forward:

1. **Immediate mitigation**: stop all application processes
   (stop-the-world) to prevent the bug from causing further damage.
   The system is unavailable during this window
2. **Prepare a hotfix**: create a patch release that fixes the bug.
   This is a new forward version, not a rollback to a previous one
3. **Deploy the hotfix**: run any pending migrations (if any) and
   restart services with the hotfix version

**Do not deploy a previous container image.** Because the database
schema is not required to be backward-compatible with older code
versions, deploying an older image against the current schema may cause
query failures, data corruption, or silent data loss. The only safe
recovery direction is forward.

**Pre-deployment database backup.** Before every production deployment,
take a database backup (e.g., `pg_dump`) so that in the extreme case
where a bug has already corrupted data, the database can be restored to
a consistent pre-deployment state. The backup is a safety net, not the
primary recovery mechanism — fix-forward remains the standard path.

### CLI Operational Access

The `sentinel` console script is available on `PATH` inside every
container image, because all process roles share the same Docker image
(see [Container Images](#container-images)). See `docs/cli-reference.md`
for the full command catalog.

**Execution model.** In staging and production, CLI commands are
executed **exclusively via container shell access** — there is no
supported host-level execution path in these environments. (Running the
CLI directly on the host via `uv run python -m app.cli ...` is a
local-development-only pattern — see [Local Development](#local-development)
above. It relies on a local `uv`-managed virtual environment that does
not exist in staging/production containers.)

**Environment dependencies.** Run CLI commands in an environment where
both PostgreSQL and Redis are reachable — the same dependencies already
required by the API and worker processes. Most commands only need
PostgreSQL. `sentinel manage-user unlock` and `sentinel manage-user
set-password` also clear login lockout state stored in Redis, while
`sentinel manage-user deactivate` purges session-liveness cache entries;
Redis connectivity is therefore required for those effects to be immediate.
This is operational guidance about environment provisioning, not a new runtime
hard dependency. Feature-specific fallback behavior remains defined in
`docs/features/identity/local-authentication.md` and
`docs/features/identity/authentication.md`; the Redis cleanup behavior of the
three commands named above is defined in
`docs/features/identity/user-service.md`.

**Container runtime pattern.** The Docker example below generalizes
the one-off container approach already used for Alembic migrations
(see [Database Migrations](#database-migrations)):

```bash
# Recommended: one-off container
docker run --rm -it --env-file .env sentinel:latest \
  sentinel <group> <command> ...

# Alternative: exec into an already-running container
docker exec -it <container> sentinel <group> <command> ...
```

Interactive commands (`manage-user create`, `manage-user set-password`,
and `manage-user deactivate`) require a TTY — the `-it` flags shown
above are mandatory for these commands. The password commands prompt for
hidden password input; `manage-user deactivate` prompts for
destructive-operation confirmation.

Consumers deploying the OCI image through another compatible runtime may adapt
these runtime-shell commands to their chosen environment. Sentinel does not
require a runtime-specific image variant.

**Kubernetes pattern.** The deployment target (Kubernetes, Docker
Compose, or another orchestrator) remains undecided (see
[Staging-Specific Notes](#staging-specific-notes)). The Kubernetes
pattern below is documented so operators are not blocked regardless of
which target is eventually chosen:

```bash
# Ad hoc: exec into a running pod
kubectl exec -it <pod> -- sentinel <group> <command> ...

# Recommended for one-off operations: a dedicated Job/pod built from
# the same image, analogous to the Alembic migration Job
```

### Health Checks

The API exposes lightweight liveness and readiness checks so
orchestrators can distinguish between a running process and a service
ready to handle traffic. See
`docs/features/platform/health-endpoints.md` for the authoritative
endpoint specification (response schemas, failure semantics, design
decisions).

| Endpoint | Purpose | Checks |
|----------|---------|--------|
| `GET /health` | Liveness | API process running |
| `GET /ready` | Readiness | PostgreSQL + Redis reachable |

Configure your orchestrator to use these endpoints:

- **Docker**: `healthcheck` directive in compose file or Dockerfile
- **Kubernetes**: `livenessProbe` → `/health`, `readinessProbe` → `/ready`

The orchestrator MUST set `timeoutSeconds` (Kubernetes) or `timeout`
(Docker) to at least 5 seconds to accommodate the internal check
timeouts (2s per dependency, checks concurrent; 5s provides margin for network overhead).

These are generic API-process probes; their PostgreSQL-plus-Redis readiness
semantics are unchanged by the standalone consumer's dependency model. Monitor
the IBS consumer through process supervision and
`GET /api/v1/ibs-consumer/status`. That endpoint reports `disabled` when the
consumer is configured off and `unreachable` when Redis cannot provide a valid
fresh heartbeat; both are HTTP 200 operational observations.

### Redis Durability, Memory, and Persistence

Sentinel uses Redis in two roles, addressed by two configuration URLs
(see `docs/configuration.md`):

- **Application cache/coordination** (`REDIS_URL`, db 0): session
  liveness cache, login lockout counters, on-demand fetch deduplication
  markers and pending overlays, the CVSS recalculation admission and
  ownership lease, and the IBS consumer's best-effort
  operational heartbeat.
- **Celery broker + scheduler** (`CELERY_BROKER_URL`, db 1): task queue
  and `celery-redbeat` schedule entries (including the distributed lock
  used as recovery sentinel).

#### Persistence is Disabled by Design

Redis persistence (RDB and AOF) MUST be disabled in all environments:

```
save ""
appendonly no
```

**Rationale**:

1. **No durable data lives solely in Redis.** PostgreSQL is the source
   of truth for all persistent state (sessions, schedules, task
   outcomes, mutation serialization). Every Redis key is either
   TTL-bounded and self-healing, or fully reconstructible at Beat
   startup — from PostgreSQL (fetcher schedules, via Sentinel's startup
   reconciliation) or from code (non-fetcher static entries, via
   redbeat's native `setup_schedule()`). See
   `docs/features/platform/fetcher-infrastructure.md` ("Non-Fetcher
   Periodic Tasks") for the coexistence mechanism.

2. **The Beat lock sentinel provides automatic recovery.** When Redis
   loses data (restart or flush), Beat detects the missing lock within
   ≤60 seconds, terminates, and the orchestrator restarts it. The
   startup process rebuilds the full schedule — fetcher entries from
   PostgreSQL (reconciliation) and non-fetcher static entries from code
   (`setup_schedule()`). No manual intervention is required. See
   `docs/features/platform/fetcher-infrastructure.md` (Runtime: Redis
   Data Loss) for the mechanism.

3. **Persistence would undermine the lock sentinel.** If RDB restored
   the `redbeat::lock` key after a Redis restart (the snapshot is recent
   enough that the lock has not expired — the lock TTL is 300s, typically
   still valid within a restart window), Beat's `lock.extend()` would
   succeed, the sentinel would NOT fire, and Beat would continue running
   with the schedule from the snapshot — bypassing the clean crash →
   reconciliation recovery path. Expired keys are correctly discarded at
   RDB reload, so this concerns non-expired keys specifically. Volatile
   Redis guarantees the lock is always absent after data loss, ensuring
   the sentinel always fires.

4. **Task queue loss is acceptable.** Queued tasks that are lost during
   a Redis restart are recovered by the next periodic fetcher execution on that
   source's schedule (see the Fetcher Registry in `docs/data-sources.md`).
   On-demand fetches can be re-triggered via the API. The `FetcherRun` table in
   PostgreSQL tracks outcomes — no Celery result backend is used.

The IBS consumer heartbeat is not a task result, delivery checkpoint, or domain
state. The consumer writes the complete `sentinel:ibs_consumer_status` JSON
value atomically through `REDIS_URL` every 30 seconds and on status changes,
with a 60-second TTL. Redis loss or write rejection makes consumer liveness
temporarily unobservable but does not pause event processing. PostgreSQL and
the owning periodic fetchers remain the recovery authorities.

#### CVSS Recalculation Coordination and Redis Loss

The all-CVE recalculation uses `REDIS_URL` for one admission and ownership
lease, `cvss_recalc_active`. The lease is not an authoritative lock and is not
proof that the run is alive or complete:

- the complete-run coordination contract is defined in
  `docs/features/platform/default-cvss-version-operations.md`
  (Complete-Run Coordination);
- the lease is a TTL-bounded key. Redis restart, flush, eviction, or expiry
  removes it, but removal never authorizes overlapping mutation: the task also
  holds a non-persistent PostgreSQL session-level advisory execution fence for
  its complete mutating workflow, and only the exact lease owner may adopt the
  run;
- Redis persistence remains disabled by design (Persistence is Disabled by
  Design above). Reconstructing the lease is unnecessary and unsupported; a
  missing lease is not treated as completion; and
- `noeviction` remains the only conforming memory policy. The lease is tiny and
  is not a reason to change memory configuration.

A worker that is alive but wedged can retain the PostgreSQL fence
indefinitely. This deliberately favors safety over availability: until the
fence is released or its connection closes, no new admission succeeds. The
operator procedure below terminates that worker before retrying.

#### Memory Configuration

Redis MUST be configured with explicit memory limits and the
`noeviction` policy to prevent silent data loss through eviction:

| Setting | Value | Purpose |
|---------|-------|---------|
| `maxmemory` | `768mb` | Internal memory ceiling (~75% of container limit). When reached, Redis refuses new writes rather than evicting existing keys |
| `maxmemory-policy` | `noeviction` | Write commands return OOM error; read commands continue. Preserves all existing data (queued tasks, schedule entries, locks) |

**Container resource limits** (Kubernetes QoS Guaranteed):

| Resource | Value | Purpose |
|----------|-------|---------|
| `requests.memory` | `1Gi` | Minimum guaranteed memory (scheduler placement) |
| `limits.memory` | `1Gi` | Maximum allowed memory (kernel OOM-kill threshold) |

Setting `requests == limits` achieves QoS class "Guaranteed": the pod
is never evicted under node memory pressure. This is appropriate for
Redis as a broker/coordination service.

**Why `maxmemory` must be lower than `limits.memory`**: the container
memory limit is enforced by the kernel — exceeding it causes immediate
process termination (OOM-kill). The Redis `maxmemory` setting is an
*internal* threshold that triggers the `noeviction` policy *before* the
kernel intervenes. The ~25% gap (768 MB vs 1024 MB) provides headroom
for Redis process overhead: allocator fragmentation, client connection
buffers, internal data structures, and Lua script execution memory.

**Behavior when `noeviction` triggers**: Redis returns
`OOM command not allowed when used memory > 'maxmemory'` on write
commands. Read commands continue normally. Application code handles this
as a `RedisError` according to the behavior specified by each owning feature
(see `docs/conventions.md`, Redis Error Handling). For the Celery broker, OOM
indicates a capacity issue — operators should investigate queue backlog growth
(e.g., workers not consuming tasks).

**If the orchestrator imposes a memory limit lower than `maxmemory`**:
the kernel OOM-kills Redis *before* the `noeviction` policy activates.
The `maxmemory` becomes ineffective. Always ensure: `maxmemory` <
container `limits.memory`.

**Memory sizing rationale**: Sentinel's Redis footprint is small.
Application keys (db 0) total < 10 MB even with thousands of active
sessions. Redbeat entries are negligible (~1 KB × ~12 fetchers). The
primary variable is the Celery task queue backlog (db 1): under normal
operation nearly empty (workers consume in real-time); under stress
(first-run with thousands of CVEs, or workers down) may grow to
~100-150 MB. The 768 MB `maxmemory` provides >5× headroom over
realistic peak usage.

#### Monitoring Scheduler Liveness (Recommended)

The lock sentinel mechanism ensures automatic recovery in all standard
failure modes. As defense-in-depth for edge cases (lock accidentally
disabled, Redis manipulated selectively), operators SHOULD configure
external monitoring on scheduler activity.

**Recommended signal** (cause-agnostic — detects any cause of stalled
ingestion):

> Alert when at least one fetcher with `enabled = true` has a
> `last_run.finished_at` older than 2× its configured schedule interval,
> has never run (`last_run = null`), or has `last_run.stale = true`.

This signal is derivable from `GET /api/v1/fetchers` without any code
changes to Sentinel. It detects not only empty schedules but also dead
workers, database unavailability, or any other cause of stalled
processing. Runs still in progress (`status` is `queued` or `running`)
have `last_run.finished_at = null` and are covered by the
`last_run.stale` condition once the respective threshold is reached —
600 seconds for a `queued` run awaiting worker adoption,
`hard_time_limit_seconds + 60` seconds for a `running` run (where
`hard_time_limit_seconds` is the per-run effective hard limit persisted
at adoption — see `docs/features/platform/fetcher-infrastructure.md`,
Stale Run Detection). A manual run normally resolves from `queued` to
`running` within seconds of a healthy worker fleet, so a `queued` run
tripping its much shorter threshold is itself a useful early signal of
broker or worker unavailability, independent of any individual fetcher's
schedule.

**Why not `/health` or `/ready`**: these endpoints report API server
instance health for the load balancer. Returning non-200 for a Beat
problem would incorrectly remove healthy API instances from rotation.
Beat is a separate process — its liveness is the orchestrator's
responsibility, not the API server's.

**When the schedule is legitimately empty**: if an operator disables all
fetchers, the schedule is empty by design. The monitoring signal above
correctly handles this: with no enabled fetchers, the condition "at
least one enabled fetcher with stale last_run" is false → no alert.

### CVSS Recalculation Recovery

An interrupted, crashed, or uncertain all-CVE recalculation is recovered by a
complete explicit rerun through
`POST /api/v1/admin/settings/default-cvss-version/recalculate`. There is no
resume cursor and no persistent progress state; the run always restarts from
the beginning and converges idempotently. The behavioral contract is
`docs/features/platform/default-cvss-version-operations.md` (Complete-Run
Coordination).

Operator procedure:

1. **Identify the worker or pod** that may hold the PostgreSQL execution fence,
   using the coordination log events and platform metadata. A repeated `409
   CVSS_RECALC_ALREADY_IN_PROGRESS` from the manual trigger, without an active
   runner renewing its lease, is the recovery-required signal.
2. **Terminate the worker or pod if it is alive and wedged.** A live process
   that cannot make progress can retain the session-level fence; terminating it
   closes its connection and releases the fence automatically.
3. **Wait for the lease to expire, or remove it owner-safely only.** The lease
   has a 900-second TTL; waiting for TTL expiry is always sufficient. If an
   operator removes it earlier, they MUST do so owner-safely by comparing the
   complete expected value — never with an unconditional
   `DEL cvss_recalc_active`, which could remove a newer owner's record. When
   the stored value is unknown or malformed, there is no owner to compare
   against, so the only supported recovery is TTL expiry.
4. **Repeat the trigger.** Once the fence is released and the lease is absent or
   expired, the manual trigger admits a new run.
5. **The run restarts from the beginning.** Committed units reclassify
   `unchanged`; no persistent progress is restored.

For every interceptable runner outcome, a failed Redis cleanup delays
readmission only until the lease TTL; it never permits the task to retain the
PostgreSQL fence merely to wait for Redis. The owning coordination specification
defines the exact cleanup ordering.

A delivery can also be rejected during adoption before any worker becomes an
active runner, for example because its initial ownership confirmation failed or
was uncertain. That outcome creates no overlap and no terminal run event. If
the delivery's known admitted token remains exactly in the lease, wait for its
TTL or remove that exact token with owner-safe comparison, then repeat the
manual trigger. An absent or mismatched lease is never removed by the rejected
delivery; wait for the current owner or TTL. Do not restart or retry the
rejected Celery delivery automatically.

A Settings PATCH never publishes a run. A `409` or `422` rejection
deterministically commits nothing. Any other failed or unconfirmed PATCH
response means the setting change may or may not have persisted; read the
current setting with `GET /api/v1/admin/settings` before deciding. A
successful effective change persists the value and its audit event, while a
successful no-op returns the persisted value and changes nothing. A successful
setting change converges existing derived state only after a manual trigger; if
the manual trigger fails or its publication outcome is uncertain, follow the
lease, task, and fence recovery above. Repeating the same PATCH starts no work
and never repairs a run; the recalculation is recovered exclusively through the
manual trigger.

No recovery procedure may treat logs, the absence of a terminal event, or a
missing Redis key as proof that the previous run completed or that its process
is gone. PostgreSQL is the source of truth for completed derived state. The
runner configures no automatic Celery retry; recovery is always the complete
manual rerun above.

### Log Aggregation

See `docs/features/platform/logging.md` for the application-side
contract (structured format, log levels, correlation IDs, standard
record schema). This section documents how the log stream surfaces
and is retained in each deployment context — the application itself
never writes, rotates, or persists log files; it only writes to
stdout/stderr.

#### Container runtimes

Logs are captured via the container engine's logging driver. For
local rotation without any external log shipper, configure the
runtime's bounded logging driver with rotation options. The repository-managed
Docker Compose environment uses `json-file` with `max-size`/`max-file` options
in `docker-compose.yml` — this is a platform/engine configuration concern, not
something Sentinel implements. Example:

```yaml
services:
  api:
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"
```

#### Kubernetes

Use `kubectl logs <pod>` for ad hoc inspection. For persistent
aggregation, a cluster-level log shipper (e.g., Fluent Bit or Vector)
forwarding to an aggregator (e.g., Loki or an ELK stack) is the
operator's responsibility — Sentinel does not bundle or require any
specific shipper.

#### Process-role identification

Per `docs/features/platform/logging.md`, log records do not carry a
process-role field of their own. Which of the 5 runtime roles (`api`,
`celery-worker`, `git-worker`, `beat`, `ibs-consumer`) produced a given
line is identified via platform-provided metadata: Kubernetes pod/
container labels, or the Docker Compose service name
(`com.docker.compose.service`, attached automatically by the Compose
engine). Configuring the log collector to attach and propagate this
metadata when shipping logs to the aggregator is the operator's
responsibility.

#### `LOG_LEVEL=DEBUG` risk in production

Setting `LOG_LEVEL=DEBUG` causes third-party loggers (notably
`sqlalchemy.engine` and `httpx`) to emit sensitive data — SQL
statements with bound parameters, full request URLs that may embed
tokens. See `docs/features/platform/logging.md` (Secrets and PII
Discipline) for the full policy. Operators should use
`LOG_LEVEL=DEBUG` in production only for time-bounded diagnostics and
revert promptly.

### Image Vulnerability Monitoring

A weekly scheduled workflow (`.github/workflows/image-scan.yml`) scans
the published `ghcr.io/<repo>:latest` backend image for OS-level
vulnerabilities using Trivy. It also supports manual dispatch for
on-demand checks between scheduled runs.

**Why the OS layer needs its own visibility.** `pip-audit` (see
Pipeline Chain above) gates Python dependencies on every merge, but the
image is Debian-based (`python:3.14-slim`) and the OS package layer is
not covered by any dependency scanner. Renovate proposes PRs refreshing
the `PYTHON_BASE_DIGEST` `ARG` (see Container Build Conventions, Base
image pinning) when a new base image digest is published, but that is
a forward-looking freshness mechanism — it does not scan the image
version already published to `ghcr.io` for currently known
vulnerabilities. Trivy's weekly scan is the mechanism that detects
those vulnerabilities in the layer already shipped.

**Deliberately non-blocking.** This scan never fails the workflow run
and is not part of the publish path (`build-images.yml` is untouched).
Many Debian OS package CVEs are "will not fix" upstream, and even
fixable ones require a rebuild of the base image — a remediation the
project does not control on demand. Blocking image publication on a
layer with no available immediate remediation would stall the release
pipeline without a corresponding way to resolve it.

**Fixable/unfixable split.** Each run produces two Trivy outputs:

- A **fixable HIGH/CRITICAL** result — vulnerabilities with a known
  upstream fix available. This result drives issue creation/update
  (see below).
- A **complete report** — every finding regardless of fix
  availability, uploaded as a workflow artifact for awareness only.

**Delivery.** A fixable finding opens a new GitHub issue labeled
`security` (the label already exists in the repository), or updates
the existing open one if a prior run already opened it — the workflow
never creates a duplicate issue for the same ongoing condition.

**Remediation path.** A fixable finding is usually resolved by merging
the latest open Renovate PR that refreshes `PYTHON_BASE_DIGEST` in
`backend/Dockerfile` (see Container Build Conventions, Base image
pinning) — Renovate proposes this PR automatically whenever the
upstream digest for the current `python:3.14-slim` tag changes, which
in practice is often the same digest that resolves the finding. If no
pending Renovate PR resolves the specific finding (e.g. the upstream
fix has not yet propagated to a new digest), a maintainer resolves the
current digest manually (e.g. `docker buildx imagetools inspect
python:3.14-slim` or an equivalent registry query) and opens a PR
directly.

### Python Forward-Compatibility Check

A weekly scheduled workflow
(`.github/workflows/python-forward-compat.yml`) runs the backend test
suite against the **next** Python minor version — one above the
current `backend/.python-version` target — using `uv python install`
to fetch the interpreter (including the latest available pre-release
build, if that is the newest published build for that minor) and `uv
sync` / `uv run` with a `--python` override. It also supports manual
dispatch for on-demand checks between scheduled runs.

**Why this exists.** Python runtime bumps follow the Version Bump
Checklist in `docs/conventions.md` (Runtime Version), which is a
manual, reactive procedure: incompatibilities in the interpreter or in
a dependency (particularly the Celery stack and packages with C/Rust
extensions) only surface when someone actually executes the bump. This
workflow turns that into an early-warning signal, surfacing breakage
weeks or months before the bump PR is opened.

**Deliberately non-blocking.** A compatibility failure makes the workflow
fail so its native Actions status and README badge reflect the test result,
but the workflow is not part of the publish path (`build-images.yml` is
untouched) and is never a required status check. The next Python minor
version is frequently a pre-release during most of its development cycle,
so a red result is an early-warning signal rather than a merge, release, or
publication gate.

**Availability guard.** Right after a Runtime Version bump, the next
minor may have no published build at all yet (not even an alpha). The
workflow checks this first via `uv python list <next> --only-downloads`
before attempting anything else. If no build is available, the run
exits successfully with an informational `::notice::` — no test is
attempted. This avoids a false-positive
failure signal for a condition that carries no compatibility
information.

**Best-effort resolution.** Unlike the reproducible `backend-test` job
in `ci.yml` (which uses `uv sync --locked` against the committed
lockfile), this workflow runs `uv sync` without `--locked` — it
intentionally allows dependency resolution to float against the new
interpreter, since the goal is to detect whether the current
dependency set *can* resolve and pass on the next version, not to
reproduce a pinned environment.

**Delivery.** Once a build is available, a failure during interpreter
installation, dependency resolution, or the test run fails the workflow.
The native Actions status drives the README badge, while the workflow logs
provide the tested version and failure details. The workflow does not create
or update tracking issues.

See `docs/conventions.md` (Version Bump Checklist) for the manual
upgrade procedure this check complements.

### Troubleshooting

Log messages referenced below appear as structured `event` fields in
the JSON/console log output — see `docs/features/platform/logging.md`
for the record schema.

#### SSO Login Fails

1. Check that `SSO_REDIRECT_URI` matches exactly one of the URIs
   registered in the IdP client configuration
2. Check that `id.suse.com` is reachable from the Sentinel backend
   (network/firewall)
3. Check logs for `"SSO token exchange failed"` warnings — indicates
   the IdP rejected the authorization code
4. Check logs for `"SSO callback: expected claim ... not found"` — the
   configured `SSO_USER_CLAIM` does not exist in the ID token
5. Verify the user exists in the Sentinel database with a matching
   `username` and `external_id IS NOT NULL` (the user must be provisioned via external identity provider first — see `identity-provisioning.md`)

#### Celery Tasks Not Running

1. Verify Redis is reachable at `CELERY_BROKER_URL`
2. Check that Celery Beat is running (scheduler)
3. Check that at least one Celery worker is running
4. Check worker logs for task exceptions
5. Check Beat logs for the reconciliation summary message ("Beat
   schedule reconciliation complete: ..."). If absent, reconciliation
   failed — check for PostgreSQL connectivity errors above it
6. If Beat exits repeatedly with "cannot read FetcherConfig from
   PostgreSQL", ensure the database is reachable before Beat can start
   successfully (Beat fails fast when PostgreSQL is unavailable at
   startup)
