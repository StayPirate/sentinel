# syntax=docker/dockerfile:1

# Python version — must match backend/.python-version (CI drift-check enforces this)
ARG PYTHON_VERSION=3.14

# Digest pin for python:${PYTHON_VERSION}-slim (see docs/deployment.md,
# Container Build Conventions → Base image pinning). Renovate's
# dockerfile manager resolves this ARG-templated FROM line natively and
# proposes PRs bumping PYTHON_BASE_DIGEST when a new digest for the
# current tag is published. PYTHON_VERSION itself is bumped manually
# only — see docs/conventions.md, Runtime Version (Version Bump
# Checklist) — and is excluded from Renovate's automated updates by a
# packageRule in renovate.jsonc.
ARG PYTHON_BASE_DIGEST=sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

# Stage 1: Install dependencies and build the project (non-editable)
FROM python:${PYTHON_VERSION}-slim@${PYTHON_BASE_DIGEST} AS builder

# Pin the uv version used to build this image (keep in sync with the
# `version:` input of astral-sh/setup-uv in .github/workflows/ci.yml).
# The tag documents the version; the digest guarantees immutability (see
# docs/deployment.md, Container Build Conventions → uv image pinning).
# The binary also provides the uv_build backend that builds the project;
# the uv_build range in pyproject.toml must stay compatible with it.
# Renovate updates tag, digest, and that range together.
COPY --from=ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 /uv /bin/uv

# Use the Python interpreter already present in this base image instead
# of letting uv download its own managed interpreter
ENV UV_PYTHON_DOWNLOADS=0 \
    UV_LINK_MODE=copy

WORKDIR /app

# Install dependencies only, in their own layer. This layer is
# invalidated only when pyproject.toml or uv.lock change — not on every
# application code change — which keeps rebuilds fast.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev --no-editable

# Copy application source and install the project itself (non-editable).
# --offline: every dependency is already installed, and the project is
# built by the uv_build backend bundled in the pinned uv binary. A
# configuration that would download a build backend instead (for example
# a uv_build range incompatible with the pinned uv) fails the build.
COPY app/ app/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --offline --no-dev --no-editable

# Stage 2: Runtime
FROM python:${PYTHON_VERSION}-slim@${PYTHON_BASE_DIGEST} AS runtime

WORKDIR /app

# The Git worker role runs the Git-based CVE fetchers through the system
# git binary (minimum 2.30 — see
# docs/features/platform/git-fetcher-infrastructure.md, Runtime
# Dependencies); the slim base image has none. The single image serves every
# role (docs/deployment.md, Container Build Conventions), so git is
# installed for all of them. Debian's package is not version-pinned: the
# image gate asserts the minimum version and the scheduled image scan
# covers its vulnerabilities.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Install the SUSE internal CA certificate at two layers (see
# docs/features/platform/networking.md, Trust Store Layering):
#
# 1. Repository-relative path (this COPY): read by build_tls_context()
#    via SUSE_CA_CERT_PATH. Required regardless of the system-wide
#    install below because httpx does NOT read the system trust
#    store — its default verify context is built from the certifi
#    bundle, which does not include the SUSE CA. This is the layer all
#    Sentinel-controlled Python code relies on, and the only layer
#    available outside containers (local development).
# 2. System-wide trust store (COPY + update-ca-certificates below): the
#    trust source for consumers that resolve TLS via OpenSSL's default
#    verify paths without an explicit context — e.g., the git
#    subprocess cloning from a SUSE-internal host. Baked at build time;
#    rotating the CA at this layer requires an image rebuild.
COPY certs/ certs/
COPY certs/SUSE_Trust_Root.crt /usr/local/share/ca-certificates/SUSE_Trust_Root.crt
RUN update-ca-certificates

# Copy the synced virtual environment (dependencies + project code,
# installed non-editable) from the builder stage. uv itself is not
# copied — it is not needed at runtime.
COPY --from=builder /app/.venv /app/.venv

# Copy application code needed at runtime (Alembic migrations run from
# this same image via a one-shot job — see docs/deployment.md,
# Database Migrations)
COPY app/ app/
COPY alembic/ alembic/
COPY alembic.ini .

# Activate the virtual environment for all subsequent commands
ENV PATH="/app/.venv/bin:$PATH"

# Create the non-root user with a fixed UID and GID, and the default
# GIT_CLONE_BASE_DIR it owns: a fresh named volume mounted there inherits
# this ownership, so the Git worker can clone into it (docs/deployment.md,
# Git Worker Volume). USER is numeric so that an orchestrator can verify
# that the image runs as non-root without a user override, for example
# Kubernetes runAsNonRoot. The UID and GID are part of the image contract
# (docs/deployment.md, Container Build Conventions).
RUN groupadd --gid 1000 appuser \
    && useradd --create-home --no-log-init --uid 1000 --gid 1000 appuser \
    && install --directory --owner=appuser --group=appuser --mode=0750 \
    /var/lib/sentinel/git
USER 1000:1000

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
