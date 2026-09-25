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
ARG PYTHON_BASE_DIGEST=sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

# Stage 1: Install dependencies and build the project (non-editable)
FROM python:${PYTHON_VERSION}-slim@${PYTHON_BASE_DIGEST} AS builder

# Pin the uv version used to build this image (keep in sync with the
# `version:` input of astral-sh/setup-uv in .github/workflows/ci.yml)
COPY --from=ghcr.io/astral-sh/uv:0.12.19 /uv /bin/uv

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
COPY app/ app/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

# Stage 2: Runtime
FROM python:${PYTHON_VERSION}-slim@${PYTHON_BASE_DIGEST} AS runtime

WORKDIR /app

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
#    verify paths without an explicit context — e.g., a future git
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

# Create non-root user
RUN useradd --create-home --no-log-init appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
