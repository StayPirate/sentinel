"""Unit tests for `build_system_process_env` — the pure function behind
the `system_process_env` fixture in `conftest.py`.

Verifies the subprocess environment isolation contract from
`docs/features/platform/testing-strategy.md` (Registration Boundary)
without spawning any process: a developer's shell-exported application
configuration (or `backend/.env` file content it stands in for) must
never reach the environment handed to a spawned worker/Beat process —
only a minimal OS-level allowlist and the function's own explicit
values may.

These tests carry no `@pytest.mark.system` marker and spawn no
subprocess, so they run as part of the ordinary default suite.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.system.conftest import _INHERITED_OS_ENV_KEYS, build_system_process_env

_DEFAULT_KWARGS: dict[str, str] = {
    "database_url": "postgresql+asyncpg://test-user:test-pass@localhost/test-db",
    "redis_url": "redis://localhost:6379/5",
    "jwt_secret_key": "a" * 32,
}

#: Keys `build_system_process_env` always sets explicitly, regardless
#: of the ambient OS environment — see the function's own docstring.
_EXPLICIT_KEYS = frozenset(
    {
        "HOME",
        "PYTHONPATH",
        "DATABASE_URL",
        "REDIS_URL",
        "CELERY_BROKER_URL",
        "JWT_SECRET_KEY",
    }
)


def _build_env(tmp_path: Path) -> dict[str, str]:
    return build_system_process_env(home_dir=tmp_path, **_DEFAULT_KWARGS)


@pytest.mark.unit
class TestBuildSystemProcessEnv:
    def test_ambient_application_config_is_never_inherited(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A developer's shell-exported application configuration must
        not reach the built environment — not even as an empty value:
        the key itself must be absent, since it is not part of the
        explicit key set this function produces."""
        monkeypatch.setenv("IBS_PASSWORD", "canary-real-password-do-not-leak")
        monkeypatch.setenv("NVD_API_KEY", "canary-nvd-key-do-not-leak")
        monkeypatch.setenv("GITHUB_TOKEN", "canary-github-token-do-not-leak")
        monkeypatch.setenv(
            "DATABASE_URL", "postgresql+asyncpg://canary/should-not-leak"
        )
        monkeypatch.setenv(
            "JWT_SECRET_KEY", "canary-jwt-secret-do-not-leak-313233343536"
        )

        env = _build_env(tmp_path)

        assert "IBS_PASSWORD" not in env
        assert "NVD_API_KEY" not in env
        assert "GITHUB_TOKEN" not in env
        assert env["DATABASE_URL"] == _DEFAULT_KWARGS["database_url"]
        assert env["JWT_SECRET_KEY"] == _DEFAULT_KWARGS["jwt_secret_key"]
        for value in env.values():
            assert "canary" not in value

    def test_only_allowlisted_os_keys_can_pass_through(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A non-application, non-allowlisted ambient variable must not
        leak into the built environment either."""
        monkeypatch.setenv("SOME_UNRELATED_SHELL_VARIABLE", "canary-unrelated-value")

        env = _build_env(tmp_path)

        assert "SOME_UNRELATED_SHELL_VARIABLE" not in env
        for key in env:
            assert key in _INHERITED_OS_ENV_KEYS or key in _EXPLICIT_KEYS

    def test_env_contains_exactly_the_expected_keys(self, tmp_path: Path) -> None:
        """The built environment contains only the OS-allowlisted keys
        actually present in the ambient environment plus the fixed
        explicit key set — nothing else, and nothing missing."""
        env = _build_env(tmp_path)

        expected = {
            key for key in _INHERITED_OS_ENV_KEYS if key in os.environ
        } | _EXPLICIT_KEYS
        assert set(env) == expected

    def test_pythonpath_points_at_backend_directory(self, tmp_path: Path) -> None:
        env = _build_env(tmp_path)

        assert env["PYTHONPATH"].endswith("backend")

    def test_home_set_to_provided_directory(self, tmp_path: Path) -> None:
        """`HOME` is the caller-supplied temporary directory, never the
        real developer home — so the subprocess never reads dotfiles
        from it."""
        env = _build_env(tmp_path)

        assert env["HOME"] == str(tmp_path)

    def test_redis_url_populates_both_redis_and_broker_url(
        self, tmp_path: Path
    ) -> None:
        env = _build_env(tmp_path)

        assert env["REDIS_URL"] == _DEFAULT_KWARGS["redis_url"]
        assert env["CELERY_BROKER_URL"] == _DEFAULT_KWARGS["redis_url"]
