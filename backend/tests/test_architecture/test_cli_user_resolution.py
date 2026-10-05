"""Structural tests for CLI user resolution and the `--full-name` bound.

docs/conventions.md (CLI Conventions, Command Design — Username
normalization and resolution): every CLI command resolves `--username`
exclusively by exact match on the normalized username, never through the
API's UUID-or-username resolution (`docs/api-spec.md`, User Identifier
Resolution). That resolution is reachable only through
`user_service.get_user()`, `resolve_user_identifier()`, and the
composable `user_identifier_condition()`; a CLI module that references any
of them — by import, attribute access, or bare name — reintroduces the
defect fixed in issue #815, so it fails here before review.

The `--full-name` bound of `manage-user create`/`update`
(docs/features/identity/user-management.md) mirrors the `User.full_name`
column length and the API profile schemas' `max_length`; the alignment
test keeps the three values from drifting apart.

See docs/features/platform/testing-strategy.md (Structural Tests).
"""

from __future__ import annotations

import ast
from pathlib import Path

import annotated_types
import pytest
from pydantic import BaseModel
from sqlalchemy import String

import app.cli.manage_user as manage_user_module
from app.models.user import User
from app.schemas.user import AdminUserCreateRequest, AdminUserUpdateRequest
from tests.support.module_imports import APP_ROOT

_CLI_ROOT = APP_ROOT / "cli"
_API_IDENTIFIER_RESOLUTION = frozenset(
    {"get_user", "resolve_user_identifier", "user_identifier_condition"}
)


def _api_resolution_references(source: str) -> list[tuple[int, str]]:
    """`(line, name)` for every reference to an API identifier-resolution
    function: an imported name, an attribute access, or a bare name."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            found.extend(
                (node.lineno, alias.name)
                for alias in node.names
                if alias.name in _API_IDENTIFIER_RESOLUTION
            )
        elif isinstance(node, ast.Attribute):
            if node.attr in _API_IDENTIFIER_RESOLUTION:
                found.append((node.lineno, node.attr))
        elif isinstance(node, ast.Name) and node.id in _API_IDENTIFIER_RESOLUTION:
            found.append((node.lineno, node.id))
    return found


def _cli_modules() -> list[Path]:
    return sorted(_CLI_ROOT.rglob("*.py"))


@pytest.mark.unit
class TestCliUsesUsernameOnlyResolution:
    def test_cli_package_is_discovered(self) -> None:
        names = {path.name for path in _cli_modules()}

        assert {"manage_user.py", "api_key.py"} <= names

    @pytest.mark.parametrize(
        "path", _cli_modules(), ids=lambda path: str(path.relative_to(APP_ROOT))
    )
    def test_cli_module_never_references_api_identifier_resolution(
        self, path: Path
    ) -> None:
        references = _api_resolution_references(path.read_text(encoding="utf-8"))

        assert references == [], (
            f"{path.relative_to(APP_ROOT)} references the API UUID-or-username "
            f"resolution at {references}; CLI commands resolve --username "
            "through user_service.get_user_by_username() (docs/conventions.md, "
            "Command Design — Username normalization and resolution)"
        )

    @pytest.mark.parametrize(
        "source",
        [
            "from app.services.user_service import get_user\n",
            "from app.services.user_service import resolve_user_identifier as r\n",
            "from app.services.user_identifier import user_identifier_condition\n",
            "async def f(db, u):\n    return await user_service.get_user(db, u)\n",
            "def f(u):\n    return get_user(u)\n",
        ],
    )
    def test_detector_reports_each_reference_form(self, source: str) -> None:
        assert _api_resolution_references(source) != []

    def test_detector_ignores_the_username_only_read(self) -> None:
        source = (
            "async def f(db, u):\n"
            "    return await user_service.get_user_by_username(db, u)\n"
        )

        assert _api_resolution_references(source) == []


def _schema_full_name_max_length(model: type[BaseModel]) -> int | None:
    metadata = model.model_fields["full_name"].metadata
    return next(
        (m.max_length for m in metadata if isinstance(m, annotated_types.MaxLen)),
        None,
    )


@pytest.mark.unit
def test_cli_full_name_bound_matches_column_and_api_schemas() -> None:
    column_type = User.__table__.c.full_name.type
    assert isinstance(column_type, String)
    bound = column_type.length

    assert bound == manage_user_module._FULL_NAME_MAX_LENGTH
    assert bound == _schema_full_name_max_length(AdminUserCreateRequest)
    assert bound == _schema_full_name_max_length(AdminUserUpdateRequest)
