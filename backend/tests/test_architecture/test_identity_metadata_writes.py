"""Structural test: only the documented owners write the operational identity
metadata `User.last_login_at`, `ApiKey.last_used_at`, and `User.synced_at`.

See `docs/features/identity/user-service.md` (Operational metadata
exclusions: `last_login_at` is written by the authentication
session-creation workflow, `last_used_at` by
`api_key_service.update_last_used_at()`, and `synced_at` by the external
provisioning synchronization workflow, initially through `create_user()`
and afterwards through `update_user()`) and
`docs/features/platform/testing-strategy.md` (User Lifecycle and
Management: "only their documented owners may write them").

Every module in `backend/app/` is enumerated via AST, and each write is
recorded as `(module, enclosing function, field)`. A write is:

- an attribute target named after a field, in an assignment, an augmented
  or annotated assignment, or a `del`;
- a keyword named after a field on a call to `User(...)`, `ApiKey(...)`,
  `.values(...)`, `.ordered_values(...)`, or `update_user(...)`;
- a dictionary key that is the field name as a string or an attribute
  named after the field, as in `.values({ApiKey.last_used_at: t})`;
- `setattr(obj, "<field>", value)` with a constant name; and
- any call to `update_last_used_at()`, recorded as a `last_used_at` write
  of its caller.

The recorded set must equal the reviewed inventory below. Reads, column
expressions, and the model column definitions (annotated assignments to a
bare name) are not writes.

Blind spots: a field name held in a variable (`setattr(obj, name, value)`),
a `**` expansion (`User(**fields)`, `.values(**fields)`), a tuple pair of
`.ordered_values()`, a callee bound to another name, and SQL text are not
detected.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"

_FIELDS: Final = frozenset({"last_login_at", "last_used_at", "synced_at"})
_KEYWORD_CALLEES: Final = frozenset(
    {"User", "ApiKey", "values", "ordered_values", "update_user"}
)
_TOUCH: Final = "update_last_used_at"

ALLOWED_WRITES: Final = {
    ("app/services/session_service.py", "create_session", "last_login_at"),
    ("app/services/api_key_service.py", "update_last_used_at", "last_used_at"),
    ("app/services/user_service.py", "create_user", "synced_at"),
    ("app/services/user_service.py", "update_user", "synced_at"),
    # The debounced authentication touch calls `update_last_used_at()`.
    ("app/api/dependencies.py", "LastUsedDebouncer.touch", "last_used_at"),
}
"""(module, enclosing function, field) of every permitted write."""


def _assign_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore[attr-defined]


def _enclosing_qualname(node: ast.AST) -> str | None:
    """The nearest enclosing function, as `"ClassName.method"` for a method
    and a bare name otherwise, or `None` at module level. Requires
    `_assign_parents()`."""
    current: ast.AST | None = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
            enclosing = getattr(current, "parent", None)
            if isinstance(enclosing, ast.ClassDef):
                return f"{enclosing.name}.{current.name}"
            return current.name
        current = getattr(current, "parent", None)
    return None


def _callee_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _key_field(key: ast.expr | None) -> str | None:
    if (
        isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and key.value in _FIELDS
    ):
        return key.value
    if isinstance(key, ast.Attribute) and key.attr in _FIELDS:
        return key.attr
    return None


def _written_fields(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Attribute):
        if node.attr in _FIELDS and isinstance(node.ctx, ast.Store | ast.Del):
            return [node.attr]
        return []
    if isinstance(node, ast.Dict):
        return [field for key in node.keys if (field := _key_field(key))]
    if not isinstance(node, ast.Call):
        return []
    callee = _callee_name(node.func)
    if callee == _TOUCH:
        return ["last_used_at"]
    if callee == "setattr" and len(node.args) >= 2:
        name = node.args[1]
        if (
            isinstance(name, ast.Constant)
            and isinstance(name.value, str)
            and name.value in _FIELDS
        ):
            return [name.value]
        return []
    if callee in _KEYWORD_CALLEES:
        return [k.arg for k in node.keywords if k.arg is not None and k.arg in _FIELDS]
    return []


def _metadata_writes(source: str) -> list[tuple[int, str | None, str]]:
    """(line, enclosing function, field) of every metadata write."""
    tree = ast.parse(source)
    _assign_parents(tree)
    return sorted(
        (node.lineno, _enclosing_qualname(node), field)
        for node in ast.walk(tree)
        if isinstance(node, ast.expr)
        for field in _written_fields(node)
    )


def _app_sources() -> dict[str, str]:
    return {
        path.relative_to(BACKEND_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(APP_ROOT.rglob("*.py"))
    }


@pytest.mark.unit
class TestMetadataWriteDetector:
    """The detector on synthetic sources, independent of `app/`."""

    @pytest.mark.parametrize(
        ("source", "field"),
        [
            ("user.last_login_at = t", "last_login_at"),
            ("key.last_used_at += delta", "last_used_at"),
            ("user.synced_at: datetime = t", "synced_at"),
            ("del user.synced_at", "synced_at"),
            ("a = user.synced_at = t", "synced_at"),
            ("update(User).values(last_login_at=t)", "last_login_at"),
            ("insert(ApiKey).values({'last_used_at': t})", "last_used_at"),
            ("stmt.values({ApiKey.last_used_at: t})", "last_used_at"),
            ("stmt.ordered_values(synced_at=t)", "synced_at"),
            ("User(synced_at=t)", "synced_at"),
            ("models.ApiKey(last_used_at=t)", "last_used_at"),
            ("setattr(u, 'synced_at', t)", "synced_at"),
            ("update_user(db, i, acting_user_id=None, synced_at=t)", "synced_at"),
            ("update_last_used_at(db, k, t)", "last_used_at"),
            ("api_key_service.update_last_used_at(db, k, t)", "last_used_at"),
        ],
    )
    def test_metadata_write_any_form_is_detected(self, source: str, field: str) -> None:
        assert [written for _, _, written in _metadata_writes(source)] == [field]

    @pytest.mark.parametrize(
        "source",
        [
            "ApiKeyData(last_used_at=k.last_used_at)",
            "x = u.last_login_at",
            "ApiKey.last_used_at.is_(None)",
            "nullslast(ApiKey.last_used_at.asc())",
            "class User(Base):\n"
            "    synced_at: Mapped[datetime | None] = mapped_column()",
            "changed_fields.append('synced_at')",
            "LAST_USED_AT = 'last_used_at'",
            "update(User).values(active=False)",
            "user.updated_at = t",
            "setattr(u, 'active', False)",
            "{'name': n}",
        ],
    )
    def test_non_write_source_is_not_detected(self, source: str) -> None:
        assert _metadata_writes(source) == []

    def test_write_reports_its_enclosing_function(self) -> None:
        source = (
            "class LastUsedDebouncer:\n"
            "    async def touch(self, db, k, t):\n"
            "        await update_last_used_at(db, k, t)\n"
            "\n"
            "async def create_session(db, user):\n"
            "    user.last_login_at = t\n"
            "\n"
            "user.synced_at = t\n"
        )

        assert _metadata_writes(source) == [
            (3, "LastUsedDebouncer.touch", "last_used_at"),
            (6, "create_session", "last_login_at"),
            (8, None, "synced_at"),
        ]


@pytest.mark.unit
class TestIdentityMetadataWriteOwners:
    def test_only_the_documented_owners_write_identity_metadata(self) -> None:
        found = {
            (module, function, field)
            for module, source in _app_sources().items()
            for _, function, field in _metadata_writes(source)
        }

        assert found == ALLOWED_WRITES, (
            "operational identity metadata written outside its documented owner "
            "(docs/features/identity/user-service.md, Operational metadata "
            "exclusions)"
        )
