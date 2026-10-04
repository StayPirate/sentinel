"""End-to-end tests for the app-wide U+0000 rejection of consumer-supplied
request input.

See `docs/api-spec.md` (NUL Characters in Request Input) for the contract
under test. Each case uses a representative real endpoint whose string
input would otherwise reach PostgreSQL, where U+0000 fails with SQLSTATE
22021 instead of the documented `422 VALIDATION_ERROR`. The synthetic-app
matrix lives in `tests/test_core/test_request_nul.py`.
"""

from __future__ import annotations

import pytest
import redis.asyncio as redis_asyncio
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User

_NUL_ERROR = {"msg": "Value error, must not contain U+0000", "type": "value_error"}


def _assert_nul_rejection(response_json: object, loc: list[object]) -> None:
    assert response_json == {
        "code": "VALIDATION_ERROR",
        "detail": "Request validation failed",
        "errors": [{"loc": loc, **_NUL_ERROR}],
    }


@pytest.mark.e2e
class TestRequestNulRejection:
    async def test_login_username_is_rejected_before_lockout_accounting(
        self, client: AsyncClient, redis_client: redis_asyncio.Redis
    ) -> None:
        """A public, unauthenticated body field: rejected with 422 before
        the endpoint runs, so no lockout counter is created."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "fictional\x00user", "password": "irrelevant"},
        )

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["body", "username"])
        assert await redis_client.keys("login_attempts:*") == []

    async def test_body_free_text_is_rejected_without_a_write(
        self, admin_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        response = await admin_client.post(
            "/api/v1/admin/users",
            json={
                "username": "nulprobeuser",
                "email": "nulprobeuser@example.com",
                "full_name": "Fictional\x00Name",
                "password": "a-fictional-password-value",
            },
        )

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["body", "full_name"])
        count = await db_session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.username == "nulprobeuser")
        )
        assert count == 0

    async def test_query_parameter_is_rejected(self, client: AsyncClient) -> None:
        """A public, anonymous query parameter that feeds a search."""
        response = await client.get("/api/v1/users", params={"search": "fic\x00tional"})

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["query", "search"])

    async def test_percent_encoded_path_parameter_is_rejected(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get("/api/v1/users/fictional%00user")

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["path", "user"])

    async def test_rejection_precedes_authentication(self, client: AsyncClient) -> None:
        """The check is syntactic and runs before the route's own
        dependencies: an unauthenticated request receives 422, not 401."""
        response = await client.get(
            "/api/v1/admin/api-keys", params={"owner": "fic\x00tional"}
        )

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["query", "owner"])

    async def test_rejection_precedes_ticket_scoped_not_found(
        self, authenticated_client: AsyncClient
    ) -> None:
        """A Ticket locator containing U+0000 is rejected with 422, not
        with the scoped `404 TICKET_NOT_FOUND` of other malformed
        locators."""
        response = await authenticated_client.get("/api/v1/tickets/SNTL-1%00")

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["path", "ticket_id"])
