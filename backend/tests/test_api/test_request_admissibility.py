"""End-to-end tests for the app-wide rejection of inadmissible characters
in consumer-supplied request input.

See `docs/api-spec.md` (Inadmissible Characters in Request Input) for the
contract under test. Each case uses a representative real endpoint whose
string input would otherwise reach PostgreSQL, where U+0000 fails with
SQLSTATE 22021 and a surrogate code point with a driver encoding error,
instead of the documented `422 VALIDATION_ERROR`. The synthetic-app matrix
lives in `tests/test_core/test_request_admissibility.py`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest
import redis.asyncio as redis_asyncio
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from tests.support.inadmissible import (
    INADMISSIBLE_CHARACTERS,
    REQUEST_INPUT_ERROR,
    SURROGATE,
    json_bytes,
)

_JSON_HEADERS = {"content-type": "application/json"}


def _assert_rejection(response_json: object, loc: list[object]) -> None:
    assert response_json == {
        "code": "VALIDATION_ERROR",
        "detail": "Request validation failed",
        "errors": [{"loc": loc, **REQUEST_INPUT_ERROR}],
    }


@pytest.mark.e2e
class TestRequestInputRejection:
    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_login_username_is_rejected_before_lockout_accounting(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        character: str,
    ) -> None:
        """A public, unauthenticated body field: rejected with 422 before
        the endpoint runs, so no lockout counter is created."""
        response = await client.post(
            "/api/v1/auth/login",
            content=json_bytes(
                {"username": f"fictional{character}user", "password": "irrelevant"}
            ),
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        _assert_rejection(response.json(), ["body", "username"])
        assert await redis_client.keys("login_attempts:*") == []

    async def test_login_surrogate_password_does_not_reveal_the_account(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        """An existing eligible user and an unknown username receive the
        same response for a surrogate in the password, and neither
        reaches lockout accounting or password verification."""
        user, _ = await local_user_factory()
        password = f"fictional-password-{SURROGATE}-value"

        responses = [
            await client.post(
                "/api/v1/auth/login",
                content=json_bytes({"username": username, "password": password}),
                headers=_JSON_HEADERS,
            )
            for username in (user.username, "fictionalunknownuser")
        ]

        for response in responses:
            assert response.status_code == 422
            _assert_rejection(response.json(), ["body", "password"])
        assert responses[0].text == responses[1].text
        assert await redis_client.keys("login_attempts:*") == []

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_body_free_text_is_rejected_without_a_write(
        self, admin_client: AsyncClient, db_session: AsyncSession, character: str
    ) -> None:
        response = await admin_client.post(
            "/api/v1/admin/users",
            content=json_bytes(
                {
                    "username": "nulprobeuser",
                    "email": "nulprobeuser@example.com",
                    "full_name": f"Fictional{character}Name",
                    "password": "a-fictional-password-value",
                }
            ),
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        _assert_rejection(response.json(), ["body", "full_name"])
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
        _assert_rejection(response.json(), ["query", "search"])

    async def test_percent_encoded_path_parameter_is_rejected(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get("/api/v1/users/fictional%00user")

        assert response.status_code == 422
        _assert_rejection(response.json(), ["path", "user"])

    async def test_rejection_precedes_authentication(self, client: AsyncClient) -> None:
        """The check is syntactic and runs before the route's own
        dependencies: an unauthenticated request receives 422, not 401."""
        response = await client.get(
            "/api/v1/admin/api-keys", params={"owner": "fic\x00tional"}
        )

        assert response.status_code == 422
        _assert_rejection(response.json(), ["query", "owner"])

    async def test_body_rejection_precedes_authentication(
        self, client: AsyncClient
    ) -> None:
        """An unauthenticated body carrying a surrogate code point receives
        422, not 401."""
        response = await client.post(
            "/api/v1/admin/users",
            content=json_bytes({"username": f"fictional{SURROGATE}"}),
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        _assert_rejection(response.json(), ["body", "username"])

    async def test_rejection_precedes_ticket_scoped_not_found(
        self, authenticated_client: AsyncClient
    ) -> None:
        """A Ticket locator containing U+0000 is rejected with 422, not
        with the scoped `404 TICKET_NOT_FOUND` of other malformed
        locators."""
        response = await authenticated_client.get("/api/v1/tickets/SNTL-1%00")

        assert response.status_code == 422
        _assert_rejection(response.json(), ["path", "ticket_id"])
