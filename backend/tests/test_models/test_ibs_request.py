"""Integration tests for the IBSRequest model
(backend/app/models/ibs_request.py).

See docs/data-model.md (IBSRequest, IBSRequestState Enum, IBS Request
Evidence Retention) and docs/features/packages/ibs-submission-tracking.md
(Request States, Data Model > IBSRequest, Retention and Deletion). Only the
persistence contract is covered here; request discovery, point-fetch,
supersession traversal, upsert conditions, and reconciliation are IBS
submission tracking behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint, insert, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import IBSRequestState
from app.models.ibs_request import IBSRequest

IBSRequestFactory = Callable[..., Awaitable[IBSRequest]]

_DOCUMENTED_COLUMNS = {
    "id",
    "request_number",
    "state",
    "superseded_by_request_number",
    "upstream_created_at",
    "upstream_updated_at",
    "created_at",
    "updated_at",
}

_NUMBER_POSITIVE_CHECK = "chk_ibs_request_request_number_positive"
_STATE_CHECK = "chk_ibs_request_state_valid"
_SUPERSESSION_CHECK = "chk_ibs_request_supersession_coherence"
_UPSTREAM_CREATED_AT = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_UPSTREAM_UPDATED_AT = datetime(2026, 8, 31, 13, 15, tzinfo=UTC)

_NON_SUPERSEDED_STATES = [s for s in IBSRequestState if s != IBSRequestState.SUPERSEDED]


@pytest.mark.integration
class TestIBSRequestCreation:
    async def test_create_with_defaults(
        self, ibs_request_factory: IBSRequestFactory
    ) -> None:
        request = await ibs_request_factory()

        assert request.id.version == 7
        assert request.request_number > 0
        assert request.state == IBSRequestState.NEW.value
        assert request.superseded_by_request_number is None
        assert request.upstream_created_at.tzinfo is not None
        assert request.upstream_updated_at.tzinfo is not None
        assert request.created_at is not None
        assert request.updated_at is not None

    async def test_create_with_every_column(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        request = await ibs_request_factory(
            request_number=41,
            state=IBSRequestState.SUPERSEDED.value,
            superseded_by_request_number=42,
            upstream_created_at=_UPSTREAM_CREATED_AT,
            upstream_updated_at=_UPSTREAM_UPDATED_AT,
        )
        request_id = request.id
        db_session.expunge(request)

        reloaded = await db_session.get(IBSRequest, request_id)
        assert reloaded is not None
        assert reloaded.request_number == 41
        assert reloaded.state == "superseded"
        assert reloaded.superseded_by_request_number == 42
        assert reloaded.upstream_created_at == _UPSTREAM_CREATED_AT
        assert reloaded.upstream_updated_at == _UPSTREAM_UPDATED_AT

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        database must supply `id` and the local timestamps. `state` has no
        default: it always carries the exact upstream state."""
        result = await db_session.execute(
            text(
                "INSERT INTO ibs_request "
                "(request_number, state, upstream_created_at, upstream_updated_at) "
                "VALUES (51, 'review', :created, :updated) "
                "RETURNING id, superseded_by_request_number, created_at, updated_at"
            ),
            {"created": _UPSTREAM_CREATED_AT, "updated": _UPSTREAM_UPDATED_AT},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.superseded_by_request_number is None
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at

    async def test_upstream_timestamps_normalized_to_utc(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        """TIMESTAMPTZ stores the instant; an offset value reads back as the
        same instant (docs/conventions.md, Timestamps & Timezones)."""
        offset = timezone(timedelta(hours=2))
        created = datetime(2026, 8, 30, 14, 0, tzinfo=offset)
        request = await ibs_request_factory(upstream_created_at=created)
        await db_session.refresh(request)
        assert request.upstream_created_at == created
        assert request.upstream_created_at.utcoffset() == timedelta(0)


@pytest.mark.unit
class TestIBSRequestSchemaShape:
    """Exactly the documented columns and constraints (#633 decision A2):
    no author, actor, comment, description, event payload, or raw response
    column; UNIQUE `request_number`; the three documented CHECKs; and no
    standalone index."""

    def test_columns_match_documented_set(self) -> None:
        assert set(IBSRequest.__table__.columns.keys()) == _DOCUMENTED_COLUMNS

    def test_unique_constraint(self) -> None:
        table = IBSRequest.metadata.tables["ibs_request"]
        uniques = [
            tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        ]
        assert uniques == [("request_number",)]

    def test_exact_check_constraint_set(self) -> None:
        table = IBSRequest.metadata.tables["ibs_request"]
        checks = {c.name for c in table.constraints if isinstance(c, CheckConstraint)}
        assert checks == {_NUMBER_POSITIVE_CHECK, _STATE_CHECK, _SUPERSESSION_CHECK}

    def test_no_standalone_index(self) -> None:
        """The UNIQUE `request_number` constraint covers the public request
        number lookup."""
        table = IBSRequest.metadata.tables["ibs_request"]
        assert table.indexes == set()

    def test_state_has_no_default(self) -> None:
        column = IBSRequest.__table__.c.state
        assert column.default is None
        assert column.server_default is None


@pytest.mark.integration
class TestIBSRequestNumber:
    async def test_duplicate_request_number_rejected(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        await ibs_request_factory(request_number=61)
        db_session.add(
            IBSRequest(
                request_number=61,
                state="new",
                upstream_created_at=_UPSTREAM_CREATED_AT,
                upstream_updated_at=_UPSTREAM_UPDATED_AT,
            )
        )
        with pytest.raises(IntegrityError, match="ibs_request_request_number_key"):
            await db_session.flush()

    async def test_duplicate_request_number_rejected_for_deleted_request(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        """An upstream `deleted` request is retained and still owns its
        number."""
        await ibs_request_factory(request_number=62, state="deleted")
        db_session.add(
            IBSRequest(
                request_number=62,
                state="new",
                upstream_created_at=_UPSTREAM_CREATED_AT,
                upstream_updated_at=_UPSTREAM_UPDATED_AT,
            )
        )
        with pytest.raises(IntegrityError, match="ibs_request_request_number_key"):
            await db_session.flush()

    async def test_smallest_positive_number_accepted(
        self, ibs_request_factory: IBSRequestFactory
    ) -> None:
        request = await ibs_request_factory(request_number=1)
        assert request.request_number == 1

    @pytest.mark.parametrize("value", [0, -1])
    async def test_non_positive_number_rejected(
        self, ibs_request_factory: IBSRequestFactory, value: int
    ) -> None:
        with pytest.raises(IntegrityError, match=_NUMBER_POSITIVE_CHECK):
            await ibs_request_factory(request_number=value)


@pytest.mark.integration
class TestIBSRequestNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        [
            "request_number",
            "state",
            "upstream_created_at",
            "upstream_updated_at",
            "created_at",
            "updated_at",
        ],
    )
    async def test_explicit_null_rejected(
        self, db_session: AsyncSession, column: str
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        values: dict[str, object] = {
            "request_number": 71,
            "state": "new",
            "upstream_created_at": _UPSTREAM_CREATED_AT,
            "upstream_updated_at": _UPSTREAM_UPDATED_AT,
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(IBSRequest).values(values))


@pytest.mark.integration
class TestIBSRequestStateCheckConstraint:
    """`state` is Category A, protected by `chk_ibs_request_state_valid`
    (docs/data-model.md, IBSRequestState Enum)."""

    @pytest.mark.parametrize("state", list(IBSRequestState), ids=lambda s: s.name)
    async def test_every_member_accepted(
        self,
        db_session: AsyncSession,
        ibs_request_factory: IBSRequestFactory,
        state: IBSRequestState,
    ) -> None:
        request = await ibs_request_factory(state=state.value)
        await db_session.refresh(request)
        assert request.state == state.value

    @pytest.mark.parametrize(
        "value", ["New", "NEW", "open", "closed", "superceded", "unknown", ""]
    )
    async def test_invalid_value_rejected_on_insert(
        self, ibs_request_factory: IBSRequestFactory, value: str
    ) -> None:
        with pytest.raises(IntegrityError, match=_STATE_CHECK):
            await ibs_request_factory(state=value)

    async def test_invalid_value_rejected_on_update(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        request = await ibs_request_factory()
        with pytest.raises(IntegrityError, match=_STATE_CHECK):
            await db_session.execute(
                text("UPDATE ibs_request SET state = 'open' WHERE id = :id"),
                {"id": request.id},
            )

    @pytest.mark.parametrize(
        ("previous", "current"),
        [("declined", "new"), ("declined", "review"), ("accepted", "deleted")],
    )
    async def test_any_known_state_may_replace_another(
        self,
        db_session: AsyncSession,
        ibs_request_factory: IBSRequestFactory,
        previous: str,
        current: str,
    ) -> None:
        """No local transition allowlist is enforced by the schema
        (ibs-submission-tracking.md, Request States)."""
        request = await ibs_request_factory(state=previous)
        request.state = current
        await db_session.flush()
        await db_session.refresh(request)
        assert request.state == current


@pytest.mark.integration
class TestIBSRequestSupersessionCoherence:
    """`chk_ibs_request_supersession_coherence`: a positive successor that
    differs from `request_number` is present if and only if `state` is
    `superseded` (docs/data-model.md, IBSRequest)."""

    async def test_superseded_with_valid_successor_accepted(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        request = await ibs_request_factory(
            request_number=81, state="superseded", superseded_by_request_number=80
        )
        await db_session.refresh(request)
        assert request.superseded_by_request_number == 80

    async def test_successor_need_not_be_retained(
        self, ibs_request_factory: IBSRequestFactory
    ) -> None:
        """Not an FK: the successor request need not exist locally."""
        request = await ibs_request_factory(
            request_number=82, state="superseded", superseded_by_request_number=999999
        )
        assert request.superseded_by_request_number == 999999

    async def test_superseded_without_successor_rejected(
        self, ibs_request_factory: IBSRequestFactory
    ) -> None:
        with pytest.raises(IntegrityError, match=_SUPERSESSION_CHECK):
            await ibs_request_factory(
                state="superseded", superseded_by_request_number=None
            )

    @pytest.mark.parametrize("successor", [0, -5])
    async def test_superseded_with_non_positive_successor_rejected(
        self, ibs_request_factory: IBSRequestFactory, successor: int
    ) -> None:
        with pytest.raises(IntegrityError, match=_SUPERSESSION_CHECK):
            await ibs_request_factory(
                state="superseded", superseded_by_request_number=successor
            )

    async def test_superseded_by_itself_rejected(
        self, ibs_request_factory: IBSRequestFactory
    ) -> None:
        with pytest.raises(IntegrityError, match=_SUPERSESSION_CHECK):
            await ibs_request_factory(
                request_number=83,
                state="superseded",
                superseded_by_request_number=83,
            )

    @pytest.mark.parametrize("state", _NON_SUPERSEDED_STATES, ids=lambda s: s.name)
    async def test_non_superseded_state_with_successor_rejected(
        self, ibs_request_factory: IBSRequestFactory, state: IBSRequestState
    ) -> None:
        with pytest.raises(IntegrityError, match=_SUPERSESSION_CHECK):
            await ibs_request_factory(
                state=state.value, superseded_by_request_number=90
            )

    @pytest.mark.parametrize("state", _NON_SUPERSEDED_STATES, ids=lambda s: s.name)
    async def test_non_superseded_state_without_successor_accepted(
        self, ibs_request_factory: IBSRequestFactory, state: IBSRequestState
    ) -> None:
        request = await ibs_request_factory(state=state.value)
        assert request.superseded_by_request_number is None

    async def test_leaving_superseded_without_clearing_successor_rejected(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        request = await ibs_request_factory(state="superseded")
        request.state = "review"
        with pytest.raises(IntegrityError, match=_SUPERSESSION_CHECK):
            await db_session.flush()


@pytest.mark.integration
class TestIBSRequestColumnTypes:
    async def test_state_over_documented_maximum_rejected(
        self, ibs_request_factory: IBSRequestFactory
    ) -> None:
        # asyncpg surfaces the truncation as a generic DBAPIError; the length
        # check precedes the state CHECK.
        with pytest.raises(DBAPIError, match="value too long"):
            await ibs_request_factory(state="a" * 21)

    async def test_request_number_is_a_32_bit_integer(
        self, ibs_request_factory: IBSRequestFactory
    ) -> None:
        maximum = 2**31 - 1
        request = await ibs_request_factory(request_number=maximum)
        assert request.request_number == maximum
        with pytest.raises(DBAPIError):
            await ibs_request_factory(request_number=maximum + 1)


@pytest.mark.integration
class TestIBSRequestTimestamps:
    async def test_timestamps_are_timezone_aware(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        request = await ibs_request_factory()
        await db_session.refresh(request)
        assert request.created_at.tzinfo is not None
        assert request.updated_at.tzinfo is not None
        assert request.upstream_created_at.tzinfo is not None
        assert request.upstream_updated_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        request = await ibs_request_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        request.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(request)
        assert request.updated_at == backdated

        request.state = IBSRequestState.REVIEW.value
        await db_session.flush()
        await db_session.refresh(request)

        assert request.updated_at > backdated

    async def test_created_at_and_upstream_times_unchanged_on_update(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        """Local chronology is never substituted for upstream time."""
        request = await ibs_request_factory(
            upstream_created_at=_UPSTREAM_CREATED_AT,
            upstream_updated_at=_UPSTREAM_UPDATED_AT,
        )
        backdated = datetime.now(UTC) - timedelta(days=7)
        request.created_at = backdated
        await db_session.flush()

        request.state = IBSRequestState.ACCEPTED.value
        await db_session.flush()
        await db_session.refresh(request)

        assert request.created_at == backdated
        assert request.upstream_created_at == _UPSTREAM_CREATED_AT
        assert request.upstream_updated_at == _UPSTREAM_UPDATED_AT
