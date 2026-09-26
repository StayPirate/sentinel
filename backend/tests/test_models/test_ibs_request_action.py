"""Integration tests for the IBSRequestAction model
(backend/app/models/ibs_request_action.py).

See docs/data-model.md (IBSRequestAction, IBSRequestActionType Enum, IBS
Request Evidence Retention) and
docs/features/packages/ibs-submission-tracking.md (Data Model >
IBSRequestAction, Retention and Deletion, RabbitMQ Request Wake-Ups step 4,
Testing Requirements: semantic-identity constraints). Only the persistence
contract is covered here; action normalization, provenance fill,
identity-conflict handling, and track correlation are IBS submission tracking
behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint, delete, insert, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import RelationshipProperty

from app.core.enums import IBSRequestActionType
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction

IBSRequestFactory = Callable[..., Awaitable[IBSRequest]]
IBSRequestActionFactory = Callable[..., Awaitable[IBSRequestAction]]

_INCIDENT = IBSRequestActionType.MAINTENANCE_INCIDENT.value
_RELEASE = IBSRequestActionType.MAINTENANCE_RELEASE.value

_DOCUMENTED_COLUMNS = {
    "id",
    "ibs_request_id",
    "action_type",
    "source_project",
    "source_package",
    "target_project",
    "target_package",
    "target_release_project",
    "logical_package",
    "codestream_name",
    "incident_number",
    "source_revision",
    "accepted_revision",
    "accepted_srcmd5",
    "accepted_xsrcmd5",
    "created_at",
    "updated_at",
}

_NULLABLE_COLUMNS = {
    "source_project",
    "source_package",
    "target_project",
    "target_package",
    "target_release_project",
    "incident_number",
    "source_revision",
    "accepted_revision",
    "accepted_srcmd5",
    "accepted_xsrcmd5",
}

_INCIDENT_POSITIVE_CHECK = "chk_ibs_request_action_incident_number_positive"
_COHERENCE_CHECK = "chk_ibs_request_action_type_coherence"
_SRCMD5_CHECK = "chk_ibs_request_action_accepted_srcmd5_hex"
_XSRCMD5_CHECK = "chk_ibs_request_action_accepted_xsrcmd5_hex"
_INCIDENT_IDENTITY = "uq_ibs_request_action_maintenance_incident_identity"
_RELEASE_IDENTITY = "uq_ibs_request_action_maintenance_release_identity"
_REQUEST_INDEX = "ix_ibs_request_action_ibs_request_id"
_REQUEST_FK = "ibs_request_action_ibs_request_id_fkey"

_EXPECTED_INDEXES = {
    _INCIDENT_IDENTITY: (
        (
            "ibs_request_id",
            "source_project",
            "source_package",
            "target_release_project",
        ),
        True,
        f"action_type = '{_INCIDENT}'",
    ),
    _RELEASE_IDENTITY: (
        ("ibs_request_id", "target_project", "target_package"),
        True,
        f"action_type = '{_RELEASE}'",
    ),
    _REQUEST_INDEX: (("ibs_request_id",), False, None),
}

_CODESTREAM = "Example:Codestream:One:Update"
_OTHER_CODESTREAM = "Example:Codestream:Two:Update"
_CHECKSUM = "0123456789abcdef0123456789abcdef"
_CHECKSUM_CASES = [
    ("accepted_srcmd5", _SRCMD5_CHECK),
    ("accepted_xsrcmd5", _XSRCMD5_CHECK),
]


@pytest.mark.integration
class TestIBSRequestActionCreation:
    async def test_create_maintenance_incident_with_defaults(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        action = await ibs_request_action_factory()

        assert action.id.version == 7
        assert action.ibs_request_id is not None
        assert action.action_type == _INCIDENT
        assert action.source_project is not None
        assert action.source_package is not None
        assert action.target_release_project is not None
        assert action.codestream_name == action.target_release_project
        assert action.target_project is None
        assert action.target_package is None
        assert action.incident_number is None
        assert action.source_revision is None
        assert action.accepted_revision is None
        assert action.accepted_srcmd5 is None
        assert action.accepted_xsrcmd5 is None
        assert action.created_at is not None
        assert action.updated_at is not None

    async def test_create_maintenance_release_with_defaults(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        action = await ibs_request_action_factory(action_type=_RELEASE)

        assert action.action_type == _RELEASE
        assert action.source_project is not None
        assert action.source_package is not None
        assert action.target_project is not None
        assert action.target_package is not None
        assert action.incident_number is not None
        assert action.incident_number > 0
        assert action.codestream_name == action.target_project
        assert action.target_release_project is None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        """An accepted submission action may carry every optional
        provenance field."""
        request = await ibs_request_factory(state="accepted")
        action = await ibs_request_action_factory(
            ibs_request_id=request.id,
            action_type=_INCIDENT,
            source_project="Example:Devel:Branch",
            source_package="example-pkg",
            target_project="Example:Maintenance:4242",
            target_package="example-pkg.Example_Codestream_One",
            target_release_project=_CODESTREAM,
            logical_package="example-pkg",
            codestream_name=_CODESTREAM,
            incident_number=4242,
            source_revision="7",
            accepted_revision="3",
            accepted_srcmd5=_CHECKSUM,
            accepted_xsrcmd5="fedcba9876543210fedcba9876543210",
        )
        action_id = action.id
        db_session.expunge(action)

        reloaded = await db_session.get(IBSRequestAction, action_id)
        assert reloaded is not None
        assert reloaded.ibs_request_id == request.id
        assert reloaded.action_type == _INCIDENT
        assert reloaded.source_project == "Example:Devel:Branch"
        assert reloaded.source_package == "example-pkg"
        assert reloaded.target_project == "Example:Maintenance:4242"
        assert reloaded.target_package == "example-pkg.Example_Codestream_One"
        assert reloaded.target_release_project == _CODESTREAM
        assert reloaded.logical_package == "example-pkg"
        assert reloaded.codestream_name == _CODESTREAM
        assert reloaded.incident_number == 4242
        assert reloaded.source_revision == "7"
        assert reloaded.accepted_revision == "3"
        assert reloaded.accepted_srcmd5 == _CHECKSUM
        assert reloaded.accepted_xsrcmd5 == "fedcba9876543210fedcba9876543210"

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, ibs_request_factory: IBSRequestFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        database must supply `id` and the timestamps."""
        request = await ibs_request_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO ibs_request_action "
                "(ibs_request_id, action_type, source_project, source_package, "
                "target_release_project, logical_package, codestream_name) "
                "VALUES (:request_id, 'maintenance_incident', 'Example:Devel:Raw', "
                "'example-pkg', :codestream, 'example-pkg', :codestream) "
                "RETURNING id, created_at, updated_at"
            ),
            {"request_id": request.id, "codestream": _CODESTREAM},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at


@pytest.mark.unit
class TestIBSRequestActionSchemaShape:
    """Exactly the documented columns, constraints, and indexes (#633
    decision A2): no author, actor, comment, description, raw payload, array
    position, or RabbitMQ `action_id` column; no UNIQUE constraint beyond the
    two partial identity indexes; the four documented CHECKs (none is a
    single-column enum CHECK on Category B `action_type`); and exactly the
    three documented indexes."""

    def test_columns_match_documented_set(self) -> None:
        assert set(IBSRequestAction.__table__.columns.keys()) == _DOCUMENTED_COLUMNS

    def test_nullability_matches_documented_set(self) -> None:
        nullable = {c.name for c in IBSRequestAction.__table__.columns if c.nullable}
        assert nullable == _NULLABLE_COLUMNS

    def test_no_unique_constraint(self) -> None:
        table = IBSRequestAction.metadata.tables["ibs_request_action"]
        assert not [c for c in table.constraints if isinstance(c, UniqueConstraint)]

    def test_exact_check_constraint_set(self) -> None:
        table = IBSRequestAction.metadata.tables["ibs_request_action"]
        checks = {c.name for c in table.constraints if isinstance(c, CheckConstraint)}
        assert checks == {
            _INCIDENT_POSITIVE_CHECK,
            _COHERENCE_CHECK,
            _SRCMD5_CHECK,
            _XSRCMD5_CHECK,
        }

    def test_exact_index_set(self) -> None:
        table = IBSRequestAction.metadata.tables["ibs_request_action"]
        actual = {}
        for index in table.indexes:
            where = index.dialect_options["postgresql"]["where"]
            actual[index.name] = (
                tuple(column.name for column in index.columns),
                index.unique,
                None if where is None else str(where),
            )
            # No `postgresql_using`: PostgreSQL's default B-tree access method.
            assert not index.dialect_options["postgresql"]["using"]
        assert actual == _EXPECTED_INDEXES

    def test_action_type_has_no_default(self) -> None:
        column = IBSRequestAction.__table__.c.action_type
        assert column.default is None
        assert column.server_default is None

    def test_foreign_key_uses_ondelete_restrict(self) -> None:
        (fk,) = IBSRequestAction.__table__.c.ibs_request_id.foreign_keys
        assert fk.target_fullname == "ibs_request.id"
        assert fk.ondelete == "RESTRICT"

    @pytest.mark.parametrize(
        ("owner", "name", "target", "reverse"),
        [
            (IBSRequest, "actions", IBSRequestAction, "ibs_request"),
            (IBSRequestAction, "ibs_request", IBSRequest, "actions"),
        ],
    )
    def test_bidirectional_back_populates(
        self, owner: type, name: str, target: type, reverse: str
    ) -> None:
        relationship = getattr(owner, name).property
        assert isinstance(relationship, RelationshipProperty)
        assert relationship.mapper.class_ is target
        assert relationship.back_populates == reverse

    def test_request_actions_use_passive_deletes_all(self) -> None:
        """The ORM never nulls or deletes retained actions; the RESTRICT FK
        rejects a request delete instead."""
        assert IBSRequest.actions.property.passive_deletes == "all"
        assert not IBSRequest.actions.property.cascade.delete


@pytest.mark.integration
class TestIBSRequestActionDatabaseIndexes:
    """The created indexes carry the documented keys and predicates."""

    async def test_index_definitions(self, db_session: AsyncSession) -> None:
        result = await db_session.execute(
            text(
                "SELECT indexname, indexdef FROM pg_indexes "
                "WHERE tablename = 'ibs_request_action' "
                "AND indexname <> 'ibs_request_action_pkey'"
            )
        )
        definitions = dict(result.tuples().all())
        assert set(definitions) == set(_EXPECTED_INDEXES)
        assert definitions[_INCIDENT_IDENTITY].endswith(
            "USING btree (ibs_request_id, source_project, source_package, "
            "target_release_project) "
            "WHERE ((action_type)::text = 'maintenance_incident'::text)"
        )
        assert definitions[_INCIDENT_IDENTITY].startswith("CREATE UNIQUE INDEX")
        assert definitions[_RELEASE_IDENTITY].endswith(
            "USING btree (ibs_request_id, target_project, target_package) "
            "WHERE ((action_type)::text = 'maintenance_release'::text)"
        )
        assert definitions[_RELEASE_IDENTITY].startswith("CREATE UNIQUE INDEX")
        assert definitions[_REQUEST_INDEX].endswith("USING btree (ibs_request_id)")
        assert definitions[_REQUEST_INDEX].startswith("CREATE INDEX")


@pytest.mark.integration
class TestIBSRequestActionColumnLengths:
    @pytest.mark.parametrize(
        "column",
        [
            "source_project",
            "source_package",
            "target_project",
            "target_package",
            "logical_package",
            "source_revision",
            "accepted_revision",
        ],
    )
    async def test_varchar_255_maximum_accepted_and_exceeded_rejected(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
        column: str,
    ) -> None:
        action = await ibs_request_action_factory(**{column: "a" * 255})
        assert len(getattr(action, column)) == 255
        # asyncpg surfaces the truncation as a generic DBAPIError.
        with pytest.raises(DBAPIError, match="value too long"):
            await ibs_request_action_factory(**{column: "a" * 256})

    async def test_codestream_and_target_release_project_maximum(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        action = await ibs_request_action_factory(target_release_project="c" * 255)
        assert action.codestream_name == "c" * 255
        with pytest.raises(DBAPIError, match="value too long"):
            await ibs_request_action_factory(target_release_project="c" * 256)

    async def test_codestream_over_maximum_rejected(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        with pytest.raises(DBAPIError, match="value too long"):
            await ibs_request_action_factory(codestream_name="c" * 256)

    async def test_action_type_over_maximum_rejected(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        with pytest.raises(DBAPIError, match="value too long"):
            await ibs_request_action_factory(action_type="a" * 33)

    @pytest.mark.parametrize("column", ["accepted_srcmd5", "accepted_xsrcmd5"])
    async def test_checksum_over_maximum_rejected(
        self, ibs_request_action_factory: IBSRequestActionFactory, column: str
    ) -> None:
        with pytest.raises(DBAPIError, match="value too long"):
            await ibs_request_action_factory(**{column: "a" * 33})


@pytest.mark.integration
class TestIBSRequestActionNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        [
            "ibs_request_id",
            "action_type",
            "logical_package",
            "codestream_name",
            "created_at",
            "updated_at",
        ],
    )
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        ibs_request_factory: IBSRequestFactory,
        column: str,
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        request = await ibs_request_factory()
        values: dict[str, object] = {
            "ibs_request_id": request.id,
            "action_type": _INCIDENT,
            "source_project": "Example:Devel:Null",
            "source_package": "example-pkg",
            "target_release_project": _CODESTREAM,
            "logical_package": "example-pkg",
            "codestream_name": _CODESTREAM,
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(IBSRequestAction).values(values))


@pytest.mark.integration
class TestIBSRequestActionIncidentNumber:
    @pytest.mark.parametrize("action_type", [_INCIDENT, _RELEASE])
    @pytest.mark.parametrize("value", [0, -1])
    async def test_non_positive_rejected(
        self,
        ibs_request_action_factory: IBSRequestActionFactory,
        action_type: str,
        value: int,
    ) -> None:
        with pytest.raises(IntegrityError, match=_INCIDENT_POSITIVE_CHECK):
            await ibs_request_action_factory(
                action_type=action_type, incident_number=value
            )

    @pytest.mark.parametrize("action_type", [_INCIDENT, _RELEASE])
    async def test_smallest_positive_accepted(
        self, ibs_request_action_factory: IBSRequestActionFactory, action_type: str
    ) -> None:
        action = await ibs_request_action_factory(
            action_type=action_type, incident_number=1
        )
        assert action.incident_number == 1

    async def test_null_accepted_for_submission_action(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        action = await ibs_request_action_factory(
            action_type=_INCIDENT, incident_number=None
        )
        assert action.incident_number is None


@pytest.mark.integration
class TestIBSRequestActionTypeCoherence:
    """`chk_ibs_request_action_type_coherence` has one branch per
    `IBSRequestActionType` value (docs/data-model.md, IBSRequestAction,
    IBSRequestActionType Enum)."""

    @pytest.mark.parametrize(
        "column", ["source_project", "source_package", "target_release_project"]
    )
    async def test_maintenance_incident_missing_required_field_rejected(
        self, ibs_request_action_factory: IBSRequestActionFactory, column: str
    ) -> None:
        with pytest.raises(IntegrityError, match=_COHERENCE_CHECK):
            await ibs_request_action_factory(action_type=_INCIDENT, **{column: None})

    async def test_maintenance_incident_codestream_mismatch_rejected(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        with pytest.raises(IntegrityError, match=_COHERENCE_CHECK):
            await ibs_request_action_factory(
                action_type=_INCIDENT,
                target_release_project=_CODESTREAM,
                codestream_name=_OTHER_CODESTREAM,
            )

    async def test_maintenance_incident_codestream_is_not_target_project(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        """A submission action's codestream is its target release project,
        never its (incident) target project."""
        with pytest.raises(IntegrityError, match=_COHERENCE_CHECK):
            await ibs_request_action_factory(
                action_type=_INCIDENT,
                target_project=_OTHER_CODESTREAM,
                target_package="example-pkg",
                target_release_project=_CODESTREAM,
                codestream_name=_OTHER_CODESTREAM,
            )

    async def test_maintenance_incident_only_required_fields_accepted(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        """Target, incident, revision, and acceptinfo fields may be absent
        until IBS exposes them."""
        action = await ibs_request_action_factory(
            action_type=_INCIDENT,
            source_project="Example:Devel:Minimal",
            source_package="example-pkg",
            target_release_project=_CODESTREAM,
            codestream_name=_CODESTREAM,
        )
        assert action.codestream_name == _CODESTREAM

    @pytest.mark.parametrize(
        "column",
        [
            "source_project",
            "source_package",
            "target_project",
            "target_package",
            "incident_number",
        ],
    )
    async def test_maintenance_release_missing_required_field_rejected(
        self, ibs_request_action_factory: IBSRequestActionFactory, column: str
    ) -> None:
        with pytest.raises(IntegrityError, match=_COHERENCE_CHECK):
            await ibs_request_action_factory(action_type=_RELEASE, **{column: None})

    async def test_maintenance_release_codestream_mismatch_rejected(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        with pytest.raises(IntegrityError, match=_COHERENCE_CHECK):
            await ibs_request_action_factory(
                action_type=_RELEASE,
                target_project=_CODESTREAM,
                codestream_name=_OTHER_CODESTREAM,
            )

    async def test_maintenance_release_codestream_is_not_target_release_project(
        self, ibs_request_action_factory: IBSRequestActionFactory
    ) -> None:
        """A release action's codestream is its target project; matching an
        unrelated `target_release_project` does not satisfy coherence."""
        with pytest.raises(IntegrityError, match=_COHERENCE_CHECK):
            await ibs_request_action_factory(
                action_type=_RELEASE,
                target_project=_CODESTREAM,
                target_release_project=_OTHER_CODESTREAM,
                codestream_name=_OTHER_CODESTREAM,
            )

    @pytest.mark.parametrize(
        "action_type",
        ["maintenance_other", "MAINTENANCE_INCIDENT", "submit", "release", ""],
    )
    async def test_unknown_action_type_rejected(
        self, ibs_request_action_factory: IBSRequestActionFactory, action_type: str
    ) -> None:
        """No row can satisfy coherence with an unknown type, even when it
        carries every field of both branches."""
        with pytest.raises(IntegrityError, match=_COHERENCE_CHECK):
            await ibs_request_action_factory(
                action_type=action_type,
                source_project="Example:Maintenance:77",
                source_package="example-pkg",
                target_project=_CODESTREAM,
                target_package="example-pkg",
                target_release_project=_CODESTREAM,
                incident_number=77,
                codestream_name=_CODESTREAM,
            )

    async def test_coherence_enforced_on_update(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        action = await ibs_request_action_factory(action_type=_RELEASE)
        action.incident_number = None
        with pytest.raises(IntegrityError, match=_COHERENCE_CHECK):
            await db_session.flush()

    async def test_type_change_without_required_fields_rejected(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        action = await ibs_request_action_factory(action_type=_INCIDENT)
        with pytest.raises(IntegrityError, match=_COHERENCE_CHECK):
            await db_session.execute(
                text(
                    "UPDATE ibs_request_action SET action_type = :release "
                    "WHERE id = :id"
                ),
                {"release": _RELEASE, "id": action.id},
            )


@pytest.mark.integration
class TestIBSRequestActionChecksumHex:
    """`chk_ibs_request_action_accepted_srcmd5_hex` and
    `chk_ibs_request_action_accepted_xsrcmd5_hex`: exactly 32 lowercase
    hexadecimal characters when present."""

    @pytest.mark.parametrize(("column", "check"), _CHECKSUM_CASES)
    @pytest.mark.parametrize("value", [_CHECKSUM, "0" * 32, "f" * 32])
    async def test_lowercase_32_hex_accepted(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
        column: str,
        check: str,
        value: str,
    ) -> None:
        action = await ibs_request_action_factory(**{column: value})
        await db_session.refresh(action)
        assert getattr(action, column) == value

    @pytest.mark.parametrize(("column", "check"), _CHECKSUM_CASES)
    async def test_null_accepted(
        self,
        ibs_request_action_factory: IBSRequestActionFactory,
        column: str,
        check: str,
    ) -> None:
        action = await ibs_request_action_factory(**{column: None})
        assert getattr(action, column) is None

    @pytest.mark.parametrize(("column", "check"), _CHECKSUM_CASES)
    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("0123456789ABCDEF0123456789ABCDEF", id="uppercase"),
            pytest.param("0123456789abcdef0123456789abcdeF", id="mixed-case"),
            pytest.param("0123456789abcdef0123456789abcde", id="31-chars"),
            pytest.param("", id="empty"),
            pytest.param("g123456789abcdef0123456789abcdef", id="non-hex"),
            pytest.param("0123456789abcdef 123456789abcdef", id="space"),
        ],
    )
    async def test_invalid_value_rejected(
        self,
        ibs_request_action_factory: IBSRequestActionFactory,
        column: str,
        check: str,
        value: str,
    ) -> None:
        with pytest.raises(IntegrityError, match=check):
            await ibs_request_action_factory(**{column: value})


@pytest.mark.integration
class TestIBSRequestActionSemanticIdentity:
    """The two unique partial indexes encode the request-scoped,
    type-specific durable semantic identities (docs/data-model.md,
    IBSRequestAction, Indexes)."""

    async def test_duplicate_maintenance_incident_in_same_request_rejected(
        self,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        request = await ibs_request_factory()
        identity: dict[str, Any] = {
            "ibs_request_id": request.id,
            "action_type": _INCIDENT,
            "source_project": "Example:Devel:Dup",
            "source_package": "example-pkg",
            "target_release_project": _CODESTREAM,
        }
        await ibs_request_action_factory(**identity)
        with pytest.raises(IntegrityError, match=_INCIDENT_IDENTITY):
            await ibs_request_action_factory(**identity, logical_package="other-pkg")

    async def test_submission_target_fields_do_not_affect_identity(
        self,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        """SR `target_project` / `target_package` are outside identity:
        acceptance can add or change them."""
        request = await ibs_request_factory()
        identity: dict[str, Any] = {
            "ibs_request_id": request.id,
            "action_type": _INCIDENT,
            "source_project": "Example:Devel:Target",
            "source_package": "example-pkg",
            "target_release_project": _CODESTREAM,
        }
        await ibs_request_action_factory(
            **identity,
            target_project="Example:Maintenance:11",
            target_package="example-pkg.Example_Codestream_One",
        )
        with pytest.raises(IntegrityError, match=_INCIDENT_IDENTITY):
            await ibs_request_action_factory(
                **identity,
                target_project="Example:Maintenance:12",
                target_package="example-pkg.Example_Codestream_Other",
            )

    @pytest.mark.parametrize(
        ("column", "value"),
        [
            ("source_project", "Example:Devel:Other"),
            ("source_package", "other-pkg"),
            ("target_release_project", _OTHER_CODESTREAM),
        ],
    )
    async def test_different_maintenance_incident_identity_accepted(
        self,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
        column: str,
        value: str,
    ) -> None:
        """Each identity key column distinguishes submission actions within
        one request."""
        request = await ibs_request_factory()
        identity: dict[str, Any] = {
            "ibs_request_id": request.id,
            "action_type": _INCIDENT,
            "source_project": "Example:Devel:Base",
            "source_package": "example-pkg",
            "target_release_project": _CODESTREAM,
        }
        await ibs_request_action_factory(**identity)
        await ibs_request_action_factory(**{**identity, column: value})

    async def test_maintenance_incident_identity_in_other_request_accepted(
        self,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        identity: dict[str, Any] = {
            "action_type": _INCIDENT,
            "source_project": "Example:Devel:Shared",
            "source_package": "example-pkg",
            "target_release_project": _CODESTREAM,
        }
        first = await ibs_request_action_factory(
            ibs_request_id=(await ibs_request_factory()).id, **identity
        )
        second = await ibs_request_action_factory(
            ibs_request_id=(await ibs_request_factory()).id, **identity
        )
        assert first.ibs_request_id != second.ibs_request_id

    async def test_duplicate_maintenance_release_in_same_request_rejected(
        self,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        """Release identity is `(target_project, target_package)` within the
        request; source provenance and incident are not part of it."""
        request = await ibs_request_factory()
        await ibs_request_action_factory(
            ibs_request_id=request.id,
            action_type=_RELEASE,
            source_project="Example:Maintenance:21",
            source_package="example-pkg.Example_Codestream_One",
            target_project=_CODESTREAM,
            target_package="example-pkg",
            incident_number=21,
        )
        with pytest.raises(IntegrityError, match=_RELEASE_IDENTITY):
            await ibs_request_action_factory(
                ibs_request_id=request.id,
                action_type=_RELEASE,
                source_project="Example:Maintenance:22",
                source_package="example-pkg.Example_Codestream_Alt",
                target_project=_CODESTREAM,
                target_package="example-pkg",
                incident_number=22,
            )

    @pytest.mark.parametrize(
        ("column", "value"),
        [("target_project", _OTHER_CODESTREAM), ("target_package", "other-pkg")],
    )
    async def test_different_maintenance_release_identity_accepted(
        self,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
        column: str,
        value: str,
    ) -> None:
        request = await ibs_request_factory()
        identity: dict[str, Any] = {
            "ibs_request_id": request.id,
            "action_type": _RELEASE,
            "target_project": _CODESTREAM,
            "target_package": "example-pkg",
        }
        await ibs_request_action_factory(**identity)
        await ibs_request_action_factory(**{**identity, column: value})

    async def test_maintenance_release_identity_in_other_request_accepted(
        self,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        identity: dict[str, Any] = {
            "action_type": _RELEASE,
            "target_project": _CODESTREAM,
            "target_package": "example-pkg",
        }
        first = await ibs_request_action_factory(
            ibs_request_id=(await ibs_request_factory()).id, **identity
        )
        second = await ibs_request_action_factory(
            ibs_request_id=(await ibs_request_factory()).id, **identity
        )
        assert first.ibs_request_id != second.ibs_request_id

    async def test_release_key_columns_shared_by_submission_accepted(
        self,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        """A submission action with the same `(target_project,
        target_package)` as a release action in the same request is outside
        the release index predicate."""
        request = await ibs_request_factory()
        await ibs_request_action_factory(
            ibs_request_id=request.id,
            action_type=_RELEASE,
            target_project=_CODESTREAM,
            target_package="example-pkg",
        )
        await ibs_request_action_factory(
            ibs_request_id=request.id,
            action_type=_INCIDENT,
            target_project=_CODESTREAM,
            target_package="example-pkg",
        )

    async def test_submission_key_columns_shared_by_release_accepted(
        self,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        """A release action with the same `(source_project, source_package,
        target_release_project)` as a submission action in the same request
        is outside the submission index predicate."""
        request = await ibs_request_factory()
        shared: dict[str, Any] = {
            "ibs_request_id": request.id,
            "source_project": "Example:Maintenance:31",
            "source_package": "example-pkg",
            "target_release_project": _CODESTREAM,
        }
        await ibs_request_action_factory(**shared, action_type=_INCIDENT)
        await ibs_request_action_factory(**shared, action_type=_RELEASE)

    async def test_duplicate_rejected_on_update(
        self,
        db_session: AsyncSession,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        request = await ibs_request_factory()
        await ibs_request_action_factory(
            ibs_request_id=request.id,
            action_type=_RELEASE,
            target_project=_CODESTREAM,
            target_package="example-pkg",
        )
        other = await ibs_request_action_factory(
            ibs_request_id=request.id,
            action_type=_RELEASE,
            target_project=_CODESTREAM,
            target_package="other-pkg",
        )
        other.target_package = "example-pkg"
        with pytest.raises(IntegrityError, match=_RELEASE_IDENTITY):
            await db_session.flush()


@pytest.mark.integration
class TestIBSRequestActionForeignKey:
    async def test_nonexistent_request_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            IBSRequestAction(
                ibs_request_id=uuid.uuid7(),
                action_type=_INCIDENT,
                source_project="Example:Devel:Orphan",
                source_package="example-pkg",
                target_release_project=_CODESTREAM,
                logical_package="example-pkg",
                codestream_name=_CODESTREAM,
            )
        )
        with pytest.raises(IntegrityError, match=_REQUEST_FK):
            await db_session.flush()


@pytest.mark.integration
class TestIBSRequestDeleteRestrictedWhileActionsExist:
    """Request evidence is retained indefinitely (docs/data-model.md, IBS
    Request Evidence Retention). The FK uses `ON DELETE RESTRICT` and
    `IBSRequest.actions` uses `passive_deletes="all"`, so deleting a request
    with actions fails on the FK instead of the ORM nulling the actions'
    `ibs_request_id` first."""

    async def test_orm_delete_with_loaded_actions_raises(
        self,
        db_session: AsyncSession,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        request = await ibs_request_factory()
        await ibs_request_action_factory(ibs_request_id=request.id)
        await db_session.refresh(request, ["actions"])
        assert len(request.actions) == 1

        await db_session.delete(request)
        with pytest.raises(IntegrityError, match=_REQUEST_FK):
            await db_session.flush()

    async def test_database_delete_raises(
        self,
        db_session: AsyncSession,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        request = await ibs_request_factory()
        await ibs_request_action_factory(ibs_request_id=request.id)
        request_id = request.id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match=_REQUEST_FK):
            await db_session.execute(
                delete(IBSRequest).where(IBSRequest.id == request_id)
            )


@pytest.mark.integration
class TestIBSRequestActionRelationships:
    async def test_request_actions_round_trip(
        self,
        db_session: AsyncSession,
        ibs_request_factory: IBSRequestFactory,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        """A multi-action request loads every action, of both types."""
        request = await ibs_request_factory()
        submission = await ibs_request_action_factory(ibs_request_id=request.id)
        release = await ibs_request_action_factory(
            ibs_request_id=request.id, action_type=_RELEASE
        )
        await ibs_request_action_factory()

        await db_session.refresh(submission, ["ibs_request"])
        await db_session.refresh(request, ["actions"])

        assert submission.ibs_request is request
        assert {a.id for a in request.actions} == {submission.id, release.id}


@pytest.mark.integration
class TestIBSRequestActionTimestamps:
    async def test_timestamps_are_timezone_aware(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        action = await ibs_request_action_factory()
        await db_session.refresh(action)
        assert action.created_at.tzinfo is not None
        assert action.updated_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        action = await ibs_request_action_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        action.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(action)
        assert action.updated_at == backdated

        action.accepted_revision = "5"
        await db_session.flush()
        await db_session.refresh(action)

        assert action.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
    ) -> None:
        action = await ibs_request_action_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        action.created_at = backdated
        await db_session.flush()

        action.source_revision = "9"
        await db_session.flush()
        await db_session.refresh(action)

        assert action.created_at == backdated
