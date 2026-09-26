"""Tests for derived package-tree actionability and delivery relevance.

Owning specification: `docs/features/packages/package-model.md`
(Exclusion and Actionability > Manual Exclusion Markers, Derived
Actionability, Gate Participation; Axis 3 > Delivery Relevance Indicator;
Three Orthogonal Dimensions).

- The pure `non_actionable_reason` projections are checked against the
  eight-row direct-marker table and the ordered precedence of every level,
  transcribed independently from the specification.
- SQL/Python parity: over persisted rows, the SQL `product`, `track`, and
  `package` actionability expressions equal the pure projections
  (`actionable` exactly when the reason is `None`) for every input of the
  shared lifecycle matrix (`tests/support/lifecycle_matrix.py`: curated
  `LIFECYCLE_CASES` and the complete `lifecycle_grid()`) crossed with all
  eight package/track/Product marker combinations, including NULL
  lifecycle inputs.
- Affectedness, eligibility, delivery, Product release, and Ticket status
  are not inputs, and no actionability or lifecycle value is persisted.
"""

from __future__ import annotations

import inspect
import itertools
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

import pytest
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.enums import (
    DeliveryStatus,
    LifecyclePhase,
    NonActionableReason,
    PackageStatus,
    TicketStatus,
)
from app.database import Base
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_actionability
from app.services.package_actionability import (
    is_delivery_relevant,
    package_actionable_expression,
    package_non_actionable_reason,
    product_actionable_expression,
    product_non_actionable_reason,
    track_actionable_expression,
    track_non_actionable_reason,
)
from app.services.product_lifecycle import evaluate_product_lifecycle_phase
from app.services.product_service import lifecycle_phase_expression
from tests.support.lifecycle_matrix import (
    LIFECYCLE_CASES,
    LifecycleCase,
    LifecycleInputs,
    grid_evaluation_dates,
    lifecycle_grid,
)
from tests.support.module_imports import APP_ROOT, imported_modules

Factory = Callable[..., Awaitable[Any]]
DateSet = tuple[date | None, date | None, date | None, date | None]

R = NonActionableReason
EXCLUDED_AT = datetime(2026, 5, 4, 12, 0, tzinfo=UTC)
TODAY = date(2027, 1, 1)
GS_FUTURE = date(2030, 1, 1)
GS_PAST = date(2020, 1, 1)


@dataclass(frozen=True, slots=True)
class Markers:
    """Direct `deleted_at` marker state of one package/track/Product chain."""

    package: bool
    track: bool
    product: bool

    @property
    def id(self) -> str:
        return "".join(
            name if flag else "-"
            for name, flag in (
                ("P", self.package),
                ("T", self.track),
                ("R", self.product),
            )
        )


ALL_MARKERS: tuple[Markers, ...] = tuple(
    Markers(package=p, track=t, product=r)
    for p, t, r in itertools.product((False, True), repeat=3)
)

# package-model.md § Manual Exclusion Markers: the eight-row table, keyed
# by (package, track, Product) marker state, before applying lifecycle.
MARKER_TABLE: dict[tuple[bool, bool, bool], NonActionableReason | None] = {
    (False, False, False): None,
    (False, False, True): R.PRODUCT_EXCLUDED,
    (False, True, False): R.TRACK_EXCLUDED,
    (False, True, True): R.TRACK_EXCLUDED,
    (True, False, False): R.PACKAGE_EXCLUDED,
    (True, False, True): R.PACKAGE_EXCLUDED,
    (True, True, False): R.PACKAGE_EXCLUDED,
    (True, True, True): R.PACKAGE_EXCLUDED,
}


def _expected_product_reason(
    markers: Markers, phase: LifecyclePhase | None
) -> NonActionableReason | None:
    """Independent transcription: the marker row applies first; only the
    all-clear row changes to `eol` for an EOL Product."""
    reason = MARKER_TABLE[(markers.package, markers.track, markers.product)]
    if reason is None and phase is LifecyclePhase.EOL:
        return R.EOL
    return reason


def _pure_phase(inputs: LifecycleInputs) -> LifecyclePhase | None:
    return evaluate_product_lifecycle_phase(**inputs.evaluator_kwargs())


def _dates_of(inputs: LifecycleInputs) -> DateSet:
    return (
        inputs.first_customer_ship_date,
        inputs.general_support_end_date,
        inputs.extended_support_end_date,
        inputs.reactive_support_end_date,
    )


# ---------------------------------------------------------------------------
# Pure projections
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestProductReasonPrecedence:
    @pytest.mark.parametrize("markers", ALL_MARKERS, ids=lambda m: m.id)
    @pytest.mark.parametrize(
        "phase", [*LifecyclePhase, None], ids=lambda p: str(p or "null")
    )
    def test_every_marker_combination_and_phase(
        self, markers: Markers, phase: LifecyclePhase | None
    ) -> None:
        reason = product_non_actionable_reason(
            package_excluded=markers.package,
            track_excluded=markers.track,
            product_excluded=markers.product,
            lifecycle_phase=phase,
        )

        assert reason == _expected_product_reason(markers, phase)

    def test_null_phase_is_actionable(self) -> None:
        assert (
            product_non_actionable_reason(
                package_excluded=False,
                track_excluded=False,
                product_excluded=False,
                lifecycle_phase=None,
            )
            is None
        )

    @pytest.mark.parametrize(
        "phase", [p for p in LifecyclePhase if p is not LifecyclePhase.EOL]
    )
    def test_only_eol_makes_a_clear_product_non_actionable(
        self, phase: LifecyclePhase
    ) -> None:
        assert (
            product_non_actionable_reason(
                package_excluded=False,
                track_excluded=False,
                product_excluded=False,
                lifecycle_phase=phase,
            )
            is None
        )


@pytest.mark.unit
class TestTrackReasonPrecedence:
    @pytest.mark.parametrize(
        ("package_excluded", "track_excluded", "has_actionable_product", "expected"),
        [
            (False, False, True, None),
            (False, False, False, R.NO_ACTIONABLE_PRODUCTS),
            (False, True, True, R.TRACK_EXCLUDED),
            (False, True, False, R.TRACK_EXCLUDED),
            (True, False, True, R.PACKAGE_EXCLUDED),
            (True, False, False, R.PACKAGE_EXCLUDED),
            (True, True, True, R.PACKAGE_EXCLUDED),
            (True, True, False, R.PACKAGE_EXCLUDED),
        ],
    )
    def test_first_applicable_reason(
        self,
        package_excluded: bool,
        track_excluded: bool,
        has_actionable_product: bool,
        expected: NonActionableReason | None,
    ) -> None:
        assert (
            track_non_actionable_reason(
                package_excluded=package_excluded,
                track_excluded=track_excluded,
                has_actionable_product=has_actionable_product,
            )
            == expected
        )


@pytest.mark.unit
class TestPackageReasonPrecedence:
    @pytest.mark.parametrize(
        ("package_excluded", "has_actionable_track", "expected"),
        [
            (False, True, None),
            (False, False, R.NO_ACTIONABLE_TRACKS),
            (True, True, R.PACKAGE_EXCLUDED),
            (True, False, R.PACKAGE_EXCLUDED),
        ],
    )
    def test_first_applicable_reason(
        self,
        package_excluded: bool,
        has_actionable_track: bool,
        expected: NonActionableReason | None,
    ) -> None:
        assert (
            package_non_actionable_reason(
                package_excluded=package_excluded,
                has_actionable_track=has_actionable_track,
            )
            == expected
        )


@pytest.mark.unit
class TestDeliveryRelevant:
    @pytest.mark.parametrize("status", list(PackageStatus))
    @pytest.mark.parametrize("delivery", list(DeliveryStatus))
    def test_rule(self, status: PackageStatus, delivery: DeliveryStatus) -> None:
        expected = status in (
            PackageStatus.ANALYSIS,
            PackageStatus.AFFECTED,
        ) or delivery in (DeliveryStatus.IN_PROGRESS, DeliveryStatus.RELEASED)

        assert is_delivery_relevant(status, delivery) is expected

    @pytest.mark.parametrize(
        "status",
        [PackageStatus.NOT_AFFECTED, PackageStatus.FIXED, PackageStatus.WONT_FIX],
    )
    def test_final_status_with_pending_default_is_noise(
        self, status: PackageStatus
    ) -> None:
        assert is_delivery_relevant(status, DeliveryStatus.PENDING) is False


# ---------------------------------------------------------------------------
# Persisted matrix: one package -> one track -> one Product occurrence per
# (marker combination, lifecycle date set)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Chain:
    markers: Markers
    dates: DateSet
    package_id: uuid.UUID
    track_id: uuid.UUID
    occurrence_id: uuid.UUID


async def _persist_chains(
    db: AsyncSession, ticket_id: uuid.UUID, date_sets: Iterable[DateSet]
) -> list[Chain]:
    """Persist one Product per date set and, for each of the eight marker
    combinations, one package -> track -> occurrence chain per Product,
    in a few bulk statements."""
    date_sets = list(date_sets)
    seen_at = datetime.now(UTC)
    product_rows = [
        {
            "name": f"Actionability {n}",
            "version": str(n),
            "display_name": f"Actionability {n}",
            "cpe": f"cpe:/o:example:actionability:{uuid.uuid4().hex}",
            "catalog_last_seen_at": seen_at,
            "first_customer_ship_date": fcs,
            "general_support_end_date": gs,
            "extended_support_end_date": ext,
            "reactive_support_end_date": rs,
        }
        for n, (fcs, gs, ext, rs) in enumerate(date_sets)
    ]
    product_ids = (
        (await db.execute(insert(Product).returning(Product.id), product_rows))
        .scalars()
        .all()
    )
    specs = [
        (markers, dates, product_id)
        for markers in ALL_MARKERS
        for dates, product_id in zip(date_sets, product_ids, strict=True)
    ]
    package_ids = (
        (
            await db.execute(
                insert(TicketPackage).returning(TicketPackage.id),
                [
                    {
                        "ticket_id": ticket_id,
                        "package_name": f"pkg-{n}",
                        "deleted_at": EXCLUDED_AT if markers.package else None,
                    }
                    for n, (markers, _, _) in enumerate(specs)
                ],
            )
        )
        .scalars()
        .all()
    )
    track_ids = (
        (
            await db.execute(
                insert(TicketPackageTrack).returning(TicketPackageTrack.id),
                [
                    {
                        "ticket_package_id": package_id,
                        "workflow_type": "ibs",
                        "reference": "Example:Codestream:1:Update",
                        "deleted_at": EXCLUDED_AT if markers.track else None,
                    }
                    for (markers, _, _), package_id in zip(
                        specs, package_ids, strict=True
                    )
                ],
            )
        )
        .scalars()
        .all()
    )
    occurrence_ids = (
        (
            await db.execute(
                insert(TicketPackageProduct).returning(TicketPackageProduct.id),
                [
                    {
                        "ticket_package_track_id": track_id,
                        "product_id": product_id,
                        "deleted_at": EXCLUDED_AT if markers.product else None,
                    }
                    for (markers, _, product_id), track_id in zip(
                        specs, track_ids, strict=True
                    )
                ],
            )
        )
        .scalars()
        .all()
    )
    return [
        Chain(markers, dates, package_id, track_id, occurrence_id)
        for (markers, dates, _), package_id, track_id, occurrence_id in zip(
            specs, package_ids, track_ids, occurrence_ids, strict=True
        )
    ]


async def _sql_actionability(
    db: AsyncSession, evaluation_date: date, package_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[bool, bool, bool, str | None]]:
    """(package, track, Product) SQL actionability and phase per occurrence."""
    result = await db.execute(
        select(
            TicketPackageProduct.id,
            package_actionable_expression(evaluation_date),
            track_actionable_expression(evaluation_date),
            product_actionable_expression(evaluation_date),
            lifecycle_phase_expression(evaluation_date),
        )
        .select_from(TicketPackage)
        .join(
            TicketPackageTrack, TicketPackageTrack.ticket_package_id == TicketPackage.id
        )
        .join(
            TicketPackageProduct,
            TicketPackageProduct.ticket_package_track_id == TicketPackageTrack.id,
        )
        .join(Product, Product.id == TicketPackageProduct.product_id)
        .where(TicketPackage.id.in_(package_ids))
    )
    return {row[0]: (row[1], row[2], row[3], row[4]) for row in result.all()}


def _pure_levels(
    markers: Markers, phase: LifecyclePhase | None
) -> tuple[
    NonActionableReason | None, NonActionableReason | None, NonActionableReason | None
]:
    """Pure (package, track, Product) reasons of a one-child chain."""
    product = product_non_actionable_reason(
        package_excluded=markers.package,
        track_excluded=markers.track,
        product_excluded=markers.product,
        lifecycle_phase=phase,
    )
    track = track_non_actionable_reason(
        package_excluded=markers.package,
        track_excluded=markers.track,
        has_actionable_product=product is None,
    )
    package = package_non_actionable_reason(
        package_excluded=markers.package, has_actionable_track=track is None
    )
    return package, track, product


@pytest.fixture
async def matrix_ticket(ticket_factory: Factory) -> Ticket:
    ticket: Ticket = await ticket_factory()
    return ticket


def _grid_date_sets() -> list[DateSet]:
    return sorted(
        {_dates_of(inputs) for inputs in lifecycle_grid()},
        key=lambda dates: tuple((d is None, d or date.min) for d in dates),
    )


@pytest.fixture
async def grid_chains(db_session: AsyncSession, matrix_ticket: Ticket) -> list[Chain]:
    return await _persist_chains(db_session, matrix_ticket.id, _grid_date_sets())


@pytest.mark.integration
class TestActionabilityParityCuratedCases:
    """`LIFECYCLE_CASES` x eight marker combinations, with expectations
    transcribed independently from the specification."""

    @pytest.mark.parametrize("case", LIFECYCLE_CASES, ids=lambda case: case.id)
    async def test_sql_equals_pure_and_expected(
        self, db_session: AsyncSession, matrix_ticket: Ticket, case: LifecycleCase
    ) -> None:
        chains = await _persist_chains(
            db_session, matrix_ticket.id, [_dates_of(case.inputs)]
        )
        sql = await _sql_actionability(
            db_session, case.inputs.evaluation_date, [c.package_id for c in chains]
        )

        assert len(chains) == len(ALL_MARKERS)
        for chain in chains:
            package_sql, track_sql, product_sql, phase_sql = sql[chain.occurrence_id]
            phase = LifecyclePhase(phase_sql) if phase_sql is not None else None
            assert phase == case.expected
            package_reason, track_reason, product_reason = _pure_levels(
                chain.markers, phase
            )
            assert product_reason == _expected_product_reason(
                chain.markers, case.expected
            ), chain.markers
            assert (product_sql, track_sql, package_sql) == (
                product_reason is None,
                track_reason is None,
                package_reason is None,
            ), chain.markers


@pytest.mark.integration
class TestActionabilityParityGrid:
    """The complete expectation-free `lifecycle_grid()` x eight markers."""

    async def test_grid_covers_every_date_set_and_marker(
        self, grid_chains: list[Chain]
    ) -> None:
        assert len(grid_chains) == 4**4 * len(ALL_MARKERS)

    @pytest.mark.parametrize(
        "evaluation_date", grid_evaluation_dates(), ids=lambda d: d.isoformat()
    )
    async def test_sql_equals_pure_for_every_level(
        self,
        db_session: AsyncSession,
        grid_chains: list[Chain],
        evaluation_date: date,
    ) -> None:
        sql = await _sql_actionability(
            db_session, evaluation_date, [c.package_id for c in grid_chains]
        )
        pure_phase = {
            _dates_of(inputs): _pure_phase(inputs)
            for inputs in lifecycle_grid()
            if inputs.evaluation_date == evaluation_date
        }

        mismatches = []
        for chain in grid_chains:
            package_sql, track_sql, product_sql, _ = sql[chain.occurrence_id]
            package_reason, track_reason, product_reason = _pure_levels(
                chain.markers, pure_phase[chain.dates]
            )
            expected = (
                package_reason is None,
                track_reason is None,
                product_reason is None,
            )
            if (package_sql, track_sql, product_sql) != expected:
                mismatches.append((chain.markers, chain.dates, expected))

        assert mismatches == []

    async def test_grid_exercises_every_reason_and_actionable_outcome(
        self, db_session: AsyncSession, grid_chains: list[Chain]
    ) -> None:
        """Guards the parity test against a degenerate matrix."""
        reasons: set[NonActionableReason | None] = set()
        for evaluation_date in grid_evaluation_dates():
            sql = await _sql_actionability(
                db_session, evaluation_date, [c.package_id for c in grid_chains]
            )
            for chain in grid_chains:
                phase_sql = sql[chain.occurrence_id][3]
                phase = LifecyclePhase(phase_sql) if phase_sql is not None else None
                reasons.update(_pure_levels(chain.markers, phase))

        assert reasons == set(NonActionableReason) | {None}


# ---------------------------------------------------------------------------
# Multi-child aggregation and filter use
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActionabilityAggregation:
    async def _track_and_package(
        self, db: AsyncSession, track: TicketPackageTrack
    ) -> tuple[bool, bool]:
        row = (
            await db.execute(
                select(
                    track_actionable_expression(TODAY),
                    package_actionable_expression(TODAY),
                )
                .select_from(TicketPackageTrack)
                .join(
                    TicketPackage,
                    TicketPackage.id == TicketPackageTrack.ticket_package_id,
                )
                .where(TicketPackageTrack.id == track.id)
            )
        ).one()
        return row[0], row[1]

    async def test_track_with_one_actionable_product_among_eol_is_actionable(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        product_factory: Factory,
    ) -> None:
        track = await ticket_package_track_factory()
        eol = await product_factory(general_support_end_date=GS_PAST)
        supported = await product_factory(general_support_end_date=GS_FUTURE)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=eol.id
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=supported.id
        )

        assert await self._track_and_package(db_session, track) == (True, True)

    async def test_all_eol_track_is_structurally_present_but_non_actionable(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        product_factory: Factory,
    ) -> None:
        track = await ticket_package_track_factory()
        for _ in range(2):
            eol = await product_factory(general_support_end_date=GS_PAST)
            await ticket_package_product_factory(
                ticket_package_track_id=track.id, product_id=eol.id
            )

        assert await self._track_and_package(db_session, track) == (False, False)
        assert track.deleted_at is None

    async def test_excluded_product_does_not_count_for_its_track(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        track = await ticket_package_track_factory()
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, deleted_at=EXCLUDED_AT
        )

        assert await self._track_and_package(db_session, track) == (False, False)

    async def test_track_without_products_is_non_actionable(
        self, db_session: AsyncSession, ticket_package_track_factory: Factory
    ) -> None:
        track = await ticket_package_track_factory()

        assert await self._track_and_package(db_session, track) == (False, False)

    async def test_package_with_one_actionable_track_among_excluded_is_actionable(
        self,
        db_session: AsyncSession,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        package = await ticket_package_factory()
        excluded = await ticket_package_track_factory(
            ticket_package_id=package.id, deleted_at=EXCLUDED_AT
        )
        included = await ticket_package_track_factory(ticket_package_id=package.id)
        await ticket_package_product_factory(ticket_package_track_id=excluded.id)
        await ticket_package_product_factory(ticket_package_track_id=included.id)

        assert await self._track_and_package(db_session, excluded) == (False, True)
        assert await self._track_and_package(db_session, included) == (True, True)

    async def test_package_without_tracks_is_non_actionable(
        self, db_session: AsyncSession, ticket_package_factory: Factory
    ) -> None:
        package = await ticket_package_factory()

        result = await db_session.execute(
            select(package_actionable_expression(TODAY)).where(
                TicketPackage.id == package.id
            )
        )

        assert result.scalar_one() is False

    async def test_expressions_filter_in_sql_with_aliases(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        product_factory: Factory,
    ) -> None:
        """Filters and existence counts run in PostgreSQL, on aliases, and
        never multiply the enclosing rows."""
        ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        actionable = await ticket_package_track_factory(ticket_package_id=package.id)
        eol_track = await ticket_package_track_factory(ticket_package_id=package.id)
        for _ in range(3):
            await ticket_package_product_factory(ticket_package_track_id=actionable.id)
        eol = await product_factory(general_support_end_date=GS_PAST)
        await ticket_package_product_factory(
            ticket_package_track_id=eol_track.id, product_id=eol.id
        )
        package_alias = aliased(TicketPackage)
        track_alias = aliased(TicketPackageTrack)

        selected = (
            (
                await db_session.execute(
                    select(track_alias.id)
                    .join(
                        package_alias, package_alias.id == track_alias.ticket_package_id
                    )
                    .where(
                        package_alias.ticket_id == ticket.id,
                        track_actionable_expression(
                            TODAY, package=package_alias, track=track_alias
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        packages = (
            (
                await db_session.execute(
                    select(package_alias.id).where(
                        package_alias.ticket_id == ticket.id,
                        package_actionable_expression(TODAY, package=package_alias),
                    )
                )
            )
            .scalars()
            .all()
        )

        assert selected == [actionable.id]
        assert packages == [package.id]


# ---------------------------------------------------------------------------
# Dimension independence and non-persistence
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActionabilityInputs:
    async def _levels(
        self, db: AsyncSession, occurrence: TicketPackageProduct
    ) -> tuple[bool, bool, bool]:
        row = (
            await db.execute(
                select(
                    package_actionable_expression(TODAY),
                    track_actionable_expression(TODAY),
                    product_actionable_expression(TODAY),
                )
                .select_from(TicketPackageProduct)
                .join(
                    TicketPackageTrack,
                    TicketPackageTrack.id
                    == TicketPackageProduct.ticket_package_track_id,
                )
                .join(
                    TicketPackage,
                    TicketPackage.id == TicketPackageTrack.ticket_package_id,
                )
                .join(Product, Product.id == TicketPackageProduct.product_id)
                .where(TicketPackageProduct.id == occurrence.id)
            )
        ).one()
        return row[0], row[1], row[2]

    @pytest.mark.parametrize("eol", [False, True], ids=["supported", "eol"])
    async def test_other_dimensions_and_ticket_status_are_not_inputs(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        product_factory: Factory,
        eol: bool,
    ) -> None:
        """Affectedness, eligibility and its override, delivery, Product
        release, and Ticket status never change any level's actionability
        (package-model.md, Three Orthogonal Dimensions; Gate Participation)."""
        ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(ticket_package_id=package.id)
        product = await product_factory(
            general_support_end_date=GS_PAST if eol else GS_FUTURE
        )
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        baseline = await self._levels(db_session, occurrence)
        assert baseline == ((not eol),) * 3

        variations: list[tuple[Any, str, Any]] = [
            *[(track, "status", s.value) for s in PackageStatus],
            *[(track, "delivery_status", d.value) for d in DeliveryStatus],
            (occurrence, "eligible", False),
            (occurrence, "is_eligible_override", True),
            (occurrence, "released_at", EXCLUDED_AT),
            *[
                (ticket, "status", s.value)
                for s in TicketStatus
                if s is not TicketStatus.DUPLICATED
            ],
        ]
        for record, attribute, value in variations:
            setattr(record, attribute, value)
            await db_session.flush()
            assert await self._levels(db_session, occurrence) == baseline, (
                attribute,
                value,
            )

    def test_no_actionability_or_lifecycle_column_is_persisted(self) -> None:
        forbidden = {"actionable", "lifecycle_phase", "non_actionable_reason"}
        columns = {
            (table.name, column.name)
            for table in Base.metadata.tables.values()
            for column in table.columns
            if column.name in forbidden
        }

        assert columns == set()


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPackageActionabilityModuleBoundary:
    def test_imports_only_models_core_and_the_product_query_service(self) -> None:
        """Importable by `package_service`, `ticket_mutations`, and the
        deadline expressions without a dependency cycle."""
        modules = imported_modules(
            APP_ROOT / "services" / "package_actionability.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.services")} == {
            "app.services.product_service"
        }
        assert {m for m in modules if m.startswith("app.")} <= {
            "app.core.enums",
            "app.models.product",
            "app.models.ticket_package",
            "app.models.ticket_package_product",
            "app.models.ticket_package_track",
            "app.services.product_service",
        }

    def test_every_builder_is_synchronous(self) -> None:
        for name in (
            "product_actionable_expression",
            "track_actionable_expression",
            "package_actionable_expression",
            "product_non_actionable_reason",
            "track_non_actionable_reason",
            "package_non_actionable_reason",
            "is_delivery_relevant",
        ):
            assert not inspect.iscoroutinefunction(
                getattr(package_actionability, name)
            ), name
