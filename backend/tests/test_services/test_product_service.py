"""Tests for the Product query service's SQL lifecycle expression.

Owning specification: `docs/features/packages/product-catalog.md` (Product
Lifecycle Phases, Lifecycle Evaluator) and
`docs/features/packages/package-model.md` (Exclusion and Actionability,
Derived Actionability): the reusable SQL expression and the pure
`evaluate_product_lifecycle_phase()` MUST agree for every valid,
incomplete, inconsistent, and boundary-date combination.

Every comparison evaluates the expression in PostgreSQL over persisted
`product` rows whose four lifecycle date columns equal the matrix input
(`tests/support/lifecycle_matrix.py`): the curated `LIFECYCLE_CASES` against
their independently transcribed expectations and the pure evaluator, and the
complete expectation-free `lifecycle_grid()` against the pure evaluator.
Filter tests assert that `= <phase>` and `IS NULL` select rows in SQL, with
no Python-side filtering.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import ColumnElement, insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.enums import LifecyclePhase
from app.models.product import Product
from app.services import product_service
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

ProductFactory = Callable[..., Awaitable[Product]]

DateSet = tuple[date | None, date | None, date | None, date | None]

_PHASE_VALUES = {phase.value for phase in LifecyclePhase}


def _dates_of(inputs: LifecycleInputs) -> DateSet:
    return (
        inputs.first_customer_ship_date,
        inputs.general_support_end_date,
        inputs.extended_support_end_date,
        inputs.reactive_support_end_date,
    )


def _pure_value(inputs: LifecycleInputs) -> str | None:
    phase = evaluate_product_lifecycle_phase(**inputs.evaluator_kwargs())
    return None if phase is None else phase.value


async def _insert_date_sets(
    session: AsyncSession, date_sets: list[DateSet]
) -> dict[DateSet, uuid.UUID]:
    """Persist one `product` row per distinct date set, in one statement."""
    seen_at = datetime.now(UTC)
    rows = [
        {
            "name": f"Lifecycle {n}",
            "version": str(n),
            "display_name": f"Lifecycle {n}",
            "cpe": f"cpe:/o:example:lifecycle:{n}",
            "catalog_last_seen_at": seen_at,
            "first_customer_ship_date": fcs,
            "general_support_end_date": gs_end,
            "extended_support_end_date": extended_end,
            "reactive_support_end_date": reactive_end,
        }
        for n, (fcs, gs_end, extended_end, reactive_end) in enumerate(date_sets)
    ]
    result = await session.execute(
        insert(Product).returning(
            Product.id,
            Product.first_customer_ship_date,
            Product.general_support_end_date,
            Product.extended_support_end_date,
            Product.reactive_support_end_date,
        ),
        rows,
    )
    return {(row[1], row[2], row[3], row[4]): row[0] for row in result.all()}


async def _phases_on(
    session: AsyncSession, evaluation_date: date, ids: list[uuid.UUID]
) -> dict[uuid.UUID, str | None]:
    """Evaluate the SQL expression for `ids` on one date, in PostgreSQL."""
    result = await session.execute(
        select(Product.id, lifecycle_phase_expression(evaluation_date)).where(
            Product.id.in_(ids)
        )
    )
    return {row[0]: row[1] for row in result.all()}


async def _ids_where(
    session: AsyncSession, predicate: ColumnElement[bool], ids: list[uuid.UUID]
) -> set[uuid.UUID]:
    result = await session.execute(
        select(Product.id).where(predicate, Product.id.in_(ids))
    )
    return set(result.scalars().all())


def _grid_date_sets() -> list[DateSet]:
    return sorted(
        {_dates_of(inputs) for inputs in lifecycle_grid()},
        key=lambda dates: tuple((d is None, d or date.min) for d in dates),
    )


@pytest.fixture
async def grid_products(db_session: AsyncSession) -> dict[DateSet, uuid.UUID]:
    """One persisted Product per distinct `lifecycle_grid()` date set."""
    return await _insert_date_sets(db_session, _grid_date_sets())


# ---------------------------------------------------------------------------
# Curated cases
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLifecycleExpressionCuratedCases:
    @pytest.mark.parametrize("case", LIFECYCLE_CASES, ids=lambda case: case.id)
    async def test_expression_matches_expectation_and_pure_evaluator(
        self, db_session: AsyncSession, case: LifecycleCase
    ) -> None:
        ids = await _insert_date_sets(db_session, [_dates_of(case.inputs)])
        (product_id,) = ids.values()

        phases = await _phases_on(db_session, case.inputs.evaluation_date, [product_id])

        expected = None if case.expected is None else case.expected.value
        assert phases[product_id] == expected
        assert phases[product_id] == _pure_value(case.inputs)


# ---------------------------------------------------------------------------
# Complete combinatorial grid
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLifecycleExpressionGridParity:
    async def test_grid_persists_one_row_per_distinct_date_set(
        self, grid_products: dict[DateSet, uuid.UUID]
    ) -> None:
        assert len(grid_products) == len(_grid_date_sets()) == 4**4

    @pytest.mark.parametrize(
        "evaluation_date", grid_evaluation_dates(), ids=lambda d: d.isoformat()
    )
    async def test_expression_equals_pure_evaluator_for_every_grid_input(
        self,
        db_session: AsyncSession,
        grid_products: dict[DateSet, uuid.UUID],
        evaluation_date: date,
    ) -> None:
        phases = await _phases_on(
            db_session, evaluation_date, list(grid_products.values())
        )
        inputs_on_date = [
            inputs
            for inputs in lifecycle_grid()
            if inputs.evaluation_date == evaluation_date
        ]
        assert len(inputs_on_date) == len(grid_products)

        mismatches = [
            (inputs, phases[grid_products[_dates_of(inputs)]], _pure_value(inputs))
            for inputs in inputs_on_date
            if phases[grid_products[_dates_of(inputs)]] != _pure_value(inputs)
        ]

        assert mismatches == []

    async def test_expression_yields_only_phase_values_or_null(
        self, db_session: AsyncSession, grid_products: dict[DateSet, uuid.UUID]
    ) -> None:
        observed: set[str | None] = set()
        for evaluation_date in grid_evaluation_dates():
            phases = await _phases_on(
                db_session, evaluation_date, list(grid_products.values())
            )
            observed.update(phases.values())

        # Every phase and NULL occur in the grid, and nothing else does.
        assert observed == {*_PHASE_VALUES, None}


# ---------------------------------------------------------------------------
# SQL-side filtering and ordering
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLifecycleExpressionFiltering:
    @pytest.mark.parametrize(
        "evaluation_date", grid_evaluation_dates(), ids=lambda d: d.isoformat()
    )
    async def test_equality_and_null_filters_select_in_sql(
        self,
        db_session: AsyncSession,
        grid_products: dict[DateSet, uuid.UUID],
        evaluation_date: date,
    ) -> None:
        ids = list(grid_products.values())
        expected: dict[str | None, set[uuid.UUID]] = {}
        for inputs in lifecycle_grid():
            if inputs.evaluation_date == evaluation_date:
                expected.setdefault(_pure_value(inputs), set()).add(
                    grid_products[_dates_of(inputs)]
                )
        expression = lifecycle_phase_expression(evaluation_date)

        for phase in LifecyclePhase:
            selected = await _ids_where(db_session, expression == phase.value, ids)
            assert selected == expected.get(phase.value, set()), phase
        unavailable = await _ids_where(db_session, expression.is_(None), ids)
        assert unavailable == expected.get(None, set())

    async def test_expression_orders_rows_in_sql(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        evaluation_date = date(2027, 1, 1)
        await product_factory(general_support_end_date=date(2030, 1, 1))
        await product_factory(general_support_end_date=date(2020, 1, 1))
        await product_factory(first_customer_ship_date=date(2028, 1, 1))
        await product_factory()
        expression = lifecycle_phase_expression(evaluation_date)

        result = await db_session.execute(
            select(expression).order_by(expression.asc().nulls_last())
        )

        assert list(result.scalars().all()) == [
            LifecyclePhase.EOL.value,
            LifecyclePhase.GENERAL_SUPPORT.value,
            LifecyclePhase.PRE_RELEASE.value,
            None,
        ]

    async def test_expression_reads_the_supplied_alias(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        """An aliased Product (e.g. the catalog Product of a package-tree
        join) is evaluated from its own columns."""
        evaluation_date = date(2027, 1, 1)
        eol = await product_factory(general_support_end_date=date(2020, 1, 1))
        supported = await product_factory(general_support_end_date=date(2030, 1, 1))
        other = aliased(Product)

        result = await db_session.execute(
            select(
                Product.id,
                lifecycle_phase_expression(evaluation_date),
                other.id,
                lifecycle_phase_expression(evaluation_date, other),
            )
            .join(other, other.id != Product.id)
            .where(Product.id.in_([eol.id, supported.id]))
        )

        rows = {row[0]: row[1:] for row in result.all()}
        assert rows == {
            eol.id: (LifecyclePhase.EOL.value, supported.id, "general_support"),
            supported.id: (LifecyclePhase.GENERAL_SUPPORT.value, eol.id, "eol"),
        }


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestProductServiceModuleBoundary:
    def test_imports_no_other_service_module(self) -> None:
        """The Product query service may be used by `package_service` and
        other query consumers without a dependency cycle."""
        modules = imported_modules(
            APP_ROOT / "services" / "product_service.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.")} == {
            "app.core.enums",
            "app.models.product",
        }

    def test_expression_builder_is_synchronous(self) -> None:
        """Building the expression performs no I/O."""
        assert not inspect.iscoroutinefunction(
            product_service.lifecycle_phase_expression
        )
