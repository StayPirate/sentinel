"""Product query service.

Owns Product catalog read queries (`docs/features/packages/product-catalog.md`,
Product Query Service). This module provides the reusable SQL lifecycle
expression required by the Lifecycle Evaluator contract
(`docs/features/packages/product-catalog.md`, Product Lifecycle Phases,
Lifecycle Evaluator) and by Derived Actionability
(`docs/features/packages/package-model.md`, Exclusion and Actionability), so
lifecycle filters and package actionability remain database-filterable, and
`list_products()`, the read behind `GET /api/v1/products` (List Products).

The expression is the SQL form of the pure
`app.services.product_lifecycle.evaluate_product_lifecycle_phase()`; both
forms must agree for every valid, incomplete, inconsistent, and boundary-date
combination (shared matrix: `tests/support/lifecycle_matrix.py`). The lifecycle
phase is never persisted.

`list_products()` is a Category B read: it creates no row or audit event,
acquires no lock, never flushes, commits, or rolls back, and selects the
snapshot identity, rows, and total in one SQL statement, so they derive
from one coherent PostgreSQL observation. Results are semantic service
values, not Pydantic schemas; the internal `Product.id` is never projected.

This module imports no other service module except the dependency-free
`sql_patterns` leaf, so `package_service` and other query consumers may use
it without a dependency cycle.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Final

from sqlalchemy import (
    ColumnElement,
    Date,
    and_,
    case,
    false,
    func,
    literal,
    or_,
    select,
    true,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.util import AliasedClass

from app.core.enums import (
    CatalogPresence,
    LifecyclePhase,
    LifecyclePhaseFilter,
    ProductSortField,
    SortOrder,
)
from app.models.product import Product
from app.services.sql_patterns import LIKE_ESCAPE, escape_like

MAX_PER_PAGE: Final = 100
"""The largest accepted `per_page` (`docs/api-spec.md`, Pagination)."""

_CODE_POINT_COLLATION: Final = "C"
"""Collation ordering the string sort fields by Unicode code point,
independent of the database collation (product-catalog.md, List Products)."""


def lifecycle_phase_expression(
    evaluation_date: date,
    product: type[Product] | AliasedClass[Product] = Product,
) -> ColumnElement[str | None]:
    """Build the SQL lifecycle-phase expression of `product` on one date.

    `evaluation_date` is the single UTC calendar date captured by the
    calling operation for its complete set of rows, filters, counts, and
    gate predicates; it is bound as a SQL `DATE` parameter. `product` is the
    `Product` entity or an alias of it (for example, the catalog Product of
    a package-tree join); the expression reads its four lifecycle date
    columns.

    The expression yields exactly one `LifecyclePhase` value string or
    `NULL`, following the Lifecycle Evaluator: an inconsistent date set
    (an extended end without a General Support end, a reactive end without
    an extended end, or any present date later than the next present date
    of FCS <= GS end <= extended end <= reactive end) yields `NULL` for every
    date; otherwise, in order, before FCS -> `pre_release`, up to the
    inclusive GS end -> `general_support`, up to the inclusive extended end
    -> `extended_support`, up to the inclusive reactive end ->
    `reactive_support`, after the last available end date of the chain ->
    `eol`, and `NULL` in every other case.

    The expression is usable in `SELECT`, `WHERE`, and `ORDER BY`. Building
    it performs no I/O, creates no audit event, acquires no lock, and raises
    no exception; executing it propagates only database exceptions.
    """
    fcs = product.first_customer_ship_date
    gs_end = product.general_support_end_date
    extended_end = product.extended_support_end_date
    reactive_end = product.reactive_support_end_date
    on_date = literal(evaluation_date, Date())

    inconsistent = or_(
        and_(extended_end.is_not(None), gs_end.is_(None)),
        and_(reactive_end.is_not(None), extended_end.is_(None)),
        and_(fcs.is_not(None), gs_end.is_not(None), fcs > gs_end),
        and_(gs_end.is_not(None), extended_end.is_not(None), gs_end > extended_end),
        and_(
            extended_end.is_not(None),
            reactive_end.is_not(None),
            extended_end > reactive_end,
        ),
    )
    # Every date is present, and consistency holds, in each branch that
    # reads it; `COALESCE` is NULL only when no end date exists (rule 6).
    last_end_date = func.coalesce(reactive_end, extended_end, gs_end)

    # The result type is inferred from the first non-NULL branch (a string).
    phase: ColumnElement[str | None] = case(
        (inconsistent, None),
        (
            and_(fcs.is_not(None), on_date < fcs),
            LifecyclePhase.PRE_RELEASE.value,
        ),
        (
            and_(gs_end.is_not(None), on_date <= gs_end),
            LifecyclePhase.GENERAL_SUPPORT.value,
        ),
        (
            and_(extended_end.is_not(None), on_date <= extended_end),
            LifecyclePhase.EXTENDED_SUPPORT.value,
        ),
        (
            and_(reactive_end.is_not(None), on_date <= reactive_end),
            LifecyclePhase.REACTIVE_SUPPORT.value,
        ),
        (
            and_(last_end_date.is_not(None), on_date > last_end_date),
            LifecyclePhase.EOL.value,
        ),
        else_=None,
    )
    return phase


@dataclass(frozen=True, slots=True)
class ProductListItemProjection:
    """One Product of the catalog list: every public list-item field.

    `cpe` is the public Product identity; the internal `Product.id` is
    deliberately absent. `catalog_presence` and `lifecycle_phase` are
    derived from the selected snapshot and the request's
    `evaluation_date`; `lifecycle_phase` is `None` when the Lifecycle
    Evaluator cannot establish a phase. `cvss_threshold` is `None` for the
    implicit threshold of 0.
    """

    name: str
    version: str
    display_name: str
    cpe: str
    catalog_presence: CatalogPresence
    catalog_last_seen_at: datetime
    first_customer_ship_date: date | None
    general_support_end_date: date | None
    extended_support_end_date: date | None
    reactive_support_end_date: date | None
    lifecycle_phase: LifecyclePhase | None
    cvss_threshold: Decimal | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ProductPage:
    """One page of Products and the unpaginated total, both derived from
    one PostgreSQL observation of one selected catalog snapshot."""

    items: tuple[ProductListItemProjection, ...]
    total: int
    page: int
    per_page: int


def _sort_key(sort_by: ProductSortField) -> ColumnElement[Any]:
    """The primary sort expression for `sort_by` on `Product`; the string
    fields compare by Unicode code point."""
    keys: Mapping[ProductSortField, ColumnElement[Any]] = {
        ProductSortField.NAME: Product.name.collate(_CODE_POINT_COLLATION),
        ProductSortField.DISPLAY_NAME: Product.display_name.collate(
            _CODE_POINT_COLLATION
        ),
        ProductSortField.VERSION: Product.version.collate(_CODE_POINT_COLLATION),
        ProductSortField.CPE: Product.cpe.collate(_CODE_POINT_COLLATION),
        ProductSortField.CATALOG_LAST_SEEN_AT: Product.catalog_last_seen_at.expression,
        ProductSortField.CREATED_AT: Product.created_at.expression,
    }
    return keys[sort_by]


def _ordered(
    sort_key: ColumnElement[Any], row_id: ColumnElement[Any], sort_order: SortOrder
) -> tuple[ColumnElement[Any], ColumnElement[Any]]:
    """Primary order with `NULL` last in both directions, then the internal
    primary-key tie-breaker in the same direction."""
    if sort_order is SortOrder.ASC:
        return sort_key.asc().nulls_last(), row_id.asc()
    return sort_key.desc().nulls_last(), row_id.desc()


def _presence_condition(
    values: tuple[CatalogPresence, ...], snapshot_at: ColumnElement[Any]
) -> ColumnElement[bool]:
    """OR over the supplied catalog-presence values against the selected
    snapshot; no value matches nothing."""
    branches: list[ColumnElement[bool]] = []
    if CatalogPresence.CURRENT in values:
        branches.append(Product.catalog_last_seen_at == snapshot_at)
    if CatalogPresence.HISTORICAL in values:
        branches.append(Product.catalog_last_seen_at != snapshot_at)
    return or_(*branches) if branches else false()


def _lifecycle_condition(
    values: tuple[LifecyclePhaseFilter, ...], phase: ColumnElement[str | None]
) -> ColumnElement[bool]:
    """OR over the supplied lifecycle filter values; `unavailable` matches
    the evaluator's `NULL`. No value matches nothing."""
    unavailable = LifecyclePhaseFilter.UNAVAILABLE
    phases = sorted({value.value for value in values if value is not unavailable})
    branches: list[ColumnElement[bool]] = []
    if phases:
        branches.append(phase.in_(phases))
    if unavailable in values:
        branches.append(phase.is_(None))
    return or_(*branches) if branches else false()


def _search_condition(term: str) -> ColumnElement[bool]:
    """Case-insensitive substring of `name`, `display_name`, `version`, or
    `cpe`; `%`, `_`, and backslash match literally."""
    pattern = f"%{escape_like(term)}%"
    return or_(
        Product.name.ilike(pattern, escape=LIKE_ESCAPE),
        Product.display_name.ilike(pattern, escape=LIKE_ESCAPE),
        Product.version.ilike(pattern, escape=LIKE_ESCAPE),
        Product.cpe.ilike(pattern, escape=LIKE_ESCAPE),
    )


async def list_products(
    db: AsyncSession,
    *,
    evaluation_date: date,
    search: str | None = None,
    cpe: str | None = None,
    catalog_presence: tuple[CatalogPresence, ...] = (CatalogPresence.CURRENT,),
    lifecycle_phase: tuple[LifecyclePhaseFilter, ...] | None = None,
    sort_by: ProductSortField = ProductSortField.NAME,
    sort_order: SortOrder = SortOrder.ASC,
    page: int = 1,
    per_page: int = 20,
) -> ProductPage:
    """List the catalog Products of one selected snapshot, one page at a time.

    Category B read (product-catalog.md, List Products > Product Query
    Service).

    Q1: `evaluation_date` is the one UTC calendar date of the request.
    `search` is the raw substring term and `cpe` the exact CPE; `None`
    means omitted. `catalog_presence` holds the valid supplied values (the
    API default is `current` only); `lifecycle_phase` is `None` when
    omitted or the valid supplied values. An empty tuple for either
    (every supplied value was invalid) matches nothing. `page` is positive
    and `per_page` is 1-100.

    Q3: in one SQL statement, and therefore one PostgreSQL observation (a
    CTE chain: snapshot identity, filtered Products, their total, the
    requested page):
    1. captures the latest complete snapshot identity
       `MAX(Product.catalog_last_seen_at)`; when no snapshot exists, no
       row qualifies and the total is 0;
    2. applies, AND-combined: catalog presence (`current` is
       `catalog_last_seen_at` equal to the snapshot, `historical` any
       other value; OR within the filter); lifecycle phase through
       `lifecycle_phase_expression(evaluation_date)` (`unavailable` is
       its `NULL`; OR within the filter); `cpe` as an exact,
       case-sensitive match; and `search` as a case-insensitive substring
       of `name`, `display_name`, `version`, or `cpe`, with `%`, `_`, and
       backslash literal;
    3. orders by `sort_by` (`name`, `display_name`, `version`, and `cpe`
       in Unicode code-point order) with `NULL` last, then by `Product.id`
       in the same direction;
    4. counts after every filter, before paging;
    5. derives `catalog_presence` against the same snapshot and
       `lifecycle_phase` on the same `evaluation_date` as the filters.
    Creates no row or event, acquires no lock, and never flushes,
    commits, or rolls back.

    Q4: returns the page items, the total, and the echoed `page` and
    `per_page`. A page beyond the last is empty with the correct total.

    Q6: raises `ValueError` before any query for `page < 1` or
    `per_page` outside 1-100; no Product-specific exception. Database
    exceptions propagate unchanged.
    """
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")

    snapshot = select(func.max(Product.catalog_last_seen_at).label("snapshot_at")).cte(
        "snapshot"
    )
    snapshot_at = snapshot.c.snapshot_at
    phase = lifecycle_phase_expression(evaluation_date)

    conditions: list[ColumnElement[bool]] = [
        snapshot_at.is_not(None),
        _presence_condition(catalog_presence, snapshot_at),
    ]
    if lifecycle_phase is not None:
        conditions.append(_lifecycle_condition(lifecycle_phase, phase))
    if cpe is not None:
        conditions.append(Product.cpe == cpe)
    if search is not None:
        conditions.append(_search_condition(search))

    presence = case(
        (Product.catalog_last_seen_at == snapshot_at, CatalogPresence.CURRENT.value),
        else_=CatalogPresence.HISTORICAL.value,
    )
    filtered = (
        select(
            Product.id.label("id"),
            _sort_key(sort_by).label("sort_key"),
            Product.name,
            Product.version,
            Product.display_name,
            Product.cpe,
            presence.label("catalog_presence"),
            Product.catalog_last_seen_at,
            Product.first_customer_ship_date,
            Product.general_support_end_date,
            Product.extended_support_end_date,
            Product.reactive_support_end_date,
            phase.label("lifecycle_phase"),
            Product.cvss_threshold,
            Product.created_at,
            Product.updated_at,
        )
        .select_from(Product)
        .join(snapshot, true())
        .where(*conditions)
        .cte("filtered")
    )
    total = select(func.count().label("total")).select_from(filtered).cte("total")
    page_rows = (
        select(filtered)
        .order_by(*_ordered(filtered.c.sort_key, filtered.c.id, sort_order))
        .limit(per_page)
        .offset((page - 1) * per_page)
        .cte("page")
    )
    statement = (
        select(total.c.total, page_rows)
        .select_from(total)
        .outerjoin(page_rows, true())
        .order_by(*_ordered(page_rows.c.sort_key, page_rows.c.id, sort_order))
    )
    rows = (await db.execute(statement)).all()
    return ProductPage(
        items=tuple(
            ProductListItemProjection(
                name=row.name,
                version=row.version,
                display_name=row.display_name,
                cpe=row.cpe,
                catalog_presence=CatalogPresence(row.catalog_presence),
                catalog_last_seen_at=row.catalog_last_seen_at,
                first_customer_ship_date=row.first_customer_ship_date,
                general_support_end_date=row.general_support_end_date,
                extended_support_end_date=row.extended_support_end_date,
                reactive_support_end_date=row.reactive_support_end_date,
                lifecycle_phase=(
                    LifecyclePhase(row.lifecycle_phase)
                    if row.lifecycle_phase is not None
                    else None
                ),
                cvss_threshold=row.cvss_threshold,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
            if row.id is not None
        ),
        total=rows[0].total,
        page=page,
        per_page=per_page,
    )
