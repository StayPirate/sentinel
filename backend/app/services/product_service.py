"""Product query service.

Owns Product catalog read queries (`docs/features/packages/product-catalog.md`,
Product Query Service). This module currently provides the reusable SQL
lifecycle expression required by the Lifecycle Evaluator contract
(`docs/features/packages/product-catalog.md`, Product Lifecycle Phases,
Lifecycle Evaluator) and by Derived Actionability
(`docs/features/packages/package-model.md`, Exclusion and Actionability), so
lifecycle filters and package actionability remain database-filterable.

The expression is the SQL form of the pure
`app.services.product_lifecycle.evaluate_product_lifecycle_phase()`; both
forms must agree for every valid, incomplete, inconsistent, and boundary-date
combination (shared matrix: `tests/support/lifecycle_matrix.py`). The lifecycle
phase is never persisted.

This module imports no other service module, so `package_service` and other
query consumers may use it without a dependency cycle.
"""

from __future__ import annotations

from datetime import date

from sqlalchemy import ColumnElement, Date, and_, case, func, literal, or_
from sqlalchemy.orm.util import AliasedClass

from app.core.enums import LifecyclePhase
from app.models.product import Product


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
