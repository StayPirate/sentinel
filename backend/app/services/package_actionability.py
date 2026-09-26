"""Derived package-tree actionability and delivery relevance.

Single owner of the canonical actionability predicates of
`docs/features/packages/package-model.md` (Exclusion and Actionability >
Manual Exclusion Markers, Derived Actionability, Gate Participation) and
of the `delivery_relevant` rule (Axis 3 > Delivery Relevance Indicator).

Two equivalent forms are provided:

- reusable SQL/SQLAlchemy expressions (`product_actionable_expression()`,
  `track_actionable_expression()`, `package_actionable_expression()`) for
  package-tree reads, filters, aggregate counts, and Ticket gates;
- pure Python projections of the ordered `non_actionable_reason`
  precedence per level (`product_non_actionable_reason()`,
  `track_non_actionable_reason()`, `package_non_actionable_reason()`); a
  record is actionable exactly when its reason is `None`.

Both forms must agree for every lifecycle input and marker combination
(shared matrix: `tests/support/lifecycle_matrix.py` crossed with the eight
direct-marker combinations).

Nothing here is persisted: actionability and lifecycle phase are derived
from the current package-tree `deleted_at` markers, the catalog Product's
lifecycle dates, and one UTC `evaluation_date` captured by the calling
operation for its complete response or workflow. Affectedness,
eligibility, delivery, Product release, and Ticket status are deliberately
not inputs. Every function is Category B: no database access, write,
audit, lock, or external call.

This module imports only Models, Core, and the leaf Product query service,
so `package_service`, `ticket_mutations`, and the Ticket-level deadline
expressions can all use it without a dependency cycle.
"""

from __future__ import annotations

from datetime import date

from sqlalchemy import ColumnElement, and_, exists, or_, select
from sqlalchemy.orm import aliased
from sqlalchemy.orm.util import AliasedClass

from app.core.enums import (
    DeliveryStatus,
    LifecyclePhase,
    NonActionableReason,
    PackageStatus,
)
from app.models.product import Product
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.product_service import lifecycle_phase_expression

type PackageEntity = type[TicketPackage] | AliasedClass[TicketPackage]
type TrackEntity = type[TicketPackageTrack] | AliasedClass[TicketPackageTrack]
type ProductOccurrenceEntity = (
    type[TicketPackageProduct] | AliasedClass[TicketPackageProduct]
)
type CatalogProductEntity = type[Product] | AliasedClass[Product]

_DELIVERY_RELEVANT_STATUSES = frozenset(
    {PackageStatus.ANALYSIS, PackageStatus.AFFECTED}
)


# ---------------------------------------------------------------------------
# SQL expressions
# ---------------------------------------------------------------------------


def product_actionable_expression(
    evaluation_date: date,
    *,
    package: PackageEntity = TicketPackage,
    track: TrackEntity = TicketPackageTrack,
    product: ProductOccurrenceEntity = TicketPackageProduct,
    catalog_product: CatalogProductEntity = Product,
) -> ColumnElement[bool]:
    """Build the SQL `product.actionable` predicate on one date.

    `package`, `track`, and `product` are the Product occurrence's
    ancestor chain and `catalog_product` its related catalog `Product`
    (entities or aliases); the enclosing statement joins or correlates
    them. The predicate is true exactly when all three direct
    `deleted_at` markers are NULL and the catalog Product's lifecycle
    phase on `evaluation_date` (`lifecycle_phase_expression()`) is NULL or
    not `eol`. A NULL phase is lifecycle-unavailable and actionable.

    Usable in `SELECT`, `WHERE`, and `ORDER BY`; building it performs no
    I/O and raises no exception.
    """
    phase = lifecycle_phase_expression(evaluation_date, catalog_product)
    return and_(
        package.deleted_at.is_(None),
        track.deleted_at.is_(None),
        product.deleted_at.is_(None),
        or_(phase.is_(None), phase != LifecyclePhase.EOL.value),
    )


def track_actionable_expression(
    evaluation_date: date,
    *,
    package: PackageEntity = TicketPackage,
    track: TrackEntity = TicketPackageTrack,
) -> ColumnElement[bool]:
    """Build the SQL `track.actionable` predicate on one date.

    `package` and `track` are the track and its parent package (entities
    or aliases) of the enclosing statement. The predicate is true exactly
    when both direct markers are NULL and at least one Product occurrence
    of the track satisfies `product_actionable_expression()` on the same
    date. The Product check uses existence semantics, so it never
    multiplies rows of the enclosing statement.
    """
    occurrence = aliased(TicketPackageProduct)
    catalog = aliased(Product)
    has_actionable_product = exists(
        select(occurrence.id)
        .join(catalog, catalog.id == occurrence.product_id)
        .where(
            occurrence.ticket_package_track_id == track.id,
            product_actionable_expression(
                evaluation_date,
                package=package,
                track=track,
                product=occurrence,
                catalog_product=catalog,
            ),
        )
        .correlate_except(occurrence, catalog)
    )
    return and_(
        package.deleted_at.is_(None),
        track.deleted_at.is_(None),
        has_actionable_product,
    )


def package_actionable_expression(
    evaluation_date: date,
    *,
    package: PackageEntity = TicketPackage,
) -> ColumnElement[bool]:
    """Build the SQL `package.actionable` predicate on one date.

    `package` is the package entity or alias of the enclosing statement.
    The predicate is true exactly when its direct marker is NULL and at
    least one of its tracks satisfies `track_actionable_expression()` on
    the same date, using existence semantics.
    """
    track = aliased(TicketPackageTrack)
    has_actionable_track = exists(
        select(track.id)
        .where(
            track.ticket_package_id == package.id,
            track_actionable_expression(evaluation_date, package=package, track=track),
        )
        .correlate_except(track)
    )
    return and_(package.deleted_at.is_(None), has_actionable_track)


# ---------------------------------------------------------------------------
# Pure projections
# ---------------------------------------------------------------------------


def product_non_actionable_reason(
    *,
    package_excluded: bool,
    track_excluded: bool,
    product_excluded: bool,
    lifecycle_phase: LifecyclePhase | None,
) -> NonActionableReason | None:
    """Return the first applicable Product `non_actionable_reason`.

    Each `*_excluded` flag states whether that record's own direct
    `deleted_at` marker is set; `lifecycle_phase` is the catalog
    Product's phase on the response's `evaluation_date` (`None` when
    unavailable). Precedence: `package_excluded`, `track_excluded`,
    `product_excluded`, `eol`. Returns `None` when the Product is
    actionable. Infallible.
    """
    if package_excluded:
        return NonActionableReason.PACKAGE_EXCLUDED
    if track_excluded:
        return NonActionableReason.TRACK_EXCLUDED
    if product_excluded:
        return NonActionableReason.PRODUCT_EXCLUDED
    if lifecycle_phase is LifecyclePhase.EOL:
        return NonActionableReason.EOL
    return None


def track_non_actionable_reason(
    *,
    package_excluded: bool,
    track_excluded: bool,
    has_actionable_product: bool,
) -> NonActionableReason | None:
    """Return the first applicable track `non_actionable_reason`.

    Precedence: `package_excluded`, `track_excluded`,
    `no_actionable_products`. `has_actionable_product` states whether any
    Product occurrence of the track is actionable on the same date.
    Returns `None` when the track is actionable. Infallible.
    """
    if package_excluded:
        return NonActionableReason.PACKAGE_EXCLUDED
    if track_excluded:
        return NonActionableReason.TRACK_EXCLUDED
    if not has_actionable_product:
        return NonActionableReason.NO_ACTIONABLE_PRODUCTS
    return None


def package_non_actionable_reason(
    *,
    package_excluded: bool,
    has_actionable_track: bool,
) -> NonActionableReason | None:
    """Return the first applicable package `non_actionable_reason`.

    Precedence: `package_excluded`, `no_actionable_tracks`.
    `has_actionable_track` states whether any track of the package is
    actionable on the same date. Returns `None` when the package is
    actionable. Infallible.
    """
    if package_excluded:
        return NonActionableReason.PACKAGE_EXCLUDED
    if not has_actionable_track:
        return NonActionableReason.NO_ACTIONABLE_TRACKS
    return None


def is_delivery_relevant(
    track_status: PackageStatus, delivery_status: DeliveryStatus
) -> bool:
    """Return the computed `delivery_relevant` API field of one track.

    True when the affectedness is `ANALYSIS` or `AFFECTED`, or the
    delivery status has moved beyond the `PENDING` default
    (package-model.md, Delivery Relevance Indicator). Never persisted.
    Infallible.
    """
    return (
        track_status in _DELIVERY_RELEVANT_STATUSES
        or delivery_status is not DeliveryStatus.PENDING
    )
