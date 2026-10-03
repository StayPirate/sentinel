"""`sync_smelt_products`: SMELT Product catalog synchronization fetcher.

Implements docs/features/packages/product-catalog.md (SMELT Integration >
Product Sync; Catalog Readiness and Freshness; Fetcher:
`sync_smelt_products`). Each run retrieves the complete paginated SMELT
Product listing before any database work, validates the complete
snapshot, and publishes it atomically in one transaction with one shared
`snapshot_at`:

- Products are upserted by exact CPE and repository associations by
  `(product_id, repo_name)`. Only the SMELT-owned descriptive fields and
  `catalog_last_seen_at` are written; AIMAAS-owned lifecycle and threshold
  columns are never touched.
- Products and associations absent from the snapshot are retained with
  their previous `catalog_last_seen_at`. The applied snapshot, and with
  it catalog readiness, is derived from `MAX(Product.catalog_last_seen_at)`.
- Any failure publishes nothing and leaves the last committed snapshot
  current. The publication creates no Ticket audit event
  (ticket-audit-log.md, Canonical Mutation and No-Event Matrix).

Product Sync steps 6 (newly-current retention) and 8 (post-commit Product
catalog backfill enqueue) are not implemented here; they land with the
backfill task and `add_package_to_ticket()` (#761 H3).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import String, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.external_strings import contains_nul
from app.models.product import Product
from app.models.product_repository import ProductRepository
from app.services.base_fetcher import BaseFetcher, FetcherError
from app.services.packages.smelt_product_listing import (
    SmeltProductListing,
    fetch_product_listing,
)

logger = structlog.get_logger(__name__)

VALIDATION_FAILED_MESSAGE = "SMELT Product catalog validation failed"
PUBLICATION_FAILED_MESSAGE = "Failed to publish SMELT Product catalog"

# PostgreSQL `timestamptz` resolution: the smallest representable increment
# used to keep every complete publication strictly newer (step 4).
_SNAPSHOT_INCREMENT = timedelta(microseconds=1)

# Rows per INSERT statement, far below the PostgreSQL bind-parameter limit.
_UPSERT_CHUNK_SIZE = 1000


def _column_length(column: Any) -> int:
    column_type = column.type
    if not isinstance(column_type, String) or column_type.length is None:
        raise TypeError(f"{column} is not a bounded string column")
    return column_type.length


# Persisted column lengths bound the validated source values (step 2).
_NAME_MAX_LENGTH = _column_length(Product.__table__.c.name)
_VERSION_MAX_LENGTH = _column_length(Product.__table__.c.version)
_CPE_MAX_LENGTH = _column_length(Product.__table__.c.cpe)
_DISPLAY_NAME_MAX_LENGTH = _column_length(Product.__table__.c.display_name)
_REPO_NAME_MAX_LENGTH = _column_length(ProductRepository.__table__.c.repo_name)


@dataclass(frozen=True, slots=True)
class CatalogProduct:
    """One validated SMELT Product, values preserved exactly as received."""

    cpe: str
    name: str
    version: str
    display_name: str
    repos: tuple[str, ...]


class SnapshotValidationError(Exception):
    """The complete snapshot violates Product Sync step 2.

    The message names the validation category and row position only; it
    never contains source values.
    """


def validate_snapshot(listing: SmeltProductListing) -> list[CatalogProduct]:
    """Validate the complete snapshot (Product Sync step 2).

    Any invalid row rejects the complete snapshot; rows are never skipped.
    Unknown and ignored fields (`id`, `end_of_life`, `changed`, `details`)
    are not inspected.
    """
    if listing.count <= 0:
        raise SnapshotValidationError("count must be greater than zero")

    products: list[CatalogProduct] = []
    seen_cpes: set[str] = set()
    for position, row in enumerate(listing.results):
        product = CatalogProduct(
            cpe=_required_string(row, "cpe", _CPE_MAX_LENGTH, position),
            name=_required_string(row, "name", _NAME_MAX_LENGTH, position),
            version=_required_string(row, "version", _VERSION_MAX_LENGTH, position),
            display_name=_required_string(
                row, "friendly_name", _DISPLAY_NAME_MAX_LENGTH, position
            ),
            repos=_repositories(row, position),
        )
        if product.cpe in seen_cpes:
            raise SnapshotValidationError(f"row {position}: duplicate cpe")
        seen_cpes.add(product.cpe)
        products.append(product)
    return products


def _required_string(
    row: dict[str, Any], field: str, max_length: int, position: int
) -> str:
    value = row.get(field)
    if not isinstance(value, str) or value == "":
        raise SnapshotValidationError(
            f"row {position}: {field} must be a non-empty string"
        )
    if len(value) > max_length:
        raise SnapshotValidationError(
            f"row {position}: {field} exceeds {max_length} characters"
        )
    if contains_nul(value):
        raise SnapshotValidationError(f"row {position}: {field} contains U+0000")
    return value


def _repositories(row: dict[str, Any], position: int) -> tuple[str, ...]:
    repos = row.get("repos")
    if not isinstance(repos, list) or not repos:
        raise SnapshotValidationError(
            f"row {position}: repos must be a non-empty array"
        )
    seen: set[str] = set()
    for repo in repos:
        if not isinstance(repo, str) or repo == "":
            raise SnapshotValidationError(
                f"row {position}: repos must contain non-empty strings"
            )
        if len(repo) > _REPO_NAME_MAX_LENGTH:
            raise SnapshotValidationError(
                f"row {position}: repository exceeds {_REPO_NAME_MAX_LENGTH} characters"
            )
        if contains_nul(repo):
            raise SnapshotValidationError(f"row {position}: repository contains U+0000")
        if repo in seen:
            raise SnapshotValidationError(f"row {position}: repeated repository")
        seen.add(repo)
    return tuple(repos)


@dataclass(frozen=True, slots=True)
class PublicationOutcome:
    """Work-unit accounting of one committed publication (§ Metrics)."""

    snapshot_at: datetime
    selected: int
    created: int
    updated: int


@dataclass(frozen=True, slots=True)
class _ExistingProduct:
    id: Any
    name: str
    version: str
    display_name: str
    current: bool


def _utc_now() -> datetime:
    """Clock seam for the snapshot timestamp (step 3)."""
    return datetime.now(UTC)


async def publish_snapshot(
    session: AsyncSession, products: Sequence[CatalogProduct], snapshot_at: datetime
) -> PublicationOutcome:
    """Publish one validated snapshot and commit once (steps 4, 5, and 7).

    `session` must have no open transaction and no pending work; the
    publication transaction begins here and is committed before return.
    A database error propagates before the commit succeeds, so no partial
    publication becomes durable; the caller rolls the session back
    (`BaseFetcher.run()` does so for `execute()`).
    """
    existing_rows = (
        await session.execute(
            select(
                Product.id,
                Product.cpe,
                Product.name,
                Product.version,
                Product.display_name,
                Product.catalog_last_seen_at,
            )
        )
    ).all()
    previous_snapshot_at = max(
        (row.catalog_last_seen_at for row in existing_rows), default=None
    )
    existing = {
        row.cpe: _ExistingProduct(
            id=row.id,
            name=row.name,
            version=row.version,
            display_name=row.display_name,
            current=row.catalog_last_seen_at == previous_snapshot_at,
        )
        for row in existing_rows
    }

    previous_associations: dict[Any, set[str]] = {}
    if previous_snapshot_at is not None:
        if snapshot_at <= previous_snapshot_at:
            snapshot_at = previous_snapshot_at + _SNAPSHOT_INCREMENT
        association_rows = await session.execute(
            select(ProductRepository.product_id, ProductRepository.repo_name).where(
                ProductRepository.catalog_last_seen_at == previous_snapshot_at
            )
        )
        for product_id, repo_name in association_rows:
            previous_associations.setdefault(product_id, set()).add(repo_name)

    product_ids = await _upsert_products(session, products, snapshot_at)
    await _upsert_associations(session, products, product_ids, snapshot_at)
    await session.commit()

    previous_cpes = {cpe for cpe, product in existing.items() if product.current}
    incoming = {product.cpe: product for product in products}
    created = 0
    updated = 0
    for cpe in previous_cpes | incoming.keys():
        prior = existing.get(cpe)
        if prior is None:
            created += 1
        elif _projection_changed(
            prior,
            incoming.get(cpe),
            previous_associations.get(prior.id, set()),
        ):
            updated += 1
    return PublicationOutcome(
        snapshot_at=snapshot_at,
        selected=len(previous_cpes | incoming.keys()),
        created=created,
        updated=updated,
    )


def _projection_changed(
    prior: _ExistingProduct,
    product: CatalogProduct | None,
    previous_repos: set[str],
) -> bool:
    """Whether an already-persisted Product's current-catalog projection changed.

    Entering or leaving the current snapshot, a descriptive field change,
    or a current repository-association set change counts; repository
    order and a timestamp-only advance do not.
    """
    if product is None or not prior.current:
        # Left the current snapshot, or (re-)entered it.
        return True
    return (prior.name, prior.version, prior.display_name) != (
        product.name,
        product.version,
        product.display_name,
    ) or previous_repos != set(product.repos)


def _chunks(rows: list[dict[str, Any]]) -> Iterable[list[dict[str, Any]]]:
    for start in range(0, len(rows), _UPSERT_CHUNK_SIZE):
        yield rows[start : start + _UPSERT_CHUNK_SIZE]


async def _upsert_products(
    session: AsyncSession, products: Sequence[CatalogProduct], snapshot_at: datetime
) -> dict[str, Any]:
    """Upsert Products by exact CPE; return the CPE → Product ID map."""
    rows = [
        {
            "cpe": product.cpe,
            "name": product.name,
            "version": product.version,
            "display_name": product.display_name,
            "catalog_last_seen_at": snapshot_at,
        }
        for product in products
    ]
    product_ids: dict[str, Any] = {}
    for chunk in _chunks(rows):
        insert_statement = pg_insert(Product).values(chunk)
        excluded = insert_statement.excluded
        statement = insert_statement.on_conflict_do_update(
            index_elements=[Product.cpe],
            set_={
                "name": excluded.name,
                "version": excluded.version,
                "display_name": excluded.display_name,
                "catalog_last_seen_at": excluded.catalog_last_seen_at,
                "updated_at": func.now(),
            },
        ).returning(Product.cpe, Product.id)
        for cpe, product_id in await session.execute(statement):
            product_ids[cpe] = product_id
    return product_ids


async def _upsert_associations(
    session: AsyncSession,
    products: Sequence[CatalogProduct],
    product_ids: dict[str, Any],
    snapshot_at: datetime,
) -> None:
    """Upsert repository associations by `(product_id, repo_name)`."""
    rows = [
        {
            "product_id": product_ids[product.cpe],
            "repo_name": repo,
            "catalog_last_seen_at": snapshot_at,
        }
        for product in products
        for repo in product.repos
    ]
    for chunk in _chunks(rows):
        statement = pg_insert(ProductRepository).values(chunk)
        excluded = statement.excluded
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[
                    ProductRepository.product_id,
                    ProductRepository.repo_name,
                ],
                set_={
                    "catalog_last_seen_at": excluded.catalog_last_seen_at,
                    "updated_at": func.now(),
                },
            )
        )


class SyncSmeltProducts(BaseFetcher):
    """Synchronize the complete SMELT Product catalog and repository associations."""

    name = "sync_smelt_products"
    description = (
        "Synchronize the complete SMELT Product catalog and repository associations"
    )
    default_schedule = "0 1 * * *"

    async def execute(self, session: AsyncSession) -> None:
        # Step 1: all network I/O completes before any database work.
        request_delay = self.config.request_delay if self.config is not None else 0.0
        listing = await fetch_product_listing(
            self.http_client,
            api_url=settings.smelt_api_url,
            request_delay=request_delay,
        )

        # Step 2: complete-snapshot validation.
        try:
            products = validate_snapshot(listing)
        except SnapshotValidationError as exc:
            logger.warning("smelt_product_catalog_validation_failed", category=str(exc))
            raise FetcherError(VALIDATION_FAILED_MESSAGE) from exc

        # Steps 3-5 and 7: one snapshot timestamp, atomic publication.
        try:
            outcome = await publish_snapshot(session, products, _utc_now())
        except SQLAlchemyError as exc:
            logger.warning("smelt_product_catalog_publication_failed")
            raise FetcherError(PUBLICATION_FAILED_MESSAGE) from exc

        # Terminal outcomes and effects only after the commit (§ Metrics).
        self.record_succeeded(outcome.selected)
        self.record_created(outcome.created)
        self.record_updated(outcome.updated)
        logger.info(
            "smelt_product_catalog_published",
            products=len(products),
            selected=outcome.selected,
            created=outcome.created,
            updated=outcome.updated,
        )
