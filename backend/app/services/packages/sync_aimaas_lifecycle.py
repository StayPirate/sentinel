"""`sync_aimaas_lifecycle`: AIMAAS Product lifecycle synchronization fetcher.

Implements docs/features/packages/product-catalog.md (AIMAAS Integration >
Product Lifecycle Sync; Fetcher: `sync_aimaas_lifecycle`). Each run
retrieves the complete default AIMAAS Product list with `all_fields=true`
before any database work, validates the complete response, and publishes
the lifecycle projection of every exactly CPE-matched local Product in one
transaction:

- `first_customer_ship_date` from `fcs`, `general_support_end_date` from
  `end_of_gs`, `extended_support_end_date` from the later non-null value of
  `end_of_ltss` and `end_of_espos`, and `reactive_support_end_date` from
  `end_of_reactive_ltss`; a source date becoming null clears the column.
- Only those four columns (and `updated_at`) are written: never the
  SMELT-owned descriptive or catalog-observation fields or
  `cvss_threshold`. Products absent from AIMAAS keep their dates; AIMAAS
  entries without a local match, including entries with a null or empty
  `cpe`, are ignored without heuristics.
- After the commit, one `product_lifecycle_dates_inconsistent` WARNING is
  logged per violated Lifecycle Evaluator rule of each matched Product.

Lifecycle synchronization never mutates eligibility, exclusion, or Ticket
status and creates no Ticket audit event (product-lifecycle-transitions.md,
Integration with AIMAAS Synchronization; ticket-audit-log.md, Canonical
Mutation and No-Event Matrix); `evaluate_lifecycle_transitions` reconciles
their effects.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any

import structlog
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.product import Product
from app.services.base_fetcher import BaseFetcher, FetcherError
from app.services.packages.aimaas_listing import fetch_aimaas_products
from app.services.product_lifecycle import (
    LifecycleDateViolation,
    lifecycle_date_violations,
)

logger = structlog.get_logger(__name__)

INVALID_RESPONSE_MESSAGE = "AIMAAS returned invalid Product lifecycle response"
VALIDATION_FAILED_MESSAGE = "AIMAAS Product lifecycle validation failed"
PUBLICATION_FAILED_MESSAGE = "Failed to synchronize AIMAAS lifecycle dates"

_DATE_FIELDS = (
    "fcs",
    "end_of_gs",
    "end_of_ltss",
    "end_of_espos",
    "end_of_reactive_ltss",
)
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

# CPEs per matching SELECT, far below the PostgreSQL bind-parameter limit.
_SELECT_CHUNK_SIZE = 1000


@dataclass(frozen=True, slots=True)
class LifecycleDates:
    """The four-column lifecycle-date projection of one Product."""

    first_customer_ship_date: date | None
    general_support_end_date: date | None
    extended_support_end_date: date | None
    reactive_support_end_date: date | None

    def violations(self) -> tuple[LifecycleDateViolation, ...]:
        """The Lifecycle Evaluator consistency rules these dates violate."""
        return lifecycle_date_violations(
            first_customer_ship_date=self.first_customer_ship_date,
            general_support_end_date=self.general_support_end_date,
            extended_support_end_date=self.extended_support_end_date,
            reactive_support_end_date=self.reactive_support_end_date,
        )


@dataclass(frozen=True, slots=True)
class LifecycleEntry:
    """One schema-valid AIMAAS Product entry: its `cpe` and projection.

    `cpe` is `None` for an entry whose upstream `cpe` is null or empty;
    such an entry cannot match a local Product.
    """

    cpe: str | None
    dates: LifecycleDates


class LifecycleResponseError(Exception):
    """An AIMAAS Product entry violates the consumed response schema.

    The message names the entry position and field only; it never
    contains source values.
    """


class LifecycleValidationError(Exception):
    """The complete AIMAAS Product list violates step 2 (duplicate `cpe`).

    The message names the validation category and entry position only.
    """


def parse_lifecycle_entries(items: Sequence[dict[str, Any]]) -> list[LifecycleEntry]:
    """Parse the consumed fields of every AIMAAS Product entry.

    Every entry must carry the `cpe` key (a string or null) and the five
    consumed date keys (an ISO `YYYY-MM-DD` calendar date or null); unknown
    and ignored fields are not inspected. A null or empty `cpe` yields an
    unmatchable entry.
    """
    entries: list[LifecycleEntry] = []
    for position, item in enumerate(items):
        if "cpe" not in item:
            raise LifecycleResponseError(f"item {position}: cpe is missing")
        cpe = item["cpe"]
        if cpe is not None and not isinstance(cpe, str):
            raise LifecycleResponseError(f"item {position}: cpe must be a string")
        fcs, end_of_gs, end_of_ltss, end_of_espos, end_of_reactive_ltss = (
            _date(item, field, position) for field in _DATE_FIELDS
        )
        extended = [value for value in (end_of_ltss, end_of_espos) if value is not None]
        entries.append(
            LifecycleEntry(
                cpe=cpe or None,
                dates=LifecycleDates(
                    first_customer_ship_date=fcs,
                    general_support_end_date=end_of_gs,
                    extended_support_end_date=max(extended, default=None),
                    reactive_support_end_date=end_of_reactive_ltss,
                ),
            )
        )
    return entries


def _date(item: dict[str, Any], field: str, position: int) -> date | None:
    if field not in item:
        raise LifecycleResponseError(f"item {position}: {field} is missing")
    value = item[field]
    if value is None:
        return None
    if not isinstance(value, str) or _ISO_DATE.fullmatch(value) is None:
        raise LifecycleResponseError(f"item {position}: {field} is not a date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise LifecycleResponseError(
            f"item {position}: {field} is not a date"
        ) from None


def validate_lifecycle_entries(
    entries: Iterable[LifecycleEntry],
) -> dict[str, LifecycleDates]:
    """Reject duplicate non-empty CPEs; return the CPE → projection map.

    Unmatchable entries (null or empty `cpe`) do not participate.
    """
    projections: dict[str, LifecycleDates] = {}
    for position, entry in enumerate(entries):
        if entry.cpe is None:
            continue
        if entry.cpe in projections:
            raise LifecycleValidationError(f"item {position}: duplicate cpe")
        projections[entry.cpe] = entry.dates
    return projections


@dataclass(frozen=True, slots=True)
class PublicationOutcome:
    """Work-unit accounting of one committed publication (§ Metrics).

    `published` maps each matched local Product's CPE to its committed
    projection, in CPE order.
    """

    published: dict[str, LifecycleDates]
    updated: int

    @property
    def selected(self) -> int:
        return len(self.published)


async def publish_lifecycle_dates(
    session: AsyncSession, projections: Mapping[str, LifecycleDates]
) -> PublicationOutcome:
    """Publish the projection of every matched local Product; commit once.

    `session` must have no open transaction and no pending work; the
    publication transaction begins here and is committed before return,
    also when nothing matched or changed. Only Products whose four-column
    projection differs are written. A database error propagates before
    the commit succeeds, so no partial publication becomes durable; the
    caller rolls the session back (`BaseFetcher.run()` does so for
    `execute()`).
    """
    cpes = sorted(projections)
    current: dict[str, tuple[Any, LifecycleDates]] = {}
    for start in range(0, len(cpes), _SELECT_CHUNK_SIZE):
        rows = await session.execute(
            select(
                Product.id,
                Product.cpe,
                Product.first_customer_ship_date,
                Product.general_support_end_date,
                Product.extended_support_end_date,
                Product.reactive_support_end_date,
            ).where(Product.cpe.in_(cpes[start : start + _SELECT_CHUNK_SIZE]))
        )
        for row in rows:
            current[row.cpe] = (
                row.id,
                LifecycleDates(
                    first_customer_ship_date=row.first_customer_ship_date,
                    general_support_end_date=row.general_support_end_date,
                    extended_support_end_date=row.extended_support_end_date,
                    reactive_support_end_date=row.reactive_support_end_date,
                ),
            )

    # ORM bulk UPDATE by primary key: one executemany statement writing
    # only the four lifecycle columns; `updated_at` follows its `onupdate`.
    changes = [
        {
            "id": product_id,
            "first_customer_ship_date": projections[cpe].first_customer_ship_date,
            "general_support_end_date": projections[cpe].general_support_end_date,
            "extended_support_end_date": projections[cpe].extended_support_end_date,
            "reactive_support_end_date": projections[cpe].reactive_support_end_date,
        }
        for cpe, (product_id, stored) in current.items()
        if stored != projections[cpe]
    ]
    if changes:
        await session.execute(update(Product), changes)
    await session.commit()

    return PublicationOutcome(
        published={cpe: projections[cpe] for cpe in sorted(current)},
        updated=len(changes),
    )


class SyncAimaasLifecycle(BaseFetcher):
    """Synchronize AIMAAS Product lifecycle dates."""

    name = "sync_aimaas_lifecycle"
    description = "Synchronize AIMAAS Product lifecycle dates"
    default_schedule = "15 2 * * *"

    async def execute(self, session: AsyncSession) -> None:
        # Step 1: all network I/O completes before any database work.
        request_delay = self.config.request_delay if self.config is not None else 0.0
        listing = await fetch_aimaas_products(
            self.http_client,
            api_url=settings.aimaas_api_url,
            request_delay=request_delay,
            invalid_message=INVALID_RESPONSE_MESSAGE,
        )
        try:
            entries = parse_lifecycle_entries(listing.items)
        except LifecycleResponseError as exc:
            logger.warning(
                "aimaas_product_lifecycle_response_invalid", category=str(exc)
            )
            raise FetcherError(INVALID_RESPONSE_MESSAGE) from exc

        # Step 2: complete-response validation.
        try:
            projections = validate_lifecycle_entries(entries)
        except LifecycleValidationError as exc:
            logger.warning(
                "aimaas_product_lifecycle_validation_failed", category=str(exc)
            )
            raise FetcherError(VALIDATION_FAILED_MESSAGE) from exc

        # Steps 3-8: exact CPE matching and one atomic publication.
        try:
            outcome = await publish_lifecycle_dates(session, projections)
        except SQLAlchemyError as exc:
            logger.warning("aimaas_product_lifecycle_publication_failed")
            raise FetcherError(PUBLICATION_FAILED_MESSAGE) from exc

        # Terminal outcomes and effects only after the commit (§ Metrics).
        self.record_succeeded(outcome.selected)
        self.record_updated(outcome.updated)

        # Inconsistency warnings describe published state only.
        inconsistent = 0
        for cpe, dates in outcome.published.items():
            violations = dates.violations()
            if violations:
                inconsistent += 1
            for reason in violations:
                logger.warning(
                    "product_lifecycle_dates_inconsistent",
                    product_cpe=cpe,
                    reason=reason.value,
                )
        logger.info(
            "aimaas_product_lifecycle_published",
            aimaas_products=len(entries),
            selected=outcome.selected,
            updated=outcome.updated,
            inconsistent=inconsistent,
        )
