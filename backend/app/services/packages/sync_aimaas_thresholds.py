"""`sync_aimaas_thresholds`: AIMAAS Product CVSS threshold synchronization.

Implements docs/features/packages/product-catalog.md (AIMAAS Integration >
CVSS Threshold Sync; Fetcher: `sync_aimaas_thresholds`). Each run:

1. retrieves the complete default AIMAAS Product list (`all_fields=true`)
   and the complete threshold list before any database work, and parses
   their consumed fields (Product `id` and `cpe`; threshold `product` and
   `threshold`);
2. validates the complete response (no duplicate `id`, non-empty `cpe`, or
   `product`; every `threshold` a number representable at one decimal
   place within `[0.0, 10.0]`) before any change;
3. resolves each threshold's AIMAAS Product ID to its CPE through the
   in-memory join (an unresolved ID is a structured warning and skip; a
   null or empty `cpe` and a CPE with no local Product are silent skips);
4. publishes in one transaction: only `Product.cvss_threshold` is written,
   for exactly CPE-matched Products whose value differs and for local
   Products whose non-null threshold is absent from the resolved set
   (cleared to NULL), then commits once;
5. after the commit, scans the operable package trees for eligibility
   mismatches with one UTC `evaluation_date`, then enqueues one
   `re_evaluate_product_eligibility(reason="threshold")` per Product in the
   union of the changed and mismatch sets. A dispatch failure is logged
   with the Product ID, counted as a failed unit, and later Products
   continue; the committed thresholds remain.

Threshold synchronization creates no Ticket audit event: Ticket-side
effects happen only in the dispatched task's per-Ticket recalculation
(ticket-audit-log.md, Canonical Mutation and No-Event Matrix).
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any, Final

import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.product import Product
from app.services.base_fetcher import BaseFetcher, FetcherError
from app.services.packages.aimaas_listing import (
    fetch_aimaas_listing,
    fetch_aimaas_products,
    item_cpe,
)
from app.services.packages.product_eligibility_mismatch import (
    find_product_eligibility_mismatches,
)
from app.services.packages.product_eligibility_recalculation import (
    dispatch_product_eligibility_recalculation,
)

logger = structlog.get_logger(__name__)

THRESHOLDS_ENDPOINT_PATH: Final = "entity/cvss-threshold"

INVALID_PRODUCT_LIST_MESSAGE: Final = "AIMAAS returned invalid Product list response"
INVALID_THRESHOLD_LIST_MESSAGE: Final = (
    "AIMAAS returned invalid CVSS threshold response"
)
VALIDATION_FAILED_MESSAGE: Final = "AIMAAS CVSS threshold validation failed"
PUBLICATION_FAILED_MESSAGE: Final = "Failed to synchronize AIMAAS CVSS thresholds"

_PRODUCTS_COLLECTION: Final = "products"
_THRESHOLDS_COLLECTION: Final = "cvss_thresholds"
_MIN_THRESHOLD: Final = Decimal("0.0")
_MAX_THRESHOLD: Final = Decimal("10.0")
_ONE_DECIMAL: Final = Decimal("0.1")

# CPEs per matching SELECT, far below the PostgreSQL bind-parameter limit.
_SELECT_CHUNK_SIZE: Final = 1000


class ThresholdResponseError(Exception):
    """An AIMAAS entry violates the consumed response schema.

    The message names the entry position and field only; it never contains
    source values.
    """


class ThresholdValidationError(Exception):
    """The complete retrieved response violates CVSS Threshold Sync step 2.

    The message names the validation category and entry position only.
    """


@dataclass(frozen=True, slots=True)
class AimaasProductRef:
    """One AIMAAS Product entry: its ID and matchable `cpe` (or `None`)."""

    id: int
    cpe: str | None


@dataclass(frozen=True, slots=True)
class ThresholdEntry:
    """One AIMAAS threshold entry; `threshold` is validated in step 2."""

    product: int
    threshold: Any


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_product_refs(items: Sequence[dict[str, Any]]) -> list[AimaasProductRef]:
    """Parse the `id` and `cpe` of every AIMAAS Product entry.

    Both keys must be present; `id` must be an integer and `cpe` a string or
    null (a null or empty `cpe` is unmatchable). Unknown and ignored fields
    are not inspected.
    """
    refs: list[AimaasProductRef] = []
    for position, item in enumerate(items):
        if "id" not in item:
            raise ThresholdResponseError(f"item {position}: id is missing")
        if not _is_integer(item["id"]):
            raise ThresholdResponseError(f"item {position}: id must be an integer")
        refs.append(
            AimaasProductRef(
                id=item["id"], cpe=item_cpe(item, position, ThresholdResponseError)
            )
        )
    return refs


def parse_threshold_entries(items: Sequence[dict[str, Any]]) -> list[ThresholdEntry]:
    """Parse the `product` and `threshold` of every AIMAAS threshold entry.

    Both keys must be present and `product` must be an integer; the
    `threshold` value is checked by the complete-response validation.
    """
    entries: list[ThresholdEntry] = []
    for position, item in enumerate(items):
        for field in ("product", "threshold"):
            if field not in item:
                raise ThresholdResponseError(f"item {position}: {field} is missing")
        if not _is_integer(item["product"]):
            raise ThresholdResponseError(f"item {position}: product must be an integer")
        entries.append(
            ThresholdEntry(product=item["product"], threshold=item["threshold"])
        )
    return entries


def threshold_value(value: Any) -> Decimal | None:
    """The persisted `DECIMAL(3,1)` value of a valid threshold, else `None`.

    Valid: a finite JSON number (not a boolean) exactly representable at one
    decimal place within `[0.0, 10.0]`.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    number = Decimal(repr(value)) if isinstance(value, float) else Decimal(value)
    if not _MIN_THRESHOLD <= number <= _MAX_THRESHOLD:
        return None
    quantized = number.quantize(_ONE_DECIMAL)
    return quantized if quantized == number else None


@dataclass(frozen=True, slots=True)
class ValidatedResponse:
    """The validated join inputs of one run."""

    cpe_by_product_id: dict[int, str | None]
    thresholds: list[tuple[int, Decimal]]


def validate_response(
    products: Sequence[AimaasProductRef], thresholds: Sequence[ThresholdEntry]
) -> ValidatedResponse:
    """Apply CVSS Threshold Sync step 2 to the complete retrieved response."""
    cpe_by_product_id: dict[int, str | None] = {}
    seen_cpes: set[str] = set()
    for position, product in enumerate(products):
        if product.id in cpe_by_product_id:
            raise ThresholdValidationError(f"product {position}: duplicate id")
        if product.cpe is not None:
            if product.cpe in seen_cpes:
                raise ThresholdValidationError(f"product {position}: duplicate cpe")
            seen_cpes.add(product.cpe)
        cpe_by_product_id[product.id] = product.cpe

    validated: list[tuple[int, Decimal]] = []
    seen_products: set[int] = set()
    for position, entry in enumerate(thresholds):
        if entry.product in seen_products:
            raise ThresholdValidationError(f"threshold {position}: duplicate product")
        seen_products.add(entry.product)
        value = threshold_value(entry.threshold)
        if value is None:
            raise ThresholdValidationError(
                f"threshold {position}: threshold out of range"
            )
        validated.append((entry.product, value))
    return ValidatedResponse(cpe_by_product_id=cpe_by_product_id, thresholds=validated)


def resolve_thresholds(response: ValidatedResponse) -> dict[str, Decimal]:
    """Resolve each threshold's AIMAAS Product ID to its CPE (steps 3-4).

    An ID absent from the Product list is skipped with one structured
    warning; an entry whose Product has a null or empty `cpe` is silently
    unmatchable. Returns the resolved CPE → threshold mapping.
    """
    resolved: dict[str, Decimal] = {}
    for product_id, value in response.thresholds:
        if product_id not in response.cpe_by_product_id:
            logger.warning(
                "aimaas_cvss_threshold_product_unresolved",
                aimaas_product_id=product_id,
            )
            continue
        cpe = response.cpe_by_product_id[product_id]
        if cpe is not None:
            resolved[cpe] = value
    return resolved


@dataclass(frozen=True, slots=True)
class ThresholdPublication:
    """Committed outcome of one threshold publication.

    `evaluated` holds every local Product matched by a resolved threshold or
    evaluated for absence clearing; `changed` those whose threshold mutation
    or clearing committed.
    """

    evaluated: frozenset[uuid.UUID]
    changed: frozenset[uuid.UUID]


async def publish_thresholds(
    session: AsyncSession, thresholds: Mapping[str, Decimal]
) -> ThresholdPublication:
    """Publish the resolved thresholds of every matched local Product; commit.

    `session` must have no open transaction and no pending work; the
    publication transaction begins here and is committed once before
    return, also when nothing changed. Only `cvss_threshold` (and its
    `updated_at`) is written: matched Products whose value differs are set,
    and local Products whose non-null threshold has no resolved CPE are
    cleared to NULL. A database error propagates before the commit
    succeeds; the caller rolls the session back.
    """
    current: dict[uuid.UUID, tuple[Decimal | None, Decimal | None]] = {}
    cpes = sorted(thresholds)
    for start in range(0, len(cpes), _SELECT_CHUNK_SIZE):
        rows = await session.execute(
            select(Product.id, Product.cpe, Product.cvss_threshold).where(
                Product.cpe.in_(cpes[start : start + _SELECT_CHUNK_SIZE])
            )
        )
        for row in rows:
            current[row.id] = (row.cvss_threshold, thresholds[row.cpe])

    stale = await session.execute(
        select(Product.id, Product.cpe, Product.cvss_threshold).where(
            Product.cvss_threshold.is_not(None)
        )
    )
    for row in stale:
        if row.cpe not in thresholds:
            current[row.id] = (row.cvss_threshold, None)

    changed = sorted(
        product_id for product_id, (stored, new) in current.items() if stored != new
    )
    if changed:
        # ORM bulk UPDATE by primary key; `updated_at` follows its `onupdate`.
        await session.execute(
            update(Product),
            [
                {"id": product_id, "cvss_threshold": current[product_id][1]}
                for product_id in changed
            ],
        )
    await session.commit()

    return ThresholdPublication(
        evaluated=frozenset(current), changed=frozenset(changed)
    )


def _utc_today() -> date:
    """The current UTC date (patched by controlled-clock tests)."""
    return datetime.now(UTC).date()


class SyncAimaasThresholds(BaseFetcher):
    """Synchronize AIMAAS Product CVSS thresholds and trigger eligibility
    reconciliation."""

    name = "sync_aimaas_thresholds"
    description = (
        "Synchronize AIMAAS Product CVSS thresholds and trigger eligibility "
        "reconciliation"
    )
    default_schedule = "45 2 * * *"

    async def execute(self, session: AsyncSession) -> None:
        # Step 1: both retrieval phases complete before any database work.
        request_delay = self.config.request_delay if self.config is not None else 0.0
        product_listing = await fetch_aimaas_products(
            self.http_client,
            api_url=settings.aimaas_api_url,
            request_delay=request_delay,
            invalid_message=INVALID_PRODUCT_LIST_MESSAGE,
        )
        threshold_listing = await fetch_aimaas_listing(
            self.http_client,
            api_url=settings.aimaas_api_url,
            path=THRESHOLDS_ENDPOINT_PATH,
            query={},
            collection=_THRESHOLDS_COLLECTION,
            request_delay=request_delay,
            invalid_message=INVALID_THRESHOLD_LIST_MESSAGE,
        )
        products = self._parse(
            parse_product_refs,
            product_listing.items,
            _PRODUCTS_COLLECTION,
            INVALID_PRODUCT_LIST_MESSAGE,
        )
        entries = self._parse(
            parse_threshold_entries,
            threshold_listing.items,
            _THRESHOLDS_COLLECTION,
            INVALID_THRESHOLD_LIST_MESSAGE,
        )

        # Step 2: complete-response validation.
        try:
            response = validate_response(products, entries)
        except ThresholdValidationError as exc:
            logger.warning("aimaas_cvss_threshold_validation_failed", category=str(exc))
            raise FetcherError(VALIDATION_FAILED_MESSAGE) from exc

        # Steps 3-8: CPE resolution, one atomic publication, one commit.
        resolved = resolve_thresholds(response)
        try:
            publication = await publish_thresholds(session, resolved)
        except SQLAlchemyError as exc:
            logger.warning("aimaas_cvss_threshold_publication_failed")
            raise FetcherError(PUBLICATION_FAILED_MESSAGE) from exc
        # Durable effects first: preserved if a post-commit step escapes.
        self.record_updated(len(publication.changed))

        # Step 9: read-only mismatch scan, closed before any dispatch.
        mismatches = await find_product_eligibility_mismatches(
            session, evaluation_date=_utc_today()
        )
        await session.commit()

        required = publication.changed | mismatches
        self.record_succeeded(len(publication.evaluated - required))

        # Step 10: one dispatch per Product in the union, in ID order.
        dispatch_failed = 0
        for product_id in sorted(required):
            try:
                await dispatch_product_eligibility_recalculation(
                    product_id, "threshold"
                )
            except SoftTimeLimitExceeded, MemoryError:
                raise
            except Exception as exc:
                dispatch_failed += 1
                self.record_failed()
                logger.warning(
                    "aimaas_cvss_threshold_dispatch_failed",
                    product_id=str(product_id),
                    error_type=type(exc).__name__,
                )
                continue
            self.record_succeeded()

        logger.info(
            "aimaas_cvss_thresholds_published",
            aimaas_products=len(products),
            aimaas_thresholds=len(entries),
            resolved=len(resolved),
            evaluated=len(publication.evaluated),
            updated=len(publication.changed),
            mismatched=len(mismatches),
            dispatched=len(required) - dispatch_failed,
            dispatch_failed=dispatch_failed,
        )

    @staticmethod
    def _parse[T](
        parser: Callable[[Sequence[dict[str, Any]]], list[T]],
        items: Sequence[dict[str, Any]],
        collection: str,
        message: str,
    ) -> list[T]:
        """Parse one retrieval phase's items; log the phase on failure."""
        try:
            return parser(items)
        except ThresholdResponseError as exc:
            logger.warning(
                "aimaas_cvss_threshold_response_invalid",
                collection=collection,
                category=str(exc),
            )
            raise FetcherError(message) from exc
