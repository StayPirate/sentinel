"""The IBS Product release reconciliation boundary.

Implements docs/features/packages/ibs-product-release-detection.md
(Scope; Reconciliation Boundary and its Local mutation and concurrency;
Irreversibility, Audit, and Observability: the occurrence and run events)
for the periodic fetcher and the per-Ticket catch-up of
`detect_ibs_product_releases`:

- `load_product_release_candidates()` is the read-only candidate selection:
  unreleased occurrences below an IBS track of an active Ticket with a
  CVE, each with its semantic locator, the Ticket CVE, the package name,
  and the current and historical repository names of its Product. VA
  exclusion, lifecycle, EOL, eligibility, affectedness, and delivery never
  narrow the scope.
- `reconcile_ibs_product_releases()` is the I/O orchestration and never
  takes a lock. Phase 1 observes every selected occurrence through one
  `ProductRepositoryDownloads` context (repository reuse per invocation)
  and closes it; phase 2 runs each match as one independent caller-owned
  transaction, so all repository I/O precedes every Ticket lock.
- `_release_occurrence()` is the only function that takes the Ticket row
  lock: it reloads the occurrence under the lock, revalidates the selected
  scope, treats an already-set `released_at` as a concurrent no-op, and
  otherwise delegates to `package_service.set_product_released_at()`, the
  sole owner of the mutation, its `product_released` event, and Ticket
  reconciliation.

After a committed unit, the per-outcome hook (periodic metrics) runs
before the session's Ticket convergence effects are drained; a broker
operational error is absorbed by the automatic policy and any other drain
exception propagates. A commit exception or ambiguous commit outcome
propagates without an outcome and terminates the invocation.
`SoftTimeLimitExceeded`, `MemoryError`, cancellation, and unexpected
exceptions propagate; only `SQLAlchemyError` before finalization becomes
a per-occurrence failure.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Final, Literal

import httpx
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ACTIVE_TICKET_STATUSES, WorkflowType
from app.core.exceptions import TicketNotMutableError
from app.database import async_session_factory
from app.models.cve import CVE
from app.models.product import Product
from app.models.product_repository import ProductRepository
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service
from app.services.packages.ibs_product_download import (
    ProductOccurrenceCandidate,
    ProductReleaseIncomplete,
    ProductReleaseMatch,
    ProductReleaseObservation,
    ProductRepositoryDownloads,
)
from app.services.ticket_convergence_publication import drain_ticket_convergence

logger = structlog.get_logger(__name__)

OCCURRENCE_FAILED_EVENT: Final = "ibs_product_release_occurrence_failed"
OCCURRENCE_STALE_EVENT: Final = "ibs_product_release_occurrence_stale"
RUN_COMPLETED_EVENT: Final = "ibs_product_release_run_completed"

DATABASE_CATEGORY: Final = "database"
TICKET_NOT_OPERABLE_CATEGORY: Final = "ticket_not_operable"
SCOPE_CHANGED_CATEGORY: Final = "scope_changed"

ProductReleaseOutcomeKind = Literal["updated", "no_op", "failed"]


@dataclass(frozen=True, slots=True)
class ProductReleaseCandidate:
    """One selected occurrence and the evidence snapshot used to match it.

    `ticket_id`, `package_id`, `track_id`, and `occurrence_id` form the
    semantic locator; `product_id` is the catalog Product. The repository
    tiers are raw retained names; `ProductRepositoryDownloads` qualifies
    and orders them.
    """

    occurrence_id: uuid.UUID
    ticket_id: uuid.UUID
    package_id: uuid.UUID
    track_id: uuid.UUID
    product_id: uuid.UUID
    cve_id: str
    package_name: str
    current_repositories: tuple[str, ...]
    historical_repositories: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProductReleaseOutcome:
    """The terminal outcome of one selected occurrence."""

    occurrence_id: uuid.UUID
    kind: ProductReleaseOutcomeKind


OutcomeHook = Callable[[ProductReleaseOutcome], None]


@dataclass(frozen=True, slots=True)
class ProductReleaseSummary:
    """Counts of one invocation; `no_op` includes no-match and stale."""

    selected: int
    updated: int
    no_op: int
    failed: int


async def load_product_release_candidates(
    db: AsyncSession, *, ticket_id: uuid.UUID | None = None
) -> list[ProductReleaseCandidate]:
    """The occurrences in the detector's Scope, ordered by occurrence ID.

    Category B (read-only; no lock, write, commit, or rollback). Selects
    every `TicketPackageProduct` with `released_at IS NULL` below a track
    with `workflow_type = ibs` of an active Ticket that has a CVE; with
    `ticket_id`, only that Ticket's occurrences (none for a missing,
    inactive, or CVE-less Ticket). A repository association is current
    when its `catalog_last_seen_at` equals the latest complete catalog
    snapshot (`MAX(Product.catalog_last_seen_at)`), otherwise historical.
    Database exceptions propagate.
    """
    statement = (
        select(
            TicketPackageProduct.id,
            Ticket.id,
            TicketPackage.id,
            TicketPackageTrack.id,
            TicketPackageProduct.product_id,
            CVE.cve_id,
            TicketPackage.package_name,
        )
        .select_from(TicketPackageProduct)
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(Ticket, Ticket.id == TicketPackage.ticket_id)
        .join(CVE, CVE.id == Ticket.cve_id)
        .where(
            TicketPackageProduct.released_at.is_(None),
            TicketPackageTrack.workflow_type == WorkflowType.IBS.value,
            Ticket.status.in_(ACTIVE_TICKET_STATUSES),
        )
        .order_by(TicketPackageProduct.id)
    )
    if ticket_id is not None:
        statement = statement.where(Ticket.id == ticket_id)
    rows = (await db.execute(statement)).all()
    if not rows:
        return []

    product_ids = {row[4] for row in rows}
    snapshot = select(func.max(Product.catalog_last_seen_at)).scalar_subquery()
    repositories = (
        await db.execute(
            select(
                ProductRepository.product_id,
                ProductRepository.repo_name,
                (ProductRepository.catalog_last_seen_at == snapshot).label("current"),
            )
            .where(ProductRepository.product_id.in_(product_ids))
            .order_by(ProductRepository.product_id, ProductRepository.repo_name)
        )
    ).all()
    current: dict[uuid.UUID, list[str]] = {}
    historical: dict[uuid.UUID, list[str]] = {}
    for product_id, repo_name, is_current in repositories:
        tier = current if is_current else historical
        tier.setdefault(product_id, []).append(repo_name)

    return [
        ProductReleaseCandidate(
            occurrence_id=occurrence_id,
            ticket_id=candidate_ticket_id,
            package_id=package_id,
            track_id=track_id,
            product_id=product_id,
            cve_id=cve_id,
            package_name=package_name,
            current_repositories=tuple(current.get(product_id, ())),
            historical_repositories=tuple(historical.get(product_id, ())),
        )
        for (
            occurrence_id,
            candidate_ticket_id,
            package_id,
            track_id,
            product_id,
            cve_id,
            package_name,
        ) in rows
    ]


async def reconcile_ibs_product_releases(
    candidates: Iterable[ProductReleaseCandidate],
    *,
    client: httpx.AsyncClient,
    fetcher_name: str,
    on_outcome: OutcomeHook | None = None,
) -> ProductReleaseSummary:
    """Reconcile the selected occurrences against their repositories.

    Category A workflow owning one independent transaction per matching
    occurrence (ibs-product-release-detection.md, Reconciliation Boundary).

    Q1: `candidates` come from `load_product_release_candidates()`;
    duplicate occurrence IDs are processed once. `client` is the fetcher's
    shared HTTP client; `fetcher_name` identifies the caller in per-item
    logs; `on_outcome`, when given, receives each terminal outcome.

    Q2: acquires no lock; each matching unit serializes on the Ticket row
    lock in `_release_occurrence()`.

    Q3: an empty selection performs no HTTP or database work. Phase 1
    observes every occurrence and closes the download context. Then an
    incomplete observation is `failed` (one
    `ibs_product_release_occurrence_failed`) and a non-match is `no_op`;
    each match runs in a fresh session: an effective release commits and
    is `updated`; an already-released or stale outcome rolls back and is
    `no_op` (a stale one emits one `ibs_product_release_occurrence_stale`);
    a `SQLAlchemyError` before commit rolls back and is `failed`. The hook
    runs after the commit or rollback, then committed effects are drained
    after the session is closed. One `ibs_product_release_run_completed`
    is emitted when the invocation completes.

    Q4: returns the invocation's counts. Creates no audit event itself.

    Q5: re-invocation re-reads repositories and PostgreSQL; released
    occurrences are concurrent no-ops.

    Q6: a commit exception or ambiguous outcome, a rollback failure, a
    non-operational drain exception, `SoftTimeLimitExceeded`,
    `MemoryError`, cancellation, and unexpected exceptions propagate;
    earlier committed occurrences remain committed.
    """
    selected: dict[uuid.UUID, ProductReleaseCandidate] = {}
    for candidate in candidates:
        selected.setdefault(candidate.occurrence_id, candidate)
    ordered = [selected[key] for key in sorted(selected)]

    updated = no_op = failed = 0

    def finish(
        candidate: ProductReleaseCandidate, kind: ProductReleaseOutcomeKind
    ) -> None:
        nonlocal updated, no_op, failed
        if kind == "updated":
            updated += 1
        elif kind == "no_op":
            no_op += 1
        else:
            failed += 1
        if on_outcome is not None:
            on_outcome(ProductReleaseOutcome(candidate.occurrence_id, kind))

    observations: dict[uuid.UUID, ProductReleaseObservation] = {}
    if ordered:
        async with ProductRepositoryDownloads(
            client, [_download_candidate(candidate) for candidate in ordered]
        ) as downloads:
            for candidate in ordered:
                observations[candidate.occurrence_id] = await downloads.observe(
                    candidate.occurrence_id
                )

    matches: list[tuple[ProductReleaseCandidate, ProductReleaseMatch]] = []
    for candidate in ordered:
        observation = observations[candidate.occurrence_id]
        if isinstance(observation, ProductReleaseMatch):
            matches.append((candidate, observation))
        elif isinstance(observation, ProductReleaseIncomplete):
            _log_failed(
                candidate,
                fetcher_name=fetcher_name,
                repository=observation.repository,
                reason_category=observation.reason_category,
            )
            finish(candidate, "failed")
        else:
            finish(candidate, "no_op")

    for candidate, match in matches:
        committed = False
        kind: ProductReleaseOutcomeKind
        async with async_session_factory() as unit:
            try:
                result = await _release_occurrence(unit, candidate, match)
            except SoftTimeLimitExceeded, MemoryError:
                raise
            except TicketNotMutableError:
                await unit.rollback()
                _log_stale(candidate, TICKET_NOT_OPERABLE_CATEGORY)
                kind = "no_op"
            except SQLAlchemyError:
                await unit.rollback()
                _log_failed(
                    candidate,
                    fetcher_name=fetcher_name,
                    repository=match.repository,
                    reason_category=DATABASE_CATEGORY,
                )
                kind = "failed"
            else:
                if result == "updated":
                    # A commit exception propagates: never a per-item outcome.
                    await unit.commit()
                    committed = True
                    kind = "updated"
                else:
                    await unit.rollback()
                    if result == "stale":
                        _log_stale(candidate, SCOPE_CHANGED_CATEGORY)
                    kind = "no_op"
        finish(candidate, kind)
        if committed:
            await drain_ticket_convergence(unit)

    summary = ProductReleaseSummary(
        selected=len(ordered), updated=updated, no_op=no_op, failed=failed
    )
    logger.info(
        RUN_COMPLETED_EVENT,
        selected=summary.selected,
        updated=summary.updated,
        no_op=summary.no_op,
        failed=summary.failed,
    )
    return summary


async def _release_occurrence(
    db: AsyncSession,
    candidate: ProductReleaseCandidate,
    match: ProductReleaseMatch,
) -> Literal["updated", "no_op", "stale"]:
    """Lock the Ticket, revalidate the scope, and release one occurrence.

    The only function of the detector that takes the Ticket row lock
    (ibs-product-release-detection.md, Local mutation and concurrency,
    steps 1-4). Performs no external I/O and never commits.

    Returns `stale` when the Ticket, occurrence, track, package, Product,
    CVE, or IBS workflow no longer matches the selected evidence;
    `no_op` when `released_at` is already set or the package service
    observes a concurrent winner; `updated` for an effective release.
    `TicketNotMutableError` and database exceptions propagate.
    """
    ticket = (
        await db.execute(
            select(Ticket)
            .where(Ticket.id == candidate.ticket_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if ticket is None:
        return "stale"
    row = (
        await db.execute(
            select(
                TicketPackageProduct.released_at,
                TicketPackageProduct.product_id,
                TicketPackageTrack.workflow_type,
                TicketPackage.package_name,
                CVE.cve_id,
            )
            .select_from(TicketPackageProduct)
            .join(
                TicketPackageTrack,
                TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .join(Ticket, Ticket.id == TicketPackage.ticket_id)
            .outerjoin(CVE, CVE.id == Ticket.cve_id)
            .where(
                TicketPackageProduct.id == candidate.occurrence_id,
                TicketPackageTrack.id == candidate.track_id,
                TicketPackage.id == candidate.package_id,
                Ticket.id == candidate.ticket_id,
            )
        )
    ).one_or_none()
    if (
        row is None
        or row.product_id != candidate.product_id
        or row.workflow_type != WorkflowType.IBS.value
        or row.package_name != candidate.package_name
        or row.cve_id != candidate.cve_id
    ):
        return "stale"
    if row.released_at is not None:
        return "no_op"

    result = await package_service.set_product_released_at(
        db,
        ticket_id=candidate.ticket_id,
        package_id=candidate.package_id,
        track_id=candidate.track_id,
        ticket_package_product_id=candidate.occurrence_id,
        released_at=match.issued_at,
        advisory_id=match.advisory_id,
    )
    if result.outcome is package_service.MutationOutcome.CHANGED:
        return "updated"
    return "no_op"


def _download_candidate(
    candidate: ProductReleaseCandidate,
) -> ProductOccurrenceCandidate:
    return ProductOccurrenceCandidate(
        occurrence_id=candidate.occurrence_id,
        cve_id=candidate.cve_id,
        package_name=candidate.package_name,
        current_repositories=candidate.current_repositories,
        historical_repositories=candidate.historical_repositories,
    )


def _log_failed(
    candidate: ProductReleaseCandidate,
    *,
    fetcher_name: str,
    repository: str,
    reason_category: str,
) -> None:
    logger.warning(
        OCCURRENCE_FAILED_EVENT,
        ticket_package_product_id=str(candidate.occurrence_id),
        ticket_id=str(candidate.ticket_id),
        fetcher_name=fetcher_name,
        repository=repository,
        reason_category=reason_category,
    )


def _log_stale(candidate: ProductReleaseCandidate, reason_category: str) -> None:
    logger.warning(
        OCCURRENCE_STALE_EVENT,
        ticket_package_product_id=str(candidate.occurrence_id),
        ticket_id=str(candidate.ticket_id),
        reason_category=reason_category,
    )
