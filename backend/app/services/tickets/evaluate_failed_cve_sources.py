"""`evaluate_failed_cve_sources`: automatic CVE source failure retry.

Implements docs/features/platform/cve-source-failure-retry.md (Fetcher:
`evaluate_failed_cve_sources`). Each run:

1. selects, in one statement, every `CVESource` `failure` row whose
   non-NULL `first_failed_at` lies inside the fixed 720-hour window
   (`cve_service.STALLED_AFTER_HOURS`, equality inside) together with an
   active-Ticket flag (`find_failed_cve_source_candidates()`), materializes
   it, and ends the read transaction before any Redis or Celery call;
2. per pair, in oldest-streak order: skips a source that is not
   fetch-single capable and a CVE without an active Ticket (pre-scope, no
   metric); revalidates the source through the in-memory registry and a
   non-locking `FetcherConfig.enabled` read in a short session closed before
   publication (unregistered, no longer capable, or disabled: excluded, no
   metric; a missing row: one failure); then publishes exactly that source
   through the database-free `cve_service.trigger_on_demand_fetch()` with
   the fetcher's queue, so MITRE and Kernel retries keep `git`. Enqueued and
   already-pending pairs succeed; an unconfirmed publication or an ordinary
   exception fails the pair and later pairs continue;
3. logs one closed end-of-run summary.

The evaluator writes no `CVESource`, CVE, Ticket, or audit row; every
status write belongs to the dispatched `fetch_single_cve` task.
`CancelledError`, `SoftTimeLimitExceeded`, and `MemoryError` are never
caught per pair. A candidate-query failure propagates as a run failure.
"""

from __future__ import annotations

from asyncio import CancelledError
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceFetchStatus
from app.database import async_session_factory
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.ticket import Ticket
from app.services.base_cve_fetcher import get_fetch_single_fetchers
from app.services.base_fetcher import BaseFetcher
from app.services.cve_projection import CODE_POINT_COLLATION
from app.services.cve_service import (
    ACTIVE_TICKET_STATUSES,
    STALLED_AFTER_HOURS,
    trigger_on_demand_fetch,
)
from app.services.fetcher_execution import (
    FetcherConfigMissingError,
    get_fetcher_enabled,
)

logger = structlog.get_logger(__name__)

SKIPPED_EVENT: Final = "cve_source_retry_skipped"
"""DEBUG: a pair was skipped before or at revalidation (`reason`)."""

DISPATCHED_EVENT: Final = "cve_source_retry_dispatched"
"""INFO: the pair's publication returned without raising."""

ALREADY_PENDING_EVENT: Final = "cve_source_retry_already_pending"
"""INFO: a pending marker already existed; nothing was published."""

CONFIG_MISSING_EVENT: Final = "cve_source_retry_config_missing"
"""ERROR: a registered source has no `FetcherConfig` row."""

DISPATCH_FAILED_EVENT: Final = "cve_source_retry_dispatch_failed"
"""WARNING: publication unconfirmed or an unexpected per-pair exception."""

SUMMARY_EVENT: Final = "failed_cve_sources_evaluated"
"""INFO: the closed end-of-run summary."""


class RetryOutcome(StrEnum):
    """The closed per-pair outcome set; each value is a summary counter."""

    DISPATCHED = "dispatched"
    ALREADY_PENDING = "already_pending"
    DISPATCH_FAILED = "dispatch_failed"
    CONFIG_MISSING = "config_missing"
    SKIPPED_NO_CAPABILITY = "skipped_no_capability"
    SKIPPED_NO_ACTIVE_TICKET = "skipped_no_active_ticket"
    EXCLUDED_AT_REVALIDATION = "excluded_at_revalidation"


_SKIP_REASONS: Final = {
    RetryOutcome.SKIPPED_NO_CAPABILITY: "not_fetch_single_capable",
    RetryOutcome.SKIPPED_NO_ACTIVE_TICKET: "no_active_ticket",
    RetryOutcome.EXCLUDED_AT_REVALIDATION: "excluded_at_revalidation",
}


@dataclass(frozen=True, slots=True)
class RetryCandidate:
    """One in-window failure pair with its active-Ticket flag."""

    cve_id: str
    source: str
    has_active_ticket: bool


async def find_failed_cve_source_candidates(
    db: AsyncSession,
) -> list[RetryCandidate]:
    """Every in-window `failure` pair with its active-Ticket flag.

    Category B (read-only; no lock, write, audit, flush, commit, or
    rollback). One statement selects the `CVESource` rows with status
    `failure` and a non-NULL `first_failed_at` at or after the statement's
    database `now()` minus `STALLED_AFTER_HOURS` (a fixed-length interval,
    independent of the session time zone), joined to their CVE, with an
    `EXISTS` flag over Tickets referencing the CVE in an active status
    (`ACTIVE_TICKET_STATUSES`). Pairs without an active Ticket are returned
    with the flag false. Ordered by `first_failed_at` ascending, then the
    canonical CVE-ID and the source in code-point order. Database
    exceptions propagate.
    """
    has_active_ticket = (
        select(Ticket.id)
        .where(
            Ticket.cve_id == CVE.id,
            Ticket.status.in_(ACTIVE_TICKET_STATUSES),
        )
        .exists()
    )
    window_start = func.now() - func.make_interval(0, 0, 0, 0, STALLED_AFTER_HOURS)
    statement = (
        select(CVE.cve_id, CVESource.source, has_active_ticket)
        .join_from(CVESource, CVE, CVESource.cve_id == CVE.id)
        .where(
            CVESource.status == CVESourceFetchStatus.FAILURE.value,
            CVESource.first_failed_at.is_not(None),
            CVESource.first_failed_at >= window_start,
        )
        .order_by(
            CVESource.first_failed_at,
            CVE.cve_id.collate(CODE_POINT_COLLATION),
            CVESource.source.collate(CODE_POINT_COLLATION),
        )
    )
    with db.no_autoflush:
        rows = (await db.execute(statement)).all()
    return [
        RetryCandidate(cve_id=cve_id, source=source, has_active_ticket=bool(active))
        for cve_id, source, active in rows
    ]


async def _read_fetcher_enabled(fetcher_name: str) -> bool:
    """Non-locking `FetcherConfig.enabled` read in a short, closed session."""
    async with async_session_factory() as read:
        return await get_fetcher_enabled(read, fetcher_name)


class EvaluateFailedCveSources(BaseFetcher):
    """Retry CVE source records stuck in failure for CVEs with an active Ticket."""

    name = "evaluate_failed_cve_sources"
    description = (
        "Retry CVE source records stuck in failure for CVEs with an active Ticket"
    )
    default_schedule = "0 6 * * *"

    async def execute(self, session: AsyncSession) -> None:
        # Step 1: one materialized candidate read, closed before any I/O.
        candidates = await find_failed_cve_source_candidates(session)
        await session.commit()

        # Step 2: one terminal outcome or pre-scope exclusion per pair.
        outcomes: Counter[RetryOutcome] = Counter()
        for candidate in candidates:
            outcomes[await self._evaluate(candidate)] += 1

        # Step 4: the closed end-of-run summary.
        logger.info(
            SUMMARY_EVENT,
            candidates=len(candidates),
            **{outcome.value: outcomes[outcome] for outcome in RetryOutcome},
        )

    async def _evaluate(self, candidate: RetryCandidate) -> RetryOutcome:
        """Classify, revalidate, and publish one candidate pair."""
        # Step 2a: in-memory fetch-single capability.
        if candidate.source not in get_fetch_single_fetchers():
            return _skip(candidate, RetryOutcome.SKIPPED_NO_CAPABILITY)
        # Step 2b: the active-Ticket flag of the candidate read.
        if not candidate.has_active_ticket:
            return _skip(candidate, RetryOutcome.SKIPPED_NO_ACTIVE_TICKET)

        # Step 2c: non-locking revalidation, then database-free publication.
        fetcher_cls = get_fetch_single_fetchers().get(candidate.source)
        if fetcher_cls is None:
            return _skip(candidate, RetryOutcome.EXCLUDED_AT_REVALIDATION)
        try:
            if not await _read_fetcher_enabled(fetcher_cls.name):
                return _skip(candidate, RetryOutcome.EXCLUDED_AT_REVALIDATION)
            result = await trigger_on_demand_fetch(
                candidate.cve_id,
                ((fetcher_cls.name, candidate.source, fetcher_cls.queue),),
            )
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise  # whole-run signals — never caught per pair
        except FetcherConfigMissingError:
            self.record_failed()
            logger.error(
                CONFIG_MISSING_EVENT,
                cve_id=candidate.cve_id,
                source=candidate.source,
                fetcher_name=fetcher_cls.name,
            )
            return RetryOutcome.CONFIG_MISSING
        except Exception as exc:
            self.record_failed()
            logger.warning(
                DISPATCH_FAILED_EVENT,
                cve_id=candidate.cve_id,
                source=candidate.source,
                reason="unexpected_error",
                cause=type(exc).__name__,
            )
            return RetryOutcome.DISPATCH_FAILED

        if candidate.source in result.sources_enqueued:
            self.record_succeeded()
            logger.info(
                DISPATCHED_EVENT, cve_id=candidate.cve_id, source=candidate.source
            )
            return RetryOutcome.DISPATCHED
        if candidate.source in result.sources_already_pending:
            self.record_succeeded()
            logger.info(
                ALREADY_PENDING_EVENT,
                cve_id=candidate.cve_id,
                source=candidate.source,
            )
            return RetryOutcome.ALREADY_PENDING
        # The one prepared source is otherwise in `sources_failed`.
        self.record_failed()
        logger.warning(
            DISPATCH_FAILED_EVENT,
            cve_id=candidate.cve_id,
            source=candidate.source,
            reason="publication_unconfirmed",
        )
        return RetryOutcome.DISPATCH_FAILED


def _skip(candidate: RetryCandidate, outcome: RetryOutcome) -> RetryOutcome:
    """Log one pre-scope exclusion; no terminal metric."""
    logger.debug(
        SKIPPED_EVENT,
        cve_id=candidate.cve_id,
        source=candidate.source,
        reason=_SKIP_REASONS[outcome],
    )
    return outcome
