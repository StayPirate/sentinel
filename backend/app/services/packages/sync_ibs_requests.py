"""`sync_ibs_requests`: IBS request synchronization fetcher.

Implements docs/features/packages/ibs-submission-tracking.md (Fetcher:
sync_ibs_requests: Properties, Request Delay, Algorithm, Error Handling,
Metrics; Accelerators > Ticket Convergence; Structured Logs, the run
completion row). Both `execute()` and `catch_up()` select their scopes
read-only with `load_ibs_request_scopes()`, end that read transaction, and
delegate to `reconcile_ibs_requests()`, which owns the IBS I/O and the
independent per-scope transactions. Neither method takes a Ticket lock.

Each invocation that selected at least one scope owns one `IBSClient`,
created on its event loop and closed before it returns (`async with`);
`BaseFetcher.http_client` is never used, so `_teardown_http_client()` has
nothing of this fetcher to close. An empty selection creates no client and
sends no request.

The boundary separates consecutive IBS requests by the request delay
(Request Delay): the run's `request_delay` in `execute()`, the class
`default_request_delay` in `catch_up()`, which has no run snapshot.

Periodic metrics are recorded through the boundary's per-outcome hook:
`created` is succeeded and created, `updated` is succeeded and updated,
`no_op` is succeeded, `failed` is failed (Metrics). A scope-enumeration
failure becomes the sanitized `FetcherError("Failed to enumerate IBS
request scopes")`; an ambiguous scope commit, `SoftTimeLimitExceeded`,
`MemoryError`, and cancellation escape as whole-run signals.

`catch_up()` uses the passed session only to enumerate the Ticket's scopes
(a missing or inactive Ticket, or no IBS track, returns silently), reports
no metric, returns normally on partial success, and raises the
non-retryable `FetcherError("All {failed} IBS request reconciliations
failed")` when every selected scope failed.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Final

import structlog
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.base_fetcher import BaseFetcher, FetcherError
from app.services.ibs_client import IBSClient
from app.services.packages.ibs_request_reconciliation import (
    IBSRequestOutcome,
    IBSRequestScope,
    load_ibs_request_scopes,
    reconcile_ibs_requests,
)

logger = structlog.get_logger(__name__)

ENUMERATION_FAILED_MESSAGE: Final = "Failed to enumerate IBS request scopes"

RUN_COMPLETED_EVENT: Final = "ibs_request_run_completed"


def all_failed_message(failed: int) -> str:
    """The sanitized public message of an all-failed catch-up."""
    return f"All {failed} IBS request reconciliations failed"


def _distinct(scopes: Sequence[IBSRequestScope]) -> int:
    """The number of distinct selected scopes (track IDs)."""
    return len({scope.track_id for scope in scopes})


def _log_completed(
    selected: int,
    outcomes: Sequence[IBSRequestOutcome],
    *,
    ticket_id: str | None = None,
) -> None:
    """One `ibs_request_run_completed` with the terminal outcome counts."""
    counts = dict.fromkeys(("created", "updated", "no_op", "failed"), 0)
    for outcome in outcomes:
        counts[outcome.kind] += 1
    fields: dict[str, object] = {"selected": selected, **counts}
    if ticket_id is not None:
        fields["ticket_id"] = ticket_id
    logger.info(RUN_COMPLETED_EVENT, **fields)


class SyncIbsRequests(BaseFetcher):
    """Reconcile active-Ticket IBS tracks against IBS request evidence."""

    name = "sync_ibs_requests"
    description = (
        "Synchronize IBS maintenance request actions and reconcile track delivery state"
    )
    default_schedule = "30 2 * * *"
    default_request_delay = 0
    participates_in_catch_up = True

    async def execute(self, session: AsyncSession) -> None:
        # Step 1: select the scopes; the read ends before any I/O.
        try:
            scopes = await load_ibs_request_scopes(session)
            await session.commit()
        except SQLAlchemyError as exc:
            raise FetcherError(ENUMERATION_FAILED_MESSAGE) from exc
        if not scopes:
            _log_completed(0, ())
            return

        # Steps 2-5: observation and independent per-scope transactions.
        async with IBSClient() as client:
            outcomes = await reconcile_ibs_requests(
                scopes,
                client=client,
                on_outcome=self._record_outcome,
                request_delay=self._run_request_delay(),
                fetcher_name=self.name,
            )
        _log_completed(_distinct(scopes), outcomes)

    def _run_request_delay(self) -> float:
        """The run snapshot's `request_delay`; the class value only when
        `execute()` is called outside `run()`."""
        if self.config is not None:
            return self.config.request_delay
        return self.default_request_delay

    def _record_outcome(self, outcome: IBSRequestOutcome) -> None:
        if outcome.kind == "failed":
            self.record_failed()
            return
        self.record_succeeded()
        if outcome.kind == "created":
            self.record_created()
        elif outcome.kind == "updated":
            self.record_updated()

    async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
        """Reconcile every IBS track of one active Ticket.

        ibs-submission-tracking.md (Accelerators > Ticket Convergence;
        Metrics). The passed session only reads; every mutation runs in
        its own session inside the boundary. Returns silently when nothing
        is selected. A failure of some scopes returns normally after their
        warnings; when every selected scope failed, raises the
        non-retryable `FetcherError`. An ambiguous scope commit and the
        whole-run signals propagate unchanged.
        """
        scopes = await load_ibs_request_scopes(session, ticket_id=uuid.UUID(ticket_id))
        await session.commit()
        if not scopes:
            return

        async with IBSClient() as client:
            outcomes = await reconcile_ibs_requests(
                scopes,
                client=client,
                request_delay=self.default_request_delay,
                fetcher_name=self.name,
            )
        _log_completed(_distinct(scopes), outcomes, ticket_id=ticket_id)
        failed = sum(1 for outcome in outcomes if outcome.kind == "failed")
        if failed == len(outcomes):
            raise FetcherError(all_failed_message(failed))
