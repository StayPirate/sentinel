"""`detect_ibs_track_releases`: IBS track release detection fetcher.

Implements docs/features/packages/ibs-track-release-detection.md (Scheduled
Reconciliation Algorithm steps 1 and 9; Catch-Up; Background Fetcher:
Fetcher, Metrics and Run Status). Both `execute()` and `catch_up()` select
their tracks read-only with `load_track_release_candidates()`, end that
read transaction, and delegate to `reconcile_ibs_track_releases()`, which
owns the IBS I/O, the independent per-track transactions, and the Ticket
convergence drain. Neither method takes a Ticket lock.

Each invocation that selected at least one track owns one `IBSClient`,
created on its event loop and closed before it returns (`async with`);
`BaseFetcher.http_client` is never used, so `_teardown_http_client()`
has nothing of this fetcher to close. An empty selection creates no
client and sends no request.

Periodic metrics are recorded through the boundary's per-outcome hook:
`updated` is succeeded and updated, `no_op` is succeeded, `failed` is
failed; nothing is ever created. A candidate enumeration failure becomes
the sanitized `FetcherError("Failed to enumerate IBS track release
candidates")`.

`catch_up()` uses the passed session only to enumerate the Ticket's tracks
in the same Scope (a missing, inactive, or CVE-less Ticket, or no relevant
track, returns silently), reports no metric, returns normally on partial
success, and raises the non-retryable
`FetcherError("All {failed} IBS track release checks failed")` when every
selected track failed.
"""

from __future__ import annotations

import uuid
from typing import Final

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.base_fetcher import BaseFetcher, FetcherError
from app.services.ibs_client import IBSClient
from app.services.packages.ibs_track_release import (
    TrackReleaseOutcome,
    load_track_release_candidates,
    reconcile_ibs_track_releases,
)

ENUMERATION_FAILED_MESSAGE: Final = "Failed to enumerate IBS track release candidates"


def all_failed_message(failed: int) -> str:
    """The sanitized public message of an all-failed catch-up."""
    return f"All {failed} IBS track release checks failed"


class DetectIbsTrackReleases(BaseFetcher):
    """Reconcile active-Ticket IBS tracks against expanded source state."""

    name = "detect_ibs_track_releases"
    description = (
        "Reconcile existing active-Ticket IBS tracks against expanded package "
        "source state"
    )
    default_schedule = "0 2 * * *"
    participates_in_catch_up = True

    async def execute(self, session: AsyncSession) -> None:
        # Step 1: select and snapshot the scope; the read ends before I/O.
        try:
            candidates = await load_track_release_candidates(session)
            await session.commit()
        except SQLAlchemyError as exc:
            raise FetcherError(ENUMERATION_FAILED_MESSAGE) from exc
        if not candidates:
            return

        # Steps 2-8: source info, diffs, independent per-track transactions.
        async with IBSClient() as client:
            await reconcile_ibs_track_releases(
                candidates,
                client=client,
                fetcher_name=self.name,
                on_outcome=self._record_outcome,
            )

    def _record_outcome(self, outcome: TrackReleaseOutcome) -> None:
        if outcome.kind == "failed":
            self.record_failed()
            return
        self.record_succeeded()
        if outcome.kind == "updated":
            self.record_updated()

    async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
        """Reconcile one Ticket's eligible IBS tracks.

        ibs-track-release-detection.md (Catch-Up). The passed session only
        reads; every mutation runs in its own session inside the boundary.
        Returns silently when nothing is selected. A pre-finalization
        failure of some tracks returns normally after their warnings; when
        every selected track failed, raises the non-retryable
        `FetcherError`. Commit exceptions and non-operational drain
        exceptions propagate unchanged.
        """
        candidates = await load_track_release_candidates(
            session, ticket_id=uuid.UUID(ticket_id)
        )
        await session.commit()
        if not candidates:
            return

        async with IBSClient() as client:
            outcomes = await reconcile_ibs_track_releases(
                candidates, client=client, fetcher_name=self.name
            )
        failed = sum(1 for outcome in outcomes if outcome.kind == "failed")
        if failed == len(outcomes):
            raise FetcherError(all_failed_message(failed))
