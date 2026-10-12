"""`detect_ibs_product_releases`: IBS Product release detection fetcher.

Implements docs/features/packages/ibs-product-release-detection.md
(Fetcher: `detect_ibs_product_releases`: Algorithm, Catch-Up, Error
Handling, Metrics and Run Status). Both `execute()` and `catch_up()`
select their occurrences read-only with
`load_product_release_candidates()`, end that read transaction, and
delegate to `reconcile_ibs_product_releases()`, which owns the repository
I/O, the independent per-occurrence transactions, and the Ticket
convergence drain. Neither method takes a Ticket lock.

Periodic metrics are recorded through the boundary's per-outcome hook:
`updated` is succeeded and updated, `no_op` (no match, already released,
or stale) is succeeded, `failed` is failed; nothing is ever created. A
candidate enumeration failure becomes the sanitized
`FetcherError("Failed to enumerate IBS Product release candidates")`.

`catch_up()` uses the passed session only to enumerate the Ticket's
occurrences in the same Scope (a missing, inactive, or CVE-less Ticket,
or no unreleased IBS occurrence, returns silently), reports no metric,
returns normally on partial success, and raises the non-retryable
`FetcherError("All {failed} IBS Product release occurrences failed")`
when every selected occurrence failed.
"""

from __future__ import annotations

import uuid
from typing import Any, ClassVar, Final

import httpx
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.base_fetcher import BaseFetcher, FetcherError
from app.services.packages.ibs_product_release import (
    ProductReleaseOutcome,
    load_product_release_candidates,
    reconcile_ibs_product_releases,
)

ENUMERATION_FAILED_MESSAGE: Final = "Failed to enumerate IBS Product release candidates"


def all_failed_message(failed: int) -> str:
    """The sanitized public message of an all-failed catch-up."""
    return f"All {failed} IBS Product release occurrences failed"


class DetectIbsProductReleases(BaseFetcher):
    """Reconcile unreleased IBS Product occurrences against updateinfo."""

    name = "detect_ibs_product_releases"
    description = (
        "Reconcile unreleased active-Ticket IBS Product occurrences against "
        "validated updateinfo advisories"
    )
    default_schedule = "0 4 * * *"
    participates_in_catch_up = True
    http_client_options: ClassVar[dict[str, Any]] = {
        "timeout": httpx.Timeout(10.0, read=120.0)
    }

    async def execute(self, session: AsyncSession) -> None:
        # Step 1: select and snapshot the scope; the read ends before I/O.
        try:
            candidates = await load_product_release_candidates(session)
            await session.commit()
        except SQLAlchemyError as exc:
            raise FetcherError(ENUMERATION_FAILED_MESSAGE) from exc

        # Steps 2-5: tiers, repository reuse, independent transactions.
        await reconcile_ibs_product_releases(
            candidates,
            client=self.http_client,
            fetcher_name=self.name,
            on_outcome=self._record_outcome,
        )

    def _record_outcome(self, outcome: ProductReleaseOutcome) -> None:
        if outcome.kind == "failed":
            self.record_failed()
            return
        self.record_succeeded()
        if outcome.kind == "updated":
            self.record_updated()

    async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
        """Reconcile one Ticket's unreleased IBS Product occurrences.

        ibs-product-release-detection.md (Catch-Up). The passed session
        only reads; every mutation runs in its own session inside the
        boundary. Returns silently when nothing is selected. A
        pre-finalization failure of some occurrences returns normally
        after their warnings; when every selected occurrence failed,
        raises the non-retryable `FetcherError`. Commit exceptions and
        non-operational drain exceptions propagate unchanged.
        """
        candidates = await load_product_release_candidates(
            session, ticket_id=uuid.UUID(ticket_id)
        )
        await session.commit()
        if not candidates:
            return

        summary = await reconcile_ibs_product_releases(
            candidates, client=self.http_client, fetcher_name=self.name
        )
        if summary.failed == summary.selected:
            raise FetcherError(all_failed_message(summary.failed))
