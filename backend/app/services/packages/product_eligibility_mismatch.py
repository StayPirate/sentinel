"""Shared Product eligibility-mismatch scan.

The one read-only discovery of catalog Products whose stored system-managed
`TicketPackageProduct.eligible` on an operable Ticket differs from the
complete current automatic result. Used after the threshold publication of
`sync_aimaas_thresholds` (docs/features/packages/product-catalog.md, CVSS
Threshold Sync step 9) and by `evaluate_lifecycle_transitions`
(docs/features/packages/product-lifecycle-transitions.md, Algorithm step 2).

Operable Tickets are `New`, `Analysis`, `Analyzed`, and `Resolved`.
Directly or effectively excluded occurrences and EOL Products are included:
exclusion and actionability do not suspend factual eligibility maintenance.
Manual overrides never mismatch.

The SQL statement only reduces the occurrences to their distinct
`(Product, CVE, stored value, threshold, lifecycle phase)` combinations;
the mismatch itself is decided by the shared pure evaluator
(`product_eligibility.evaluate_product_eligibility()`) over the Eligibility
Score Resolution of each CVE (`cvss.resolve_eligibility_score()`), so the
eligibility formula has no SQL copy (docs/features/packages/package-model.md,
Axis 2: Eligibility). Mutation always recomputes from current persisted
inputs under the Ticket lock; this scan only selects Products.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Sequence
from datetime import date
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import LifecyclePhase
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import settings as settings_service
from app.services.cvss import EligibilityResolution, resolve_eligibility_score
from app.services.packages.product_eligibility_recalculation import (
    OPERABLE_TICKET_STATUSES,
)
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.product_service import lifecycle_phase_expression

# CVE IDs per assessment SELECT, far below the PostgreSQL bind-parameter limit.
_CVE_CHUNK_SIZE: Final = 1000


async def find_product_eligibility_mismatches(
    db: AsyncSession, *, evaluation_date: date
) -> frozenset[uuid.UUID]:
    """Return the catalog Product IDs with an eligibility mismatch.

    Category B (read-only; no lock, write, audit, commit, or rollback).

    Q1: `evaluation_date` is the caller's one UTC date used for every
    lifecycle-dependent comparison.

    Q3: selects the distinct combinations of catalog Product, Ticket CVE,
    stored `eligible`, `Product.cvss_threshold`, and lifecycle phase on
    `evaluation_date` over system-managed occurrences (`is_eligible_override
    = false`) of operable Tickets, including excluded and EOL occurrences;
    reads the current `default_cvss_version` once and the complete
    assessment set of each distinct CVE; resolves one eligibility score per
    CVE (the `10.0` fallback for a CVE-less Ticket) and applies the shared
    pure evaluator to every combination. Reads no setting when no
    system-managed operable occurrence exists.

    Q4: the set of Product IDs having at least one mismatching
    combination; each Product appears once.

    Q6: `RequiredSystemSettingMissingError`, `ValueError` from an invalid
    default version or assessment set, and database exceptions propagate.
    """
    lifecycle = lifecycle_phase_expression(evaluation_date).label("lifecycle")
    rows = (
        await db.execute(
            select(
                TicketPackageProduct.product_id,
                Ticket.cve_id,
                TicketPackageProduct.eligible,
                Product.cvss_threshold,
                lifecycle,
            )
            .join(
                TicketPackageTrack,
                TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
            )
            .join(
                TicketPackage,
                TicketPackage.id == TicketPackageTrack.ticket_package_id,
            )
            .join(Ticket, Ticket.id == TicketPackage.ticket_id)
            .join(Product, Product.id == TicketPackageProduct.product_id)
            .where(
                TicketPackageProduct.is_eligible_override.is_(False),
                Ticket.status.in_(OPERABLE_TICKET_STATUSES),
            )
            .distinct()
        )
    ).all()
    if not rows:
        return frozenset()

    default_cvss_version = await settings_service.get_default_cvss_version(db)
    scores = await _eligibility_scores(
        db,
        {row.cve_id for row in rows if row.cve_id is not None},
        default_cvss_version,
    )
    fallback = resolve_eligibility_score((), default_cvss_version)

    mismatches: set[uuid.UUID] = set()
    for row in rows:
        expected = evaluate_product_eligibility(
            is_eligible_override=False,
            lifecycle_phase=(
                LifecyclePhase(row.lifecycle) if row.lifecycle is not None else None
            ),
            cvss_threshold=row.cvss_threshold,
            eligibility_score=(fallback if row.cve_id is None else scores[row.cve_id]),
        ).automatic_eligible
        if expected != row.eligible:
            mismatches.add(row.product_id)
    return frozenset(mismatches)


async def _eligibility_scores(
    db: AsyncSession, cve_ids: set[uuid.UUID], default_cvss_version: str
) -> dict[uuid.UUID, EligibilityResolution]:
    """Resolve the eligibility score of every CVE from its complete set."""
    assessments: dict[uuid.UUID, list[CVECVSSAssessment]] = defaultdict(list)
    ordered: Sequence[uuid.UUID] = sorted(cve_ids)
    for start in range(0, len(ordered), _CVE_CHUNK_SIZE):
        chunk = ordered[start : start + _CVE_CHUNK_SIZE]
        for assessment in (
            await db.execute(
                select(CVECVSSAssessment)
                .where(CVECVSSAssessment.cve_id.in_(chunk))
                .execution_options(populate_existing=True)
            )
        ).scalars():
            assessments[assessment.cve_id].append(assessment)
    return {
        cve_id: resolve_eligibility_score(assessments[cve_id], default_cvss_version)
        for cve_id in ordered
    }
