"""Shared helpers for the trusted-external CVSS batch tests.

Consumers:

- `tests/test_services/test_upsert_external_cvss_batch.py` (guards, the
  empty and all-unchanged batches, the status matrix, canonical ordering,
  propagation, gate, priority, and lock order of
  `upsert_external_cvss_batch()`);
- `tests/test_services/test_upsert_external_cvss_batch_atomicity.py`
  (whole-chain rollback, the supplied evaluation date, and the
  independent-session CVSS/CVSS, CVSS/override, CVSS/reactivation, and
  default-version/CVSS races of the batch).

The helpers are generic over provider, vector, CVE, and session, so the
racing sessions of the atomicity module use them unchanged.

Inputs are built with `cvss.validate_cvss_vector()` because the batch
requires the parser's stable result as its input; that is input
construction, not an expectation. Expected values are the transcribed
`Vector` constants of `tests/support/suse_cvss.py`; nothing here computes
an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.cvss import validate_cvss_vector
from app.services.ticket_mutations import (
    ExternalCVSSBatchResult,
    ParsedExternalCVSSAssessment,
    upsert_external_cvss_batch,
)
from tests.support.suse_cvss import Vector
from tests.support.ticket_mutations import EVAL, EventRow


def external(provider: str, vector: Vector) -> ParsedExternalCVSSAssessment:
    """One batch candidate: `provider` with the parser's stable result of
    `vector`'s canonical form."""
    return ParsedExternalCVSSAssessment(
        provider=provider, parsed=validate_cvss_vector(vector.canonical)
    )


def external_value(provider: str, vector: Vector) -> str:
    """The canonical `cvss_assessment_changed` value of an external
    assessment (ticket-audit-log.md, Event Type Contract)."""
    return f"{provider} v{vector.version} {vector.canonical} ({vector.score})"


def external_cvss_event(old: str | None, new: str | None) -> EventRow:
    """The system `cvss_assessment_changed` event of trusted external
    ingestion (`user_id`, `comment`, and `detail` `NULL`)."""
    return EventRow("cvss_assessment_changed", None, old, new, None, None)


async def run_batch(
    db: AsyncSession,
    cve_id: uuid.UUID,
    *assessments: ParsedExternalCVSSAssessment,
    evaluation_date: date = EVAL,
) -> ExternalCVSSBatchResult:
    """Call the batch as `cve_service.upsert_cve()` would, with the fixed
    `EVAL` by default."""
    return await upsert_external_cvss_batch(
        db, cve_id=cve_id, assessments=assessments, evaluation_date=evaluation_date
    )
