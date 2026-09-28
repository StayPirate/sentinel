"""Shared expectations for the Ticket creation tests.

Consumers:

- `tests/test_services/test_create_ticket.py` (event order and fields,
  ingestion labels, conflict, rejected CVE);
- `tests/test_services/test_create_ticket_atomicity.py` (independent-session
  races and whole-transaction rollback);
- the `POST /api/v1/tickets` end-to-end tests, which assert the same
  creation event contract through the HTTP boundary.

Every expected value is transcribed from the specifications
(docs/features/tickets/ticket-audit-log.md, Event Type Contract and
Canonical Automatic Comment Vocabulary; docs/features/tickets/cve-service.md,
`upsert_cve()` Parameter `source`; docs/features/tickets/ticket-service.md,
`create_ticket`). Nothing here computes an expectation with the module under
test: the ingestion labels are a literal copy of the cve-service.md table,
not a reference to `CVE_SOURCE_AUDIT_LABELS`.
"""

from __future__ import annotations

import uuid

from app.core.enums import CVESourceType
from tests.support.ticket_mutations import EventRow

MANUAL_COMMENT = "Ticket created manually"
"""The exact manual `ticket_created.comment`."""

INGESTION_LABELS: dict[CVESourceType, str] = {
    CVESourceType.NVD: "NVD",
    CVESourceType.MITRE: "MITRE",
    CVESourceType.KERNEL: "Linux Kernel CNA",
    CVESourceType.REDHAT: "Red Hat",
    CVESourceType.GHSA: "GitHub Advisory Database",
    CVESourceType.OSV: "OSV",
    CVESourceType.KEV: "CISA KEV",
    CVESourceType.EPSS: "FIRST.org EPSS",
}
"""The cve-service.md audit label of every `CVESourceType` member."""


def creation_events(
    *,
    creator_id: uuid.UUID | None,
    comment: str = MANUAL_COMMENT,
    assignee_username: str | None = None,
    severity: str | None = None,
    coordinated_release: str | None = None,
    cve_id: str | None = None,
    priority: str | None = None,
) -> list[EventRow]:
    """The complete expected creation history, in the contractual order.

    `creator_id` is the creating User (`None` for a CVE-ingestion creation);
    `comment` the exact `ticket_created.comment`; `assignee_username` the
    active VA creator's username when the creation assigns;
    `severity` the PascalCase manual severity label;
    `coordinated_release` the UTC ISO 8601 `Z` value of the Coordinated
    Release Date; `cve_id` the associated CVE-ID string; `priority` the
    automatic priority of the final system `priority_changed` (manual
    creation only). Each `None` omits its optional event. Every comment but
    the first is `NULL` and every `detail` is `NULL`.
    """
    events = [EventRow("ticket_created", creator_id, None, None, comment, None)]
    if assignee_username is not None:
        events.append(
            EventRow("assignment", creator_id, None, assignee_username, None, None)
        )
    if severity is not None:
        events.append(
            EventRow("severity_changed", creator_id, None, severity, None, None)
        )
    if coordinated_release is not None:
        events.append(
            EventRow(
                "coordinated_release_changed",
                creator_id,
                None,
                coordinated_release,
                None,
                None,
            )
        )
    if cve_id is not None:
        events.append(EventRow("cve_associated", creator_id, None, cve_id, None, None))
    if priority is not None:
        events.append(EventRow("priority_changed", None, None, priority, None, None))
    return events


def ingestion_comment(source: CVESourceType) -> str:
    """The exact `ticket_created.comment` of a CVE-ingestion creation."""
    return f"CVE ingested from {INGESTION_LABELS[source]}"
