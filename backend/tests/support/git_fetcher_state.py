"""Source-independent helpers of the production `BaseGitFetcher` tests.

Consumers, through the per-source helpers that add the source's fictional
commit identity, record paths, and fixtures:

- `tests/support/kernel_fetcher.py`, with
  `tests/test_services/test_tickets/test_sync_kernel_cves_execute.py` and
  `test_sync_kernel_cves_reachability.py`;
- `tests/support/mitre_fetcher.py`, with
  `tests/test_services/test_tickets/test_sync_mitre_cves_execute.py`,
  `test_sync_mitre_cves_reachability.py`, and `test_sync_mitre_cves_kev.py`.

Provided here:

- `commit()`, which commits upstream changes with a given author identity,
  so a source helper can use one distinct from the hermetic default and a
  log-privacy assertion can prove that no commit author reaches a log;
- `committed_fetcher_rows()`, the count of committed `FetcherRun` and
  `FetcherConfig` rows of one fetcher name;
- the committed Ticket, audit, reference, and CVSS assessment reads the
  tests assert on.

Nothing here computes an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import NamedTuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_reference import TicketReference
from tests.support.git_fetchers import Upstream
from tests.support.git_repos import git, rev_parse


def commit(
    upstream: Upstream,
    files: Mapping[str, bytes | None],
    *,
    date: str,
    author_name: str,
    author_email: str,
    message: str,
) -> str:
    """Write (`bytes`) or delete (`None`) paths and commit them at `date`
    as `author_name <author_email>` (author and committer); return the
    commit SHA."""
    for relative, content in files.items():
        target = upstream.path / relative
        if content is None:
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    git(upstream.path, "add", "--all")
    git(
        upstream.path,
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        message,
        env_extra={
            "GIT_AUTHOR_NAME": author_name,
            "GIT_AUTHOR_EMAIL": author_email,
            "GIT_COMMITTER_NAME": author_name,
            "GIT_COMMITTER_EMAIL": author_email,
            "GIT_AUTHOR_DATE": date,
            "GIT_COMMITTER_DATE": date,
        },
    )
    return rev_parse(upstream.path / ".git", "HEAD")


# ---------------------------------------------------------------------------
# Committed state
# ---------------------------------------------------------------------------


async def committed_fetcher_rows(
    factory: async_sessionmaker[AsyncSession], fetcher_name: str
) -> int:
    """Committed `FetcherRun` plus `FetcherConfig` rows named
    `fetcher_name`."""
    async with factory() as session:
        runs = await session.scalar(
            select(func.count())
            .select_from(FetcherRun)
            .where(FetcherRun.fetcher_name == fetcher_name)
        )
        configs = await session.scalar(
            select(func.count())
            .select_from(FetcherConfig)
            .where(FetcherConfig.fetcher_name == fetcher_name)
        )
    return int(runs or 0) + int(configs or 0)


async def ticket_of(
    factory: async_sessionmaker[AsyncSession], cve_pk: uuid.UUID
) -> Ticket | None:
    async with factory() as session:
        ticket: Ticket | None = await session.scalar(
            select(Ticket).where(Ticket.cve_id == cve_pk)
        )
    return ticket


class AuditRow(NamedTuple):
    event_type: str
    user_id: uuid.UUID | None
    old_value: str | None
    new_value: str | None
    comment: str | None


async def audit_events(
    factory: async_sessionmaker[AsyncSession], ticket_id: uuid.UUID
) -> list[AuditRow]:
    """Every committed Ticket audit event, in insertion order."""
    async with factory() as session:
        rows = await session.execute(
            select(
                TicketAuditEvent.event_type,
                TicketAuditEvent.user_id,
                TicketAuditEvent.old_value,
                TicketAuditEvent.new_value,
                TicketAuditEvent.comment,
            )
            .where(TicketAuditEvent.ticket_id == ticket_id)
            .order_by(TicketAuditEvent.id)
        )
    return [AuditRow(*row) for row in rows]


class ReferenceRow(NamedTuple):
    url: str
    title: str | None
    type: str | None
    source: str


async def references(
    factory: async_sessionmaker[AsyncSession], ticket_id: uuid.UUID
) -> list[ReferenceRow]:
    """Every committed Ticket reference, in insertion order (UUIDv7)."""
    async with factory() as session:
        rows = await session.execute(
            select(
                TicketReference.url,
                TicketReference.title,
                TicketReference.type,
                TicketReference.source,
            )
            .where(TicketReference.ticket_id == ticket_id)
            .order_by(TicketReference.id)
        )
    return [ReferenceRow(*row) for row in rows]


class AssessmentRow(NamedTuple):
    provider_name: str
    cvss_version: str
    vector_string: str


async def assessments(
    factory: async_sessionmaker[AsyncSession], cve_pk: uuid.UUID
) -> list[AssessmentRow]:
    """Every committed CVSS assessment of one CVE, by provider and version."""
    async with factory() as session:
        rows = await session.execute(
            select(
                CVECVSSAssessment.provider_name,
                CVECVSSAssessment.cvss_version,
                CVECVSSAssessment.vector_string,
            )
            .where(CVECVSSAssessment.cve_id == cve_pk)
            .order_by(CVECVSSAssessment.provider_name, CVECVSSAssessment.cvss_version)
        )
    return [AssessmentRow(*row) for row in rows]
