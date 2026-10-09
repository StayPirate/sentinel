"""Shared helpers of the `SyncKernelCves` integration tests
(backend/app/services/tickets/sync_kernel_cves.py).

Consumers:

- `tests/test_services/test_tickets/test_sync_kernel_cves_execute.py` (the
  inherited `execute()` of the real class through `BaseFetcher.run()`);
- `tests/test_services/test_tickets/test_sync_kernel_cves_reachability.py`
  (the on-demand, catch-up, publication, bootstrap, and schedule paths of
  the real class).

Provided here:

- `kernel_probe()`, the `GitFetcherProbe` of the production class: the
  `GitRunHarness` and `GitWorkspace` helpers of `tests/support/git_fetchers.py`
  read only its `name`, `cls`, and `clone_dir_name`, so no test-only fetcher
  is defined;
- `record_path()` and `derived_record()`, which re-key a sanitized record
  fixture of `tests/support/kernel.py` to a fictional CVE-ID and apply an
  optional edit;
- `commit()`, which commits upstream changes with a fictional author
  identity distinct from the hermetic default, so a log-privacy assertion
  can prove that no commit author reaches a log;
- the committed persisted-state reads the tests assert on, and
  `committed_fetcher_rows()`, the count of committed `FetcherRun` and
  `FetcherConfig` rows of the fetcher name.

Nothing here computes an expectation with the module under test. All
identifiers, names, and e-mail addresses are fictional.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Final, NamedTuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_reference import TicketReference
from app.services.tickets.sync_kernel_cves import SyncKernelCves
from tests.support.git_fetchers import GitFetcherProbe, Upstream
from tests.support.git_repos import git, rev_parse
from tests.support.kernel import load_record

NAME: Final = "sync_kernel_cves"
CLONE_DIR: Final = "vulns.git"

AUTHOR_NAME: Final = "Fictional Kernel Maintainer"
AUTHOR_EMAIL: Final = "kernel-maintainer@example.test"
"""The identity of every upstream commit these helpers create."""

_IDENTITY: Final = {
    "GIT_AUTHOR_NAME": AUTHOR_NAME,
    "GIT_AUTHOR_EMAIL": AUTHOR_EMAIL,
    "GIT_COMMITTER_NAME": AUTHOR_NAME,
    "GIT_COMMITTER_EMAIL": AUTHOR_EMAIL,
}

RecordEdit = Callable[[dict[str, Any]], None]


def kernel_probe(events: list[str]) -> GitFetcherProbe:
    """The production class as the harness's probe."""
    return GitFetcherProbe(
        cls=SyncKernelCves, name=NAME, clone_dir_name=CLONE_DIR, events=events
    )


def record_path(state: str, cve_id: str) -> str:
    """`cve/<state>/<year>/<cve_id>.json`."""
    return f"cve/{state}/{cve_id.split('-')[1]}/{cve_id}.json"


def derived_record(fixture: str, cve_id: str, edit: RecordEdit | None = None) -> bytes:
    """The record fixture re-keyed to `cve_id` (under the CVE-ID key it
    already uses), with `edit` applied, serialized with a two-space indent."""
    record = load_record(fixture)
    metadata = record["cveMetadata"]
    metadata["cveId" if "cveId" in metadata else "cveID"] = cve_id
    if edit is not None:
        edit(record)
    return json.dumps(record, indent=2).encode()


def cna(record: dict[str, Any]) -> dict[str, Any]:
    """The `containers.cna` object of a parsed record."""
    container: dict[str, Any] = record["containers"]["cna"]
    return container


def commit(upstream: Upstream, files: Mapping[str, bytes | None], *, date: str) -> str:
    """Write (`bytes`) or delete (`None`) paths and commit them at `date`
    as the fictional author; return the commit SHA."""
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
        "example: fictional vulns.git change",
        env_extra={**_IDENTITY, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date},
    )
    return rev_parse(upstream.path / ".git", "HEAD")


# ---------------------------------------------------------------------------
# Committed state
# ---------------------------------------------------------------------------


async def committed_fetcher_rows(factory: async_sessionmaker[AsyncSession]) -> int:
    """Committed `FetcherRun` plus `FetcherConfig` rows named `NAME`."""
    async with factory() as session:
        runs = await session.scalar(
            select(func.count())
            .select_from(FetcherRun)
            .where(FetcherRun.fetcher_name == NAME)
        )
        configs = await session.scalar(
            select(func.count())
            .select_from(FetcherConfig)
            .where(FetcherConfig.fetcher_name == NAME)
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
