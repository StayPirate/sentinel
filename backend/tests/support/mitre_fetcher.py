"""Shared helpers of the `SyncMitreCves` integration tests
(backend/app/services/tickets/sync_mitre_cves.py).

Consumers:

- `tests/test_services/test_tickets/test_sync_mitre_cves_execute.py` (the
  inherited `execute()` of the real class through `BaseFetcher.run()`);
- `tests/test_services/test_tickets/test_sync_mitre_cves_reachability.py`
  (the on-demand, catch-up, publication, bootstrap, and schedule paths of
  the real class);
- `tests/test_services/test_tickets/test_sync_mitre_cves_kev.py` (the KEV
  projection and the MITRE/KEV overlap through the real class).

Provided here:

- `mitre_probe()`, the `GitFetcherProbe` of the production class: the
  `GitRunHarness` and `GitWorkspace` helpers of `tests/support/git_fetchers.py`
  read only its `name`, `cls`, and `clone_dir_name`, so no test-only fetcher
  is defined;
- `record_path()` and `derived_record()`, which re-key a sanitized record
  fixture of `tests/support/mitre.py` to a fictional CVE-ID at its
  `cves/YEAR/NNNxxx/` path and apply an optional edit;
- `commit()`, which commits upstream changes with a fictional author
  identity distinct from the hermetic default, so a log-privacy assertion
  can prove that no commit author reaches a log;
- the committed CVE child reads the MITRE mapping adds to those of
  `tests/support/git_fetcher_state.py`: SSVC, KEV, CWE, and affected
  versions.

Nothing here computes an expectation with the module under test. All
identifiers, names, and e-mail addresses are fictional.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from datetime import date, datetime
from typing import Any, Final, NamedTuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_cwe import CVECWE
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.services.tickets.sync_mitre_cves import SyncMitreCves
from tests.support import git_fetcher_state
from tests.support.git_fetchers import GitFetcherProbe, Upstream
from tests.support.mitre import load_record

NAME: Final = "sync_mitre_cves"
CLONE_DIR: Final = "cvelistV5"

AUTHOR_NAME: Final = "Fictional CVE Automation"
AUTHOR_EMAIL: Final = "cvelist-automation@example.test"
"""The identity of every upstream commit these helpers create."""

RecordEdit = Callable[[dict[str, Any]], None]


def mitre_probe(events: list[str]) -> GitFetcherProbe:
    """The production class as the harness's probe."""
    return GitFetcherProbe(
        cls=SyncMitreCves, name=NAME, clone_dir_name=CLONE_DIR, events=events
    )


def record_path(cve_id: str) -> str:
    """`cves/<year>/<thousands>xxx/<cve_id>.json`: the sequence without its
    last three digits names the bucket (`0` below one thousand)."""
    _, year, sequence = cve_id.split("-")
    bucket = sequence[:-3].lstrip("0") or "0"
    return f"cves/{year}/{bucket}xxx/{cve_id}.json"


def derived_record(fixture: str, cve_id: str, edit: RecordEdit | None = None) -> bytes:
    """The record fixture with `cveMetadata.cveId` set to `cve_id`, with
    `edit` applied, serialized with a two-space indent."""
    record = load_record(fixture)
    record["cveMetadata"]["cveId"] = cve_id
    if edit is not None:
        edit(record)
    return json.dumps(record, indent=2).encode()


def cna(record: dict[str, Any]) -> dict[str, Any]:
    """The `containers.cna` object of a parsed record."""
    container: dict[str, Any] = record["containers"]["cna"]
    return container


def adps(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The `containers.adp` array of a parsed record."""
    entries: list[dict[str, Any]] = record["containers"]["adp"]
    return entries


def commit(upstream: Upstream, files: Mapping[str, bytes | None], *, date: str) -> str:
    """Write (`bytes`) or delete (`None`) paths and commit them at `date`
    as the fictional author; return the commit SHA."""
    return git_fetcher_state.commit(
        upstream,
        files,
        date=date,
        author_name=AUTHOR_NAME,
        author_email=AUTHOR_EMAIL,
        message="example: fictional cvelistV5 change",
    )


# ---------------------------------------------------------------------------
# Committed CVE children
# ---------------------------------------------------------------------------


class SsvcRow(NamedTuple):
    exploitation: str
    automatable: str
    technical_impact: str
    version: str
    assessed_at: datetime | None


async def ssvc(
    factory: async_sessionmaker[AsyncSession], cve_pk: uuid.UUID
) -> list[SsvcRow]:
    """The committed SSVC assessment rows of one CVE."""
    async with factory() as session:
        rows = await session.execute(
            select(
                CVESSVCAssessment.exploitation,
                CVESSVCAssessment.automatable,
                CVESSVCAssessment.technical_impact,
                CVESSVCAssessment.version,
                CVESSVCAssessment.assessed_at,
            ).where(CVESSVCAssessment.cve_id == cve_pk)
        )
    return [SsvcRow(*row) for row in rows]


class KevRow(NamedTuple):
    date_added: date
    reference_url: str | None


async def kev(
    factory: async_sessionmaker[AsyncSession], cve_pk: uuid.UUID
) -> list[KevRow]:
    """The committed KEV entry rows of one CVE."""
    async with factory() as session:
        rows = await session.execute(
            select(CVEKEVEntry.date_added, CVEKEVEntry.reference_url).where(
                CVEKEVEntry.cve_id == cve_pk
            )
        )
    return [KevRow(*row) for row in rows]


async def cwes(
    factory: async_sessionmaker[AsyncSession], cve_pk: uuid.UUID
) -> list[tuple[str, str]]:
    """Every committed `(cwe_id, source)` of one CVE, sorted."""
    async with factory() as session:
        rows = await session.execute(
            select(CVECWE.cwe_id, CVECWE.source)
            .where(CVECWE.cve_id == cve_pk)
            .order_by(CVECWE.source, CVECWE.cwe_id)
        )
    return [(cwe_id, source) for cwe_id, source in rows]


class AffectedRow(NamedTuple):
    source_container: str
    vendor: str | None
    product: str | None
    version: str | None
    version_type: str | None
    version_end: str | None
    version_end_inclusive: bool | None
    cpe: str | None
    status: str | None
    default_status: str | None


async def affected_versions(
    factory: async_sessionmaker[AsyncSession], cve_pk: uuid.UUID
) -> list[AffectedRow]:
    """Every committed affected-version row of one CVE, by scope and
    version."""
    async with factory() as session:
        rows = await session.execute(
            select(
                CVEAffectedVersion.source_container,
                CVEAffectedVersion.vendor,
                CVEAffectedVersion.product,
                CVEAffectedVersion.version,
                CVEAffectedVersion.version_type,
                CVEAffectedVersion.version_end,
                CVEAffectedVersion.version_end_inclusive,
                CVEAffectedVersion.cpe,
                CVEAffectedVersion.status,
                CVEAffectedVersion.default_status,
            )
            .where(CVEAffectedVersion.cve_id == cve_pk)
            .order_by(CVEAffectedVersion.source_container, CVEAffectedVersion.version)
        )
    return [AffectedRow._make(row) for row in rows]
