"""`sync_mitre_cves`: MITRE CVE Program fetcher (`cvelistV5`).

Implements docs/features/tickets/cve-sync-mitre.md (Fetcher Definition,
Algorithm, Caller WARNING fields, `fetch_single()` Behavior, Error Handling)
on the `BaseGitFetcher` template of
docs/features/platform/git-fetcher-infrastructure.md:

- the inherited `execute()` keeps the bare clone of `cvelistV5`, computes
  the delta under `cves/`, and finalizes every item through
  `commit_and_dispatch()`; the inherited `fetch_single()` reads the single
  record path at `HEAD`; `catch_up()` is the inherited `BaseCVEFetcher`
  default and `queue` the inherited `"git"`;
- `filter_delta_files()` keeps only the record paths
  `cves/YEAR/NNNxxx/CVE-YEAR-SEQ.json` with a canonical CVE-ID, which drops
  `cves/delta.json` and `cves/deltaLog.json`; the default
  `deduplicate_items()` applies, since one CVE has one path;
- `process_item()` maps the record (`mitre_cve_record.map_record()`), logs
  the bounded WARNINGs of the facts the mapping reports, then ingests it
  through `cve_service.upsert_cve()` and
  `reference_service.upsert_references()` in the caller's per-CVE
  transaction. Every failure propagates to the template's per-item
  boundary, which logs only the exception class name.

`cve_service` and `reference_service` are imported as module objects and
dereferenced at call time: `cve_service` belongs to the import cycle of
`base_cve_fetcher`.
"""

from __future__ import annotations

from typing import Final

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType
from app.core.identifiers import is_valid_cve_id
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import CVEFetchResult
from app.services.base_git_fetcher import BaseGitFetcher
from app.services.tickets import mitre_cve_record

logger = structlog.get_logger(__name__)

ADP_ENTRY_SKIPPED_EVENT: Final = "mitre_adp_entry_skipped"
CNA_PROVIDER_SKIPPED_EVENT: Final = "mitre_cna_provider_skipped"
SSVC_ASSESSMENT_SKIPPED_EVENT: Final = "mitre_ssvc_assessment_skipped"


class SyncMitreCves(BaseGitFetcher):
    """Sync CVE data from the MITRE cvelistV5 repository."""

    name = "sync_mitre_cves"
    cve_source_type = CVESourceType.MITRE
    description = "Sync CVE data from the MITRE cvelistV5 repository"
    default_schedule = "0 */6 * * *"
    default_request_delay = 0

    source_reference_url_pattern = mitre_cve_record.SOURCE_REFERENCE_URL_PATTERN

    repo_url = "https://github.com/CVEProject/cvelistV5.git"
    clone_dir_name = "cvelistV5"
    delta_path_prefix = "cves/"
    recovery_path_prefix = "cves/"

    def filter_delta_files(self, file_list: list[str]) -> list[str]:
        """Algorithm step 1: the structural record paths with a canonical
        file-name CVE-ID; every other path is a pre-scope exclusion."""
        return [path for path in file_list if _is_record_path(path)]

    def _construct_candidate_paths(self, item_id: str) -> list[str]:
        """`fetch_single()` step 1: the single record path
        `cves/{year}/{seq // 1000}xxx/{cve_id}.json`. `ValueError` for a
        value that is not a canonical CVE-ID."""
        if not is_valid_cve_id(item_id):
            raise ValueError("item_id is not a canonical CVE-ID")
        _, year, sequence = item_id.split("-")
        return [f"cves/{year}/{int(sequence) // 1000}xxx/{item_id}.json"]

    async def process_item(
        self, path: str, content: bytes, session: AsyncSession
    ) -> CVEFetchResult:
        """Map and ingest one record file (Algorithm step 2).

        Category A source ingestion into the caller-owned per-CVE session.

        Q1: `path` is the record path relative to the repository root,
        `content` its bytes at `HEAD`, `session` the caller's session.

        Q2: the complete mapping, including the payload validation,
        precedes every write; the WARNINGs of the reported facts follow it.

        Q3: one bounded WARNING per reported fact, then `upsert_cve()` with
        the mapped payload, then `upsert_references()` with the source
        reference first and the CNA `references[]` candidates in array
        order, `source = self.name`. Adds no flush beyond its delegates'
        own, never commits, and records no metric.

        Q4: `CVEFetchResult` with the effective `UpsertResult.action` and
        the package-candidate handoff.

        Q5: idempotent through `upsert_cve()` and the reference merge; the
        WARNINGs repeat for an unchanged record.

        Q6: `MitreRecordError` subclasses and the payload's
        `pydantic.ValidationError` from the mapping, and every delegate
        exception, propagate unchanged.
        """
        record = mitre_cve_record.map_record(path, content)
        _log_skipped_data(record, self.name)
        result = await cve_service.upsert_cve(
            session, record.cve_id, self.cve_source_type, record.payload
        )
        await reference_service.upsert_references(
            session,
            result.ticket.id,
            record.cve_id,
            self.name,
            record.source_reference,
            record.upstream_references,
        )
        return CVEFetchResult(
            result.action, cve_service.build_post_ingest_tasks(result, record.payload)
        )


def _log_skipped_data(record: mitre_cve_record.MitreRecord, fetcher_name: str) -> None:
    """The caller WARNINGs of cve-sync-mitre.md: only the bounded facts the
    mapping reports, never a raw upstream value."""
    for adp in record.skipped_adps:
        logger.warning(
            ADP_ENTRY_SKIPPED_EVENT,
            cve_id=record.cve_id,
            fetcher_name=fetcher_name,
            **_org_id_field(adp.org_id),
        )
    if record.cna_guard is not None:
        logger.warning(
            CNA_PROVIDER_SKIPPED_EVENT,
            cve_id=record.cve_id,
            fetcher_name=fetcher_name,
            reason=record.cna_guard.reason,
            **_org_id_field(record.cna_guard.org_id),
        )
    for skip in record.ssvc_skips:
        logger.warning(
            SSVC_ASSESSMENT_SKIPPED_EVENT,
            cve_id=record.cve_id,
            fetcher_name=fetcher_name,
            reason=skip.reason,
            missing_fields=list(skip.missing_fields),
        )


def _is_record_path(path: str) -> bool:
    match = mitre_cve_record.RECORD_PATH_PATTERN.fullmatch(path)
    return match is not None and is_valid_cve_id(match["cve_id"])


def _org_id_field(org_id: str | None) -> dict[str, str]:
    """`{"org_id": org_id}` when the mapping kept a UUID-shaped value."""
    return {} if org_id is None else {"org_id": org_id}
