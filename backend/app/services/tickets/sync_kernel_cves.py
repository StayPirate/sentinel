"""`sync_kernel_cves`: Linux Kernel CNA CVE fetcher (`vulns.git`).

Implements docs/features/tickets/cve-sync-kernel.md (Fetcher Definition,
Algorithm, Rejection Handling, `fetch_single()` Behavior) on the
`BaseGitFetcher` template of
docs/features/platform/git-fetcher-infrastructure.md:

- the inherited `execute()` keeps the bare clone of `vulns.git`, computes
  the delta under `cve/`, and finalizes every item through
  `commit_and_dispatch()`; the inherited `fetch_single()` reads the
  published, then the rejected, record at `HEAD`; `catch_up()` is the
  inherited `BaseCVEFetcher` default and `queue` the inherited `"git"`;
- `filter_delta_files()` keeps only the complete record paths
  `cve/{published,rejected}/YEAR/CVE-YEAR-ID.json` with a canonical
  CVE-ID, and `deduplicate_items()` keeps the `rejected/` path of a CVE
  present in both directories;
- `process_item()` maps the record (`kernel_cve_record.map_record()`),
  then ingests it through `cve_service.upsert_cve()` and
  `reference_service.upsert_references()` in the caller's per-CVE
  transaction. Every failure propagates to the template's per-item
  boundary.

`cve_service` and `reference_service` are imported as module objects and
dereferenced at call time: `cve_service` belongs to the import cycle of
`base_cve_fetcher`.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType
from app.core.identifiers import is_valid_cve_id
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import CVEFetchResult
from app.services.base_git_fetcher import BaseGitFetcher
from app.services.tickets import kernel_cve_record

_REJECTED_DIRECTORY = "rejected"
_RECORD_DIRECTORIES = ("published", _REJECTED_DIRECTORY)


class SyncKernelCves(BaseGitFetcher):
    """Sync CVE data from the Linux Kernel CNA vulnerability repository."""

    name = "sync_kernel_cves"
    cve_source_type = CVESourceType.KERNEL
    description = "Sync CVE data from the Linux Kernel CNA vulnerability repository"
    default_schedule = "0 */3 * * *"
    default_request_delay = 0

    source_reference_url_pattern = None  # constructed from the record path

    repo_url = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
    clone_dir_name = "vulns.git"
    delta_path_prefix = "cve/"
    recovery_path_prefix = "cve/"

    def filter_delta_files(self, file_list: list[str]) -> list[str]:
        """Algorithm step 1: the complete record paths with a canonical
        CVE-ID. Sibling files and the `reserved/`, `returned/`, `review/`,
        and `testing/` trees are pre-scope exclusions."""
        return [path for path in file_list if _record_cve_id(path) is not None]

    def deduplicate_items(self, file_list: list[str]) -> list[str]:
        """Algorithm step 2a: one path per CVE-ID; `rejected/` wins over
        `published/`. The order of the remaining paths is preserved."""
        winners: dict[str, str] = {}
        for path in file_list:
            match = kernel_cve_record.RECORD_PATH_PATTERN.fullmatch(path)
            if match is None:
                continue
            cve_id = match["cve_id"]
            if cve_id not in winners or match["state"] == _REJECTED_DIRECTORY:
                winners[cve_id] = path
        selected = set(winners.values())
        return [path for path in file_list if path in selected]

    def _construct_candidate_paths(self, item_id: str) -> list[str]:
        """`fetch_single()` step 1: the published, then the rejected, record
        path. `ValueError` for a value that is not a canonical CVE-ID."""
        if not self._is_valid_cve_id(item_id):
            raise ValueError("item_id is not a canonical CVE-ID")
        year = item_id.split("-")[1]
        return [
            f"cve/{directory}/{year}/{item_id}.json"
            for directory in _RECORD_DIRECTORIES
        ]

    async def process_item(
        self, path: str, content: bytes, session: AsyncSession
    ) -> CVEFetchResult:
        """Map and ingest one record file (Algorithm steps 2b-2h).

        Category A source ingestion into the caller-owned per-CVE session.

        Q1: `path` is the record path relative to the repository root,
        `content` its bytes at `HEAD`, `session` the caller's session.

        Q2: the complete mapping, including the payload validation,
        precedes every write.

        Q3: `upsert_cve()` with the mapped payload (`kernel-source` as the
        direct package-name candidate), then `upsert_references()` with the
        source reference first and the URL-only `references[]` candidates
        in array order, `source = self.name`. Adds no flush beyond its
        delegates' own, never commits, and records no metric.

        Q4: `CVEFetchResult` with the effective `UpsertResult.action` and
        the package-candidate handoff.

        Q5: idempotent through `upsert_cve()` and the reference merge.

        Q6: `KernelRecordError` subclasses and the payload's
        `pydantic.ValidationError` from the mapping, and every delegate
        exception, propagate unchanged.
        """
        record = kernel_cve_record.map_record(path, content)
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


def _record_cve_id(path: str) -> str | None:
    """The canonical CVE-ID of a complete record path, else `None`."""
    match = kernel_cve_record.RECORD_PATH_PATTERN.fullmatch(path)
    if match is None:
        return None
    cve_id = match["cve_id"]
    return cve_id if is_valid_cve_id(cve_id) else None
