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
  can prove that no commit author reaches a log.

The source-independent committed-state reads are
`tests/support/git_fetcher_state.py`.

Nothing here computes an expectation with the module under test. All
identifiers, names, and e-mail addresses are fictional.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any, Final

from app.services.tickets.sync_kernel_cves import SyncKernelCves
from tests.support import git_fetcher_state
from tests.support.git_fetchers import GitFetcherProbe, Upstream
from tests.support.kernel import load_record

NAME: Final = "sync_kernel_cves"
CLONE_DIR: Final = "vulns.git"

AUTHOR_NAME: Final = "Fictional Kernel Maintainer"
AUTHOR_EMAIL: Final = "kernel-maintainer@example.test"
"""The identity of every upstream commit these helpers create."""

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
    return git_fetcher_state.commit(
        upstream,
        files,
        date=date,
        author_name=AUTHOR_NAME,
        author_email=AUTHOR_EMAIL,
        message="example: fictional vulns.git change",
    )
