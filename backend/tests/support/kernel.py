"""Linux Kernel CNA `vulns.git` fixtures.

The files under `backend/tests/fixtures/kernel/` are sanitized captures of
`https://git.kernel.org/pub/scm/linux/security/vulns.git` consumed by
`app/services/tickets/kernel_cve_record.py`
(docs/features/tickets/cve-sync-kernel.md). One capture, made anonymously on
2026-10-09 (docs/conventions.md, External Integration Contract
Verification):

- `git ls-remote --symref` reported `HEAD` → `refs/heads/master` at
  `e65245d833add2ba0bda9658cba6581a4ad7a71b` (committed
  2026-10-07T13:02:32Z), the commit the CVE record parser fixtures
  (`tests/support/cve_record.py`, `vulns_*`) were read from.
- `git clone --bare --depth 1 --filter=blob:none` printed
  `warning: filtering not recognized by server, ignoring` (69 MB, about
  8 s); a full `git clone --bare --single-branch` is 167 MB (about 20 s).
  The cgit web interface answers automated clients with an Anubis
  challenge, so the source reference URL form
  (`.../vulns.git/tree/cve/{state}/{year}/{cve_id}.json`) is
  documentation-only.

Full scan of every `cve/{published,rejected}/YEAR/CVE-YEAR-ID.json` at
that commit (17,327 published, 317 rejected):

- `containers` is always `{cna}`; `providerMetadata` is always `{orgId}`
  (`f4215fc3-5b6b-47ff-a258-f7189bd81038`); `cveMetadata` never has
  `datePublished`, `dateUpdated`, `dateRejected`, `dateReserved`, or
  `assignerShortName`. Its keys are `assignerOrgId`, `cveId`, `state` (5.1.1,
  17,352), plus `requesterUserId` and `serial` with the legacy `cveID` (5.0,
  291) or with `cveId` (5.1, 1).
- `state` is `PUBLISHED` in every record, including all 317 under
  `rejected/`. Every JSON CVE-ID equals its file name; no year directory
  differs from the CVE-ID year; no CVE-ID is in both directories.
- `metrics` occurs in 6,427 records (36.4%; 7 rejected), each entry holding
  `cvssV3_1` (always a strict Base vector) and, in all but one, `scenarios`.
  No other CVSS key and no non-Base vector occurs.
- `problemTypes` occurs in 1 record (CVE-2025-0927, rejected, 5.1, without
  `title`, its description without `type` or `cweId`); that record also
  carries `source`.
- `title` is absent in that one record and otherwise a string of at most 151
  characters; `descriptions` is always one `en` entry (at most 3,998
  characters); `affected` is always a non-empty array; `references` is
  absent in 1 record (CVE-2024-26701) and otherwise an array of objects with
  exactly one key, `url` (90,416 URLs, 57 not on `git.kernel.org`).
- `cpeApplicability` occurs in 17,477 records and `x_generator` in all.
- No string contains U+0000.

Repository layout under `cve/`: `published/` and `rejected/` hold, per
CVE, an empty `CVE-YEAR-ID`, `.json`, `.sha1`, `.mbox`, and optional `.dyad`,
`.vulnerable`, `.reference`, `.cvss`, `.message` (published, 7 files), and
`.mbox.rejected` (rejected) files, plus `.empty` placeholders; `reserved/`
(also nested one level deeper, `reserved/2026/x/`) and `returned/` hold no
`.json`; `review/` (`done/`, `done/gsd/`, `proposed/`) holds no CVE file;
`testing/published/YEAR/` holds 10
`CVE-YEAR-ID.json` files outside the processed directories; `schema`,
`README`, `vulnerability.txt`, and two `CVE_JSON_*_schema.json` files sit at
the top. `repository_paths.txt` keeps one path per directory and file type
(sorted). The two `review/` file names are fictional (their directories are
real): the real names carry maintainers' first names.

Record fixtures, source path, and purpose:

- `published_cvss_v3_1` (`cve/published/2026/CVE-2026-43070.json`, 5.1.1): a
  current published record with `cvssV3_1` and `scenarios`, `git` and
  `semver` blocks with `programFiles`, `cpeApplicability`, `x_generator`,
  and three `references`;
- `published_without_metrics` (`cve/published/2025/CVE-2025-21679.json`,
  5.1.1): the most common shape, without `metrics`;
- `published_external_references`
  (`cve/published/2020/CVE-2020-36791.json`, 5.1.1): nine `references`, two
  of them not on `git.kernel.org`;
- `rejected_cvss_v3_1` (`cve/rejected/2025/CVE-2025-68195.json`, 5.1.1): a
  rejected record with `cvssV3_1`;
- `rejected_without_references` (`cve/rejected/2024/CVE-2024-26701.json`,
  5.0): the record without `references`, with the legacy `cveID` and two
  identical `affected` elements without `versions`.

Each record was read with `git show HEAD:<path>` and re-serialized with a
two-space indent, keeping every key in its original order; nothing was
trimmed. Sanitization (docs/conventions.md, Example Data in
Documentation): every `title` and `descriptions[].value` is replaced with
the `example: fictional ...` shape of the `vulns_*` fixtures, every
`metrics[].scenarios[].value` with `Fictional scenario.`,
`requesterUserId` with `requester@example.invalid`, and the personal-blog
reference of CVE-2020-36791 with `https://advisory.example.invalid/upstream/1`.
CVE-IDs, organisation UUIDs, Git SHAs, versions, file paths, CPEs, vectors,
tool names, and organisation URLs (`git.kernel.org`,
`syzkaller.appspot.com`) are public product data and are retained.

Consumers: `tests/test_services/test_tickets/test_kernel_record_contract.py`,
`tests/test_services/test_tickets/test_kernel_cve_record.py`, the
`SyncKernelCves` tests (`test_sync_kernel_cves.py`,
`test_sync_kernel_cves_execute.py`, `test_sync_kernel_cves_reachability.py`),
and `tests/support/kernel_fetcher.py`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tests.support import cve_record

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "kernel"

RECORD_SOURCES: Mapping[str, str] = {
    "published_cvss_v3_1": "cve/published/2026/CVE-2026-43070.json",
    "published_without_metrics": "cve/published/2025/CVE-2025-21679.json",
    "published_external_references": "cve/published/2020/CVE-2020-36791.json",
    "rejected_cvss_v3_1": "cve/rejected/2025/CVE-2025-68195.json",
    "rejected_without_references": "cve/rejected/2024/CVE-2024-26701.json",
}
"""Record fixture name → repository path of its source file."""

KERNEL_ORG_ID = "f4215fc3-5b6b-47ff-a258-f7189bd81038"
"""The `providerMetadata.orgId` and `assignerOrgId` of every record."""

ALL_RECORDS: tuple[str, ...] = (*RECORD_SOURCES, *cve_record.VULNS_FIXTURES)
"""Every captured kernel record: this module's and the parser's `vulns_*`."""


def record_path(name: str) -> str:
    """The repository path of a kernel record fixture of either module."""
    if name in RECORD_SOURCES:
        return RECORD_SOURCES[name]
    return cve_record.FIXTURE_SOURCES[name]


def load_raw_record(name: str) -> bytes:
    """One kernel record fixture's bytes, as a fetcher reads a blob."""
    if name in RECORD_SOURCES:
        return (FIXTURE_DIR / f"{name}.json").read_bytes()
    return cve_record.load_raw_fixture(name)


def load_record(name: str) -> dict[str, Any]:
    """One kernel record fixture as parsed JSON."""
    data: dict[str, Any] = json.loads(load_raw_record(name))
    return data


def repository_paths() -> list[str]:
    """The sampled repository paths of `repository_paths.txt`."""
    text = (FIXTURE_DIR / "repository_paths.txt").read_text(encoding="utf-8")
    return text.splitlines()
