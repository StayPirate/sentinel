"""Shared CVE Record Format 5.x fixtures from `cvelistV5` and `vulns.git`.

The files under `backend/tests/fixtures/cve_record/` are trimmed and
sanitized live CVE Records consumed by `app/services/cve_record_parser.py`
(docs/features/platform/cve-record-parser.md). Two captures, both made
anonymously on 2026-10-08 (docs/conventions.md, External Integration
Contract Verification):

- `cvelistv5_*.json`: entries of the official `CVEProject/cvelistV5`
  release asset `2026-10-08_all_CVEs_at_midnight.zip.zip` of release
  `cve_2026-10-08_1400Z` (`main` at
  `d39faec3f8b078931fe8198de5bd2d8e4ccd35e0`, 2026-10-08T14:35:03Z),
  downloaded over HTTPS. The asset carries the repository's `cves/` tree,
  so each entry is the repository file of the same path; a shallow Git
  clone was too slow over the network.
- `vulns_*.json`: blobs of
  `https://git.kernel.org/pub/scm/linux/security/vulns.git` at `master`
  `e65245d833add2ba0bda9658cba6581a4ad7a71b` (2026-10-07T15:02:32+02:00),
  read from an anonymous `git clone --depth 1`.

Every source file was verified byte-identical with its release-asset entry
or `HEAD` blob before trimming. Fixture, source path, and purpose:

- `cvelistv5_5_2_package_only_affected` (`cves/2024/3xxx/CVE-2024-3094.json`,
  5.2): an `affected[]` element identified only by `packageName` and
  `collectionURL`, Red Hat elements with `cpes` and without `versions`, a
  `cvssV3_1` vector beside a Red Hat `other` severity, a CWE, a CISA-ADP
  SSVC, a CVE Program ADP container, and a CRLF description;
- `cvelistv5_5_0_rejected_legacy` (`cves/2006/2xxx/CVE-2006-2938.json`,
  5.0): the legacy minimal REJECTED structure (`providerMetadata` and
  `rejectedReasons` only) with `datePublished` and `dateRejected`;
- `cvelistv5_5_2_rejected` (`cves/2005/20xxx/CVE-2005-20001.json`, 5.2):
  REJECTED with `dateRejected` and without `datePublished`;
- `cvelistv5_5_1_rejected_without_date_rejected`
  (`cves/2023/20xxx/CVE-2023-20239.json`, 5.1): REJECTED without
  `dateRejected`;
- `cvelistv5_kev_ssvc_offset_n_a` (`cves/2015/2xxx/CVE-2015-2546.json`,
  5.2): `n/a` vendor, product, and version, a `text` problem type, and a
  CISA-ADP container with a `cvssV3_1` vector, an SSVC whose timestamp
  carries `+00:00`, a KEV entry, and a CWE;
- `cvelistv5_all_cvss_keys_en_de` (`cves/2005/10xxx/CVE-2005-10003.json`,
  5.1): `cvssV4_0`, `cvssV3_1`, `cvssV3_0`, and `cvssV2_0` Base vectors in
  separate entries, and `en` plus `de` descriptions;
- `cvelistv5_v4_supplemental_non_base` (`cves/2022/26xxx/CVE-2022-26327.json`,
  5.1): a v4.0 vector with the Supplemental metrics `RE:M/U:Clear`;
- `cvelistv5_v3_1_non_base_en_us_kev` (`cves/2013/3xxx/CVE-2013-3900.json`,
  5.2): a v3.1 vector with the Temporal metrics `E:U/RL:O/RC:C`, an `en-US`
  description, an uppercase `N/A` version, and CISA-ADP SSVC and KEV;
- `cvelistv5_all_cvss_keys_non_base` (`cves/2022/3xxx/CVE-2022-3636.json`,
  5.2): all four keys with non-Base metrics (v2.0 `E:ND/RL:OF/RC:C`) and
  two problem types;
- `cvelistv5_v3_0_non_base_unordered` (`cves/2022/33xxx/CVE-2022-33955.json`,
  5.1): a v3.0 vector with Temporal metrics in non-FIRST order;
- `cvelistv5_package_url_package_only` (`cves/2022/4xxx/CVE-2022-4993.json`,
  5.2): `packageURL` on a `packageName`-only element with `repo` and
  `programFiles`;
- `cvelistv5_package_url_vendor` (`cves/2022/50xxx/CVE-2022-50589.json`,
  5.2): `packageURL` on an element with vendor and product;
- `cvelistv5_program_files_adp_affected`
  (`cves/2006/10xxx/CVE-2006-10003.json`, 5.2): `programFiles`,
  `lessThanOrEqual`, a CISA-ADP `cvssV3_1` vector, and a `redhat-SADP`
  container with `rpm` versions, `cpes`, an element without `versions`, a
  Red Hat `other` severity, and a CWE;
- `cvelistv5_naive_date_published` (`cves/2022/38xxx/CVE-2022-38370.json`,
  5.1): `datePublished` without offset or fraction;
- `cvelistv5_lowercase_cwe_type` (`cves/2022/20xxx/CVE-2022-20969.json`,
  5.1): a problem type `"type": "cwe"`, an uppercase `N/A` version, and a
  CRLF description;
- `cvelistv5_cwe_id_without_type` (`cves/2022/46xxx/CVE-2022-46827.json`,
  5.1): a `cweId` without `type`;
- `cvelistv5_adp_cvss_v4` (`cves/2025/9xxx/CVE-2025-9491.json`, 5.2): a
  CISA-ADP `cvssV4_0` vector and `defaultStatus` `unknown`;
- `cvelistv5_repeated_cvss_v4` (`cves/2026/16xxx/CVE-2026-16651.json`,
  5.2): two `cvssV4_0` entries in one `metrics` array, `lessThan` and
  `lessThanOrEqual`, `cpes`, and `programFiles`;
- `cvelistv5_unknown_version_status` (`cves/2022/46xxx/CVE-2022-46688.json`,
  5.1): a version `status` `unknown`;
- `cvelistv5_empty_cpes` (`cves/2022/29xxx/CVE-2022-29059.json`, 5.1): an
  empty `cpes` array and a v3.1 vector with `E:P/RL:U/RC:C`;
- `cvelistv5_coexisting_cvss_keys` (`cves/2026/3xxx/CVE-2026-3861.json`,
  5.2): `cvssV3_1` and `cvssV4_0` in one `metrics` entry and a problem type
  without `type` and `cweId`;
- `vulns_published_5_1_1` (`cve/published/2019/CVE-2019-25160.json`,
  5.1.1): a `cvssV3_1` vector, `programFiles`, `lessThan` and
  `lessThanOrEqual`, and the `git`, `semver`, and `original_commit_for_fix`
  version types;
- `vulns_published_affected_without_versions`
  (`cve/published/2023/CVE-2023-53012.json`, 5.1.1): an element without
  `versions`;
- `vulns_rejected_5_0_legacy_cve_id` (`cve/rejected/2019/CVE-2019-25161.json`,
  5.0): the legacy `cveID` key and `versionType` `custom`, in `rejected/`
  with state PUBLISHED;
- `vulns_rejected_5_1_problem_types` (`cve/rejected/2025/CVE-2025-0927.json`,
  5.1): the only 5.1 kernel record and the only one with `problemTypes`,
  without a title, in `rejected/` with state PUBLISHED.

Trimming kept every key of `cveMetadata` and every key of the consumed
container members (`affected`, `metrics`, `problemTypes`, `descriptions`,
`title`, `providerMetadata`) and `references`, in the original key order.
These unconsumed container members were removed wherever present:
`x_legacyV4Record`, `timeline`, `solutions`, `workarounds`, `exploits`,
`impacts`, `configurations`, `source`, `cpeApplicability`, and (CVE-2024-3094
only) `x_redhatCweChain`. Arrays were shortened, keeping each shape of
interest: CVE-2024-3094 `cna.affected` 3 of 7 (indexes 0, 1, 6) and the CVE
Program `references` 3 of 55; CVE-2005-10003 `references` 3 of 6;
CVE-2013-3900 `affected` 3 of 28; CVE-2022-3636 `references` 3 of 5;
CVE-2022-4993 `programFiles` 2 of 4, `programRoutines` 2 of 4, and
`references` 3 of 7; CVE-2006-10003 `redhat-SADP` `affected` 3 of 18
(indexes 0, 1, 17) and its `references` 3 of 16; CVE-2026-16651
`programRoutines` 2 of 5 and `references` 3 of 7; CVE-2022-29059 `versions`
2 of 4; CVE-2019-25160 `versions` 2 of 8 and 4 of 10 and `references` 2 of
8; CVE-2023-53012 `versions` 3 of 7 and `references` 1 of 3.

Sanitization (docs/conventions.md, Example Data in Documentation): every
`descriptions[].value` (and its `supportingMedia[].value`), every CNA and
`redhat-SADP` `title`, and every `rejectedReasons[].value` was replaced
with fictional text keeping `lang`, one CRLF paragraph break where the
original had one, and the kernel description and title shape
(`example: fictional ...`); the fixed program titles
`CISA ADP Vulnrichment` and `CVE Program Container` are kept. Every
`credits` array was replaced with one entry `Example Researcher` keeping the
first entry's keys; every non-`GENERAL` `metrics[].scenarios[].value` with
`Fictional scenario.`; `requesterUserId` with `requester@example.invalid`
(an e-mail) or `00000000-0000-0000-0000-000000000001` (a user UUID).
Personal handles in consumed fields were replaced: CVE-2005-10003 vendor
`examplestudios`; CVE-2006-10003 vendor `EXAMPLEAUTHOR` and `repo`
`http://github.example.invalid/example-author/XML-Parser`; CVE-2022-4993
`repo` `https://github.example.invalid/example-author/html-formhandler`.
Twelve reference URLs on mailing-list archives (openwall, lists.apache.org,
lists.debian.org), a personal blog, a HackerOne report, personal GitHub
accounts and CPAN author pages, a personal kernel tree, and a personal
project site were replaced with fictional
`https://advisory.example.invalid/upstream/<n>` URLs (their `name`, if any,
with `Fictional reference`; one VulDB `name` with `VDB-280359 | Fictional
entry`). CVE-IDs, organisation UUIDs and short names, Git SHAs, versions,
file paths, CPEs, purls, vectors, dates, SSVC and KEV content, tool names in
`x_generator`, and URLs of organisations, vendors, projects, and advisory
databases are public product data and are retained.

Consumers: `tests/test_services/test_cve_record_contract.py`; later, the
parser unit tests of `cve_record_parser`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "cve_record"

FIXTURE_SOURCES: Mapping[str, str] = {
    "cvelistv5_5_2_package_only_affected": "cves/2024/3xxx/CVE-2024-3094.json",
    "cvelistv5_5_0_rejected_legacy": "cves/2006/2xxx/CVE-2006-2938.json",
    "cvelistv5_5_2_rejected": "cves/2005/20xxx/CVE-2005-20001.json",
    "cvelistv5_5_1_rejected_without_date_rejected": (
        "cves/2023/20xxx/CVE-2023-20239.json"
    ),
    "cvelistv5_kev_ssvc_offset_n_a": "cves/2015/2xxx/CVE-2015-2546.json",
    "cvelistv5_all_cvss_keys_en_de": "cves/2005/10xxx/CVE-2005-10003.json",
    "cvelistv5_v4_supplemental_non_base": "cves/2022/26xxx/CVE-2022-26327.json",
    "cvelistv5_v3_1_non_base_en_us_kev": "cves/2013/3xxx/CVE-2013-3900.json",
    "cvelistv5_all_cvss_keys_non_base": "cves/2022/3xxx/CVE-2022-3636.json",
    "cvelistv5_v3_0_non_base_unordered": "cves/2022/33xxx/CVE-2022-33955.json",
    "cvelistv5_package_url_package_only": "cves/2022/4xxx/CVE-2022-4993.json",
    "cvelistv5_package_url_vendor": "cves/2022/50xxx/CVE-2022-50589.json",
    "cvelistv5_program_files_adp_affected": "cves/2006/10xxx/CVE-2006-10003.json",
    "cvelistv5_naive_date_published": "cves/2022/38xxx/CVE-2022-38370.json",
    "cvelistv5_lowercase_cwe_type": "cves/2022/20xxx/CVE-2022-20969.json",
    "cvelistv5_cwe_id_without_type": "cves/2022/46xxx/CVE-2022-46827.json",
    "cvelistv5_adp_cvss_v4": "cves/2025/9xxx/CVE-2025-9491.json",
    "cvelistv5_repeated_cvss_v4": "cves/2026/16xxx/CVE-2026-16651.json",
    "cvelistv5_unknown_version_status": "cves/2022/46xxx/CVE-2022-46688.json",
    "cvelistv5_empty_cpes": "cves/2022/29xxx/CVE-2022-29059.json",
    "cvelistv5_coexisting_cvss_keys": "cves/2026/3xxx/CVE-2026-3861.json",
    "vulns_published_5_1_1": "cve/published/2019/CVE-2019-25160.json",
    "vulns_published_affected_without_versions": (
        "cve/published/2023/CVE-2023-53012.json"
    ),
    "vulns_rejected_5_0_legacy_cve_id": "cve/rejected/2019/CVE-2019-25161.json",
    "vulns_rejected_5_1_problem_types": "cve/rejected/2025/CVE-2025-0927.json",
}
"""Fixture name → repository path of its source record."""

CVELISTV5_FIXTURES = tuple(
    name for name in FIXTURE_SOURCES if name.startswith("cvelistv5_")
)
"""Fixtures captured from `cvelistV5`."""

VULNS_FIXTURES = tuple(name for name in FIXTURE_SOURCES if name.startswith("vulns_"))
"""Fixtures captured from the kernel `vulns.git`."""

ALL_FIXTURES = (*CVELISTV5_FIXTURES, *VULNS_FIXTURES)


def source_cve_id(name: str) -> str:
    """The CVE-ID of a fixture's source file name (the authoritative ID)."""
    return Path(FIXTURE_SOURCES[name]).stem


def load_fixture(name: str) -> dict[str, Any]:
    """Return one sanitized CVE Record as parsed JSON."""
    data: dict[str, Any] = json.loads(load_raw_fixture(name))
    return data


def load_raw_fixture(name: str) -> bytes:
    """Return one fixture file's bytes unparsed."""
    return (FIXTURE_DIR / f"{name}.json").read_bytes()
