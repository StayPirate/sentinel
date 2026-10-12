"""Tests for traversal, matching, reuse, and logging of the IBS Product
repository download boundary.

Contract under test: docs/features/packages/ibs-product-release-detection.md
(Source Authority; Repository qualification and URL construction;
Repository Traversal: tiers, deterministic order, outcome table, and stop
rules; Issued time: earliest matching advisory in the first matching
repository with the advisory-ID tiebreak; Exact Source-Package Match;
Reconciliation Boundary: per-invocation repository deduplication, no
cross-invocation state; Irreversibility, Audit, and Observability: the
`ibs_product_release_repository_failed` and
`ibs_product_release_advisories_ignored` events and their bounded fields),
docs/features/integrations/ibs-integration.md (Business Rule 2: bounded
operational logging), and docs/features/platform/logging.md (Secrets and
PII Discipline). The boundary is mutation-free: it opens no database
session and imports no persistence module.

Fictional repositories are served through `httpx.MockTransport` from
`tests/support/ibs_download.py`; the end-to-end tests serve the sanitized
live updateinfo captures in the live response shape. No network, database,
or Redis is used.
"""

from __future__ import annotations

import ast
import asyncio
import builtins
import io
import os
import subprocess
import sys
import uuid
from collections.abc import Iterable, MutableMapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

import app.database
from app.config import settings
from app.services import xml_safety
from app.services.packages import ibs_product_download, ibs_repodata, ibs_updateinfo
from app.services.packages.ibs_product_download import (
    ADVISORIES_IGNORED_EVENT,
    REPOSITORY_FAILED_EVENT,
    ProductOccurrenceCandidate,
    ProductReleaseIncomplete,
    ProductReleaseMatch,
    ProductReleaseNoMatch,
    ProductReleaseObservation,
    ProductRepositoryDownloads,
)
from app.services.packages.ibs_repodata import RepositoryFailureCategory
from tests.support.ibs_download import (
    DEFAULT_CVE,
    DEFAULT_PACKAGE,
    REDIRECT_HOST,
    TEST_BASE_URL,
    Artifact,
    DownloadServer,
    Responder,
    advisory,
    artifact,
    binary_package,
    candidate,
    load_updateinfo_fixture,
    observe,
    redirect_response,
    source_package,
    updateinfo_document,
    xml_response,
)

pytestmark = pytest.mark.unit

SUFFIXLESS: Final = "SUSE:Updates:Example:1"
X86: Final = "SUSE:Updates:Example:1:x86_64"
AARCH64: Final = "SUSE:Updates:Example:1:aarch64"
HISTORICAL: Final = "SUSE:Updates:Example:0:x86_64"
MATCH_ID: Final = "SUSE-Example-2024-1"
MARKER: Final = "fictional-private-marker"
LIVE_TIMESTAMP: Final = 1_782_862_012


def _matching(
    advisory_id: str = MATCH_ID,
    *,
    sources: Iterable[str] = (DEFAULT_PACKAGE,),
    cves: Iterable[str] = (DEFAULT_CVE,),
    issued: str = "1717068854",
) -> str:
    return advisory(advisory_id, cves=cves, sources=sources, issued=issued)


def _repository(*updates: str) -> Artifact:
    return artifact(updateinfo_document(*updates))


def _status(status: int) -> Responder:
    return lambda _: xml_response(b"<html/>", status=status, content_type="text/html")


def _raise(error: BaseException) -> Responder:
    def respond(_: httpx.Request) -> httpx.Response:
        raise error

    return respond


def _repomd_urls(server: DownloadServer) -> list[str]:
    return [
        str(request.url)
        for request in server.requests
        if request.url.path.endswith("/repomd.xml")
    ]


def _requests_for(server: DownloadServer, repo_name: str) -> int:
    root = "/".join(repo_name.split(":")) + "/update/"
    return sum(1 for request in server.requests if root in request.url.path)


async def _observe_all(
    server: DownloadServer, *candidates: ProductOccurrenceCandidate
) -> list[ProductReleaseObservation]:
    async with server.client() as client:
        return await observe(client, *candidates)


def _match(repository: str, advisory_id: str, issued: int) -> ProductReleaseMatch:
    return ProductReleaseMatch(
        repository=repository,
        issued_at=datetime.fromtimestamp(issued, UTC),
        advisory_id=advisory_id,
    )


# ---------------------------------------------------------------------------
# Traversal
# ---------------------------------------------------------------------------


class TestTraversalOrder:
    async def test_tier_order_is_suffixless_then_x86_64_then_other_architectures(
        self,
    ) -> None:
        names = [
            "SUSE:Updates:Example:1:x86_64",
            "SUSE:Updates:Example:1:s390x",
            "SUSE:Updates:Example:1",
            "SUSE:Updates:Alpha:1:aarch64",
            "SUSE:Updates:Example:1:aarch64",
            "SUSE:Updates:Alpha:1:x86_64",
            "SUSE:Updates:Alpha:1",
            "SUSE:Updates:Example:1:ppc64le",
            "SUSE:Updates:Example:1:ppc64",
            "SUSE:Updates:Example:1:noarch",
            "SUSE:Updates:Example:1:i686",
            "SUSE:Updates:Example:1:i586",
            "SUSE:Updates:Example:1:ia64",
        ]
        server = DownloadServer()

        outcomes = await _observe_all(server, candidate(current=names))

        assert outcomes == [ProductReleaseNoMatch()]
        expected = [
            "SUSE:Updates:Alpha:1",
            "SUSE:Updates:Example:1",
            "SUSE:Updates:Example:1:noarch",
            "SUSE:Updates:Alpha:1:x86_64",
            "SUSE:Updates:Example:1:x86_64",
            "SUSE:Updates:Alpha:1:aarch64",
            "SUSE:Updates:Example:1:aarch64",
            "SUSE:Updates:Example:1:i586",
            "SUSE:Updates:Example:1:i686",
            "SUSE:Updates:Example:1:ia64",
            "SUSE:Updates:Example:1:ppc64",
            "SUSE:Updates:Example:1:ppc64le",
            "SUSE:Updates:Example:1:s390x",
        ]
        assert _repomd_urls(server) == [server.repomd_url(name) for name in expected]

    async def test_historical_tier_follows_current_without_repeating_it(
        self,
    ) -> None:
        server = DownloadServer()
        item = candidate(
            current=[X86, SUFFIXLESS],
            historical=["SUSE:Updates:Old:1:x86_64", SUFFIXLESS, "SUSE:Updates:Old:1"],
        )

        assert await _observe_all(server, item) == [ProductReleaseNoMatch()]
        expected = [SUFFIXLESS, X86, "SUSE:Updates:Old:1", "SUSE:Updates:Old:1:x86_64"]
        assert _repomd_urls(server) == [server.repomd_url(name) for name in expected]

    @pytest.mark.parametrize(
        "name",
        [
            "SUSE:Products:SLE-Product-SLES:15-SP6:x86_64",
            "SUSE:Updates:Example:1:debug",
            "SUSE:Updates:Example:1:src",
            "SUSE:Updates:Debian:12-CLIENT-TOOLS:x86_64",
            "SUSE:Updates:MultiLinuxManagerTools:Ubuntu-24.04:x86_64",
            "SUSE:Updates:MultiLinuxManagerTools:Debian-12:x86_64",
            "SUSE:Updates:Ubuntu:22.04",
            "SUSE:Updates:Example::1",
            "SUSE:Updates:Example:1/../2",
            "SUSE:Updates:Exa mple:1",
            "SUSE:Updates:Example:1:",
            "SUSE:Updates",
            "suse:updates:Example:1",
            "openSUSE:Updates:Example:1",
            "",
        ],
    )
    async def test_unqualified_name_is_never_requested(self, name: str) -> None:
        server = DownloadServer()
        server.add(name, _repository(_matching()))

        outcomes = await _observe_all(
            server, candidate(current=[name], historical=[name])
        )

        assert outcomes == [ProductReleaseNoMatch()]
        assert server.requests == []

    async def test_mixed_family_with_rpm_target_is_requested(self) -> None:
        name = "SUSE:Updates:MultiLinuxManagerTools:SLE-15:x86_64"
        server = DownloadServer()
        server.add(name, _repository(_matching()))

        outcomes = await _observe_all(server, candidate(current=[name]))

        assert outcomes == [_match(name, MATCH_ID, 1717068854)]

    async def test_empty_tiers_are_no_match_without_requests(self) -> None:
        server = DownloadServer()

        assert await _observe_all(server, candidate()) == [ProductReleaseNoMatch()]
        assert server.requests == []


class TestTraversalStopRules:
    async def test_historical_tier_not_consulted_after_current_match(self) -> None:
        server = DownloadServer()
        server.add(X86, _repository(_matching()))
        server.add(HISTORICAL, _repository(_matching("SUSE-Old-1", issued="1")))

        outcomes = await _observe_all(
            server, candidate(current=[X86], historical=[HISTORICAL])
        )

        assert outcomes == [_match(X86, MATCH_ID, 1717068854)]
        assert _requests_for(server, HISTORICAL) == 0

    async def test_historical_fallback_after_every_current_completes_without_match(
        self,
    ) -> None:
        no_updateinfo = "SUSE:Updates:Example:2"
        absent = "SUSE:Updates:Example:3"
        server = DownloadServer()
        server.add(no_updateinfo, None)
        server.add(X86, _repository(_matching(sources=["other"])))
        server.add(HISTORICAL, _repository(_matching("SUSE-Old-1")))

        outcomes = await _observe_all(
            server,
            candidate(current=[X86, absent, no_updateinfo], historical=[HISTORICAL]),
        )

        assert outcomes == [_match(HISTORICAL, "SUSE-Old-1", 1717068854)]
        assert _repomd_urls(server)[:3] == [
            server.repomd_url(no_updateinfo),
            server.repomd_url(absent),
            server.repomd_url(X86),
        ]

    async def test_traversal_stops_per_occurrence_after_first_match(self) -> None:
        server = DownloadServer()
        server.add(SUFFIXLESS, _repository(_matching()))
        server.add(X86, _repository(_matching("SUSE-Other-1", sources=["other"])))
        first = candidate(current=[SUFFIXLESS, X86])
        second = candidate(current=[SUFFIXLESS, X86], package_name="other")

        async with (
            server.client() as client,
            ProductRepositoryDownloads(
                client, [first, second], base_url=TEST_BASE_URL
            ) as downloads,
        ):
            first_outcome = await downloads.observe(first.occurrence_id)
            assert _requests_for(server, X86) == 0
            second_outcome = await downloads.observe(second.occurrence_id)

        assert first_outcome == _match(SUFFIXLESS, MATCH_ID, 1717068854)
        assert second_outcome == _match(X86, "SUSE-Other-1", 1717068854)
        assert _requests_for(server, SUFFIXLESS) == 4

    @pytest.mark.parametrize(
        ("responder", "category", "http_status"),
        [
            pytest.param(_status(403), "http_status", 403, id="403"),
            pytest.param(_status(500), "http_status", 500, id="500"),
            pytest.param(
                _raise(httpx.ConnectError("fictional")),
                "transport",
                None,
                id="transport",
            ),
            pytest.param(
                _raise(httpx.ReadTimeout("fictional")),
                "timeout",
                None,
                id="timeout",
            ),
            pytest.param(
                lambda _: xml_response(b"<repomd"), "xml_structure", None, id="xml"
            ),
            pytest.param(
                lambda _: redirect_response("https://dist.example.test/x"),
                "redirect",
                302,
                id="redirect",
            ),
        ],
    )
    async def test_incomplete_repository_suppresses_lower_priority_ones(
        self,
        responder: Responder,
        category: RepositoryFailureCategory,
        http_status: int | None,
    ) -> None:
        server = DownloadServer()
        server.add(SUFFIXLESS, _repository(_matching()))
        server.add(X86, _repository(_matching()))
        server.add(AARCH64, _repository(_matching()))
        server.add(HISTORICAL, _repository(_matching()))
        server.script(server.repomd_url(SUFFIXLESS), responder)

        outcomes = await _observe_all(
            server,
            candidate(current=[AARCH64, X86, SUFFIXLESS], historical=[HISTORICAL]),
        )

        assert outcomes == [
            ProductReleaseIncomplete(
                repository=SUFFIXLESS,
                reason_category=category,
                http_status=http_status,
            )
        ]
        for name in (X86, AARCH64, HISTORICAL):
            assert _requests_for(server, name) == 0

    async def test_incomplete_after_non_matches_suppresses_historical_tier(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(SUFFIXLESS, None)
        server.add(X86, _repository(_matching()))
        server.add(HISTORICAL, _repository(_matching()))
        server.script(server.repomd_url(X86), _status(403))

        outcomes = await _observe_all(
            server, candidate(current=[X86, SUFFIXLESS], historical=[HISTORICAL])
        )

        assert outcomes == [
            ProductReleaseIncomplete(
                repository=X86, reason_category="http_status", http_status=403
            )
        ]
        assert _requests_for(server, HISTORICAL) == 0

    async def test_incomplete_historical_repository_is_incomplete(self) -> None:
        server = DownloadServer()
        server.add(X86, _repository(_matching(sources=["other"])))
        server.script(server.repomd_url(HISTORICAL), _status(403))

        outcomes = await _observe_all(
            server, candidate(current=[X86], historical=[HISTORICAL])
        )

        assert outcomes == [
            ProductReleaseIncomplete(
                repository=HISTORICAL, reason_category="http_status", http_status=403
            )
        ]


# ---------------------------------------------------------------------------
# Match semantics
# ---------------------------------------------------------------------------


class TestMatchSemantics:
    async def test_earliest_issued_advisory_of_first_matching_repository_wins(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(
            SUFFIXLESS,
            _repository(
                _matching("SUSE-Example-2024-3", issued="1700000300"),
                _matching("SUSE-Example-2024-2", issued="1700000200"),
                _matching("SUSE-Example-2024-9", issued="1700000900"),
            ),
        )
        server.add(X86, _repository(_matching("SUSE-Example-2023-1", issued="1")))

        outcomes = await _observe_all(server, candidate(current=[X86, SUFFIXLESS]))

        assert outcomes == [_match(SUFFIXLESS, "SUSE-Example-2024-2", 1700000200)]
        assert _requests_for(server, X86) == 0

    async def test_equal_issued_time_selects_lexically_smallest_advisory_id(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(
            X86,
            _repository(
                _matching("SUSE-Example-2024-3", issued="1700000000"),
                _matching("SUSE-Example-2024-20", issued="1700000000"),
                _matching("SUSE-Example-2024-1", issued="1700000001"),
            ),
        )

        outcomes = await _observe_all(server, candidate(current=[X86]))

        assert outcomes == [_match(X86, "SUSE-Example-2024-20", 1700000000)]

    async def test_issued_at_is_utc_aware_issued_seconds(self) -> None:
        server = DownloadServer()
        server.add(X86, _repository(_matching(issued="0")))

        [outcome] = await _observe_all(server, candidate(current=[X86]))

        assert isinstance(outcome, ProductReleaseMatch)
        assert outcome.issued_at == datetime(1970, 1, 1, tzinfo=UTC)
        assert outcome.issued_at.utcoffset() == timedelta(0)
        assert outcome.issued_at.timestamp() == 0

    async def test_one_advisory_matches_several_occurrences_without_suppression(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(
            X86, _repository(_matching(sources=[DEFAULT_PACKAGE, "example-libs"]))
        )
        items = [
            candidate(current=[X86]),
            candidate(current=[X86], package_name="example-libs"),
            candidate(current=[X86], package_name="unrelated"),
            candidate(current=[X86]),
        ]

        outcomes = await _observe_all(server, *items)

        expected = _match(X86, MATCH_ID, 1717068854)
        assert outcomes == [expected, expected, ProductReleaseNoMatch(), expected]
        assert len(server.requests) == 4

    async def test_occurrences_with_different_cves_match_from_one_snapshot(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(
            X86,
            _repository(
                _matching(),
                _matching("SUSE-Example-2024-2", cves=["CVE-2024-0002"]),
            ),
        )

        outcomes = await _observe_all(
            server,
            candidate(current=[X86]),
            candidate(current=[X86], cve_id="CVE-2024-0002"),
            candidate(current=[X86], cve_id="CVE-2024-0003"),
        )

        assert outcomes == [
            _match(X86, MATCH_ID, 1717068854),
            _match(X86, "SUSE-Example-2024-2", 1717068854),
            ProductReleaseNoMatch(),
        ]
        assert len(server.requests) == 4

    @pytest.mark.parametrize(
        "update",
        [
            pytest.param(
                advisory(
                    MATCH_ID,
                    cves=[DEFAULT_CVE],
                    sources=[DEFAULT_PACKAGE],
                    status="retracted",
                ),
                id="retracted",
            ),
            pytest.param(
                advisory(
                    MATCH_ID,
                    cves=[DEFAULT_CVE],
                    sources=[DEFAULT_PACKAGE],
                    type_="recommended",
                ),
                id="recommended-with-cve",
            ),
            pytest.param(
                advisory(
                    MATCH_ID,
                    cves=[DEFAULT_CVE],
                    sources=[DEFAULT_PACKAGE],
                    type_="Security",
                ),
                id="type-case",
            ),
            pytest.param(
                _matching().replace('<issued date="1717068854"/>', ""),
                id="malformed-missing-issued",
            ),
            pytest.param(
                _matching(issued=str(LIVE_TIMESTAMP + 1)), id="issued-after-metadata"
            ),
            pytest.param(
                advisory(MATCH_ID, cves=[DEFAULT_CVE], packages=[]),
                id="empty-package-collection",
            ),
            pytest.param(
                advisory(
                    MATCH_ID,
                    cves=[DEFAULT_CVE],
                    packages=[binary_package(DEFAULT_PACKAGE)],
                ),
                id="binary-entry-only",
            ),
            pytest.param(
                advisory(
                    MATCH_ID,
                    cves=[DEFAULT_CVE],
                    packages=[
                        source_package(
                            DEFAULT_PACKAGE, src="src/../example-1.0-1.src.rpm"
                        )
                    ],
                ),
                id="unsafe-source-path",
            ),
            pytest.param(
                advisory(
                    MATCH_ID,
                    references=[
                        f'<reference href="https://x.example.test" id="{DEFAULT_CVE}"'
                        ' type="bugzilla"/>'
                    ],
                    sources=[DEFAULT_PACKAGE],
                ),
                id="cve-only-in-other-reference-type",
            ),
            pytest.param(_matching(cves=["CVE-2024-0009"]), id="other-cve"),
            pytest.param(_matching(sources=["Example"]), id="package-case"),
            pytest.param(_matching(sources=["example-libs"]), id="package-prefix"),
        ],
    )
    async def test_non_authoritative_or_non_matching_advisory_never_matches(
        self, update: str
    ) -> None:
        server = DownloadServer()
        server.add(X86, _repository(update))

        outcomes = await _observe_all(server, candidate(current=[X86]))

        assert outcomes == [ProductReleaseNoMatch()]

    async def test_malformed_advisory_does_not_hide_valid_sibling(self) -> None:
        server = DownloadServer()
        server.add(
            X86,
            _repository(
                _matching("SUSE-Example-2024-0", issued="5").replace(
                    "<pkglist>", "<pkglist/><pkglist>"
                ),
                _matching(),
            ),
        )

        outcomes = await _observe_all(server, candidate(current=[X86]))

        assert outcomes == [_match(X86, MATCH_ID, 1717068854)]


# ---------------------------------------------------------------------------
# Reuse and statelessness
# ---------------------------------------------------------------------------


class TestReuse:
    async def test_repository_examined_once_for_every_dependent_occurrence(
        self,
    ) -> None:
        item = _repository(_matching())
        server = DownloadServer()
        server.add(X86, item)
        candidates = [
            candidate(current=[X86]),
            candidate(current=[X86], package_name="other"),
            candidate(current=[SUFFIXLESS], historical=[X86]),
        ]

        outcomes = await _observe_all(server, *candidates)

        assert outcomes[0] == _match(X86, MATCH_ID, 1717068854)
        assert outcomes[1] == ProductReleaseNoMatch()
        assert outcomes[2] == _match(X86, MATCH_ID, 1717068854)
        assert [str(request.url) for request in server.requests] == [
            server.repomd_url(X86),
            server.artifact_url(X86, item),
            server.artifact_url(X86, item, host=REDIRECT_HOST),
            server.repomd_url(X86),
            server.repomd_url(SUFFIXLESS),
        ]

    async def test_concurrent_observations_examine_repository_once(self) -> None:
        server = DownloadServer()
        server.add(X86, _repository(_matching()))
        candidates = [candidate(current=[X86]) for _ in range(5)]

        async with (
            server.client() as client,
            ProductRepositoryDownloads(
                client, candidates, base_url=TEST_BASE_URL
            ) as downloads,
        ):
            outcomes = await asyncio.gather(
                *(downloads.observe(item.occurrence_id) for item in candidates)
            )

        assert set(outcomes) == {_match(X86, MATCH_ID, 1717068854)}
        assert len(server.requests) == 4

    async def test_failed_repository_is_not_retried_for_another_occurrence(
        self,
    ) -> None:
        server = DownloadServer()
        server.script(server.repomd_url(X86), _status(503))
        candidates = [candidate(current=[X86]) for _ in range(3)]

        outcomes = await _observe_all(server, *candidates)

        failure = ProductReleaseIncomplete(
            repository=X86, reason_category="http_status", http_status=503
        )
        assert outcomes == [failure] * 3
        assert len(server.requests) == 1

    async def test_new_invocation_examines_repository_again(self) -> None:
        server = DownloadServer()
        server.add(X86, _repository(_matching()))

        async with server.client() as client:
            first = await observe(client, candidate(current=[X86]))
            second = await observe(client, candidate(current=[X86]))

        assert first == second == [_match(X86, MATCH_ID, 1717068854)]
        assert len(server.requests) == 8

    async def test_new_invocation_examines_failed_repository_again(self) -> None:
        server = DownloadServer()
        server.add(X86, _repository(_matching()))
        server.script(
            server.repomd_url(X86),
            _status(503),
            lambda _: xml_response(b"", status=404, content_type="text/html"),
        )

        async with server.client() as client:
            first = await observe(client, candidate(current=[X86]))
            second = await observe(client, candidate(current=[X86]))

        assert isinstance(first[0], ProductReleaseIncomplete)
        assert second == [ProductReleaseNoMatch()]
        assert len(server.requests) == 2

    async def test_invocation_opens_no_database_session_and_no_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def forbidden(*_: object, **__: object) -> Any:
            raise AssertionError("persistence or filesystem access")

        monkeypatch.setattr(app.database, "async_session_factory", forbidden)
        monkeypatch.setattr(AsyncSession, "__init__", forbidden)
        server = DownloadServer()
        server.add(X86, _repository(_matching()))
        server.script(server.repomd_url(AARCH64), _status(403))
        candidates = [
            candidate(current=[X86]),
            candidate(current=[AARCH64]),
            candidate(current=[SUFFIXLESS]),
        ]

        async with server.client() as client:
            with monkeypatch.context() as files:
                files.setattr(builtins, "open", forbidden)
                files.setattr(io, "open", forbidden)
                files.setattr(os, "open", forbidden)
                outcomes = await observe(client, *candidates)

        assert isinstance(outcomes[0], ProductReleaseMatch)
        assert isinstance(outcomes[1], ProductReleaseIncomplete)
        assert outcomes[2] == ProductReleaseNoMatch()


_BOUNDARY_MODULES: Final = (
    ibs_product_download,
    ibs_repodata,
    ibs_updateinfo,
    xml_safety,
)
_FORBIDDEN_IMPORTS: Final = (
    "sqlalchemy",
    "redis",
    "app.database",
    "app.models",
    "app.services.package_service",
    "os",
    "pathlib",
    "tempfile",
    "shutil",
    "io",
    "mmap",
)
_FORBIDDEN_CALLS: Final = frozenset(
    {
        "open",
        "read_bytes",
        "read_text",
        "write_bytes",
        "write_text",
        "mkdir",
        "unlink",
        "mkstemp",
        "NamedTemporaryFile",
    }
)


class TestPersistenceFreeBoundary:
    @pytest.mark.parametrize(
        "module", _BOUNDARY_MODULES, ids=lambda module: module.__name__
    )
    def test_module_imports_no_persistence_or_filesystem_module(
        self, module: Any
    ) -> None:
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imported: list[str] = []
        called: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.append(node.module)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    called.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    called.add(node.func.attr)

        assert imported
        for name in imported:
            for forbidden in _FORBIDDEN_IMPORTS:
                assert name != forbidden
                assert not name.startswith(f"{forbidden}.")
        assert called.isdisjoint(_FORBIDDEN_CALLS)

    def test_importing_boundary_loads_no_persistence_module(self) -> None:
        program = (
            "import sys\n"
            + "".join(f"import {module.__name__}\n" for module in _BOUNDARY_MODULES)
            + "prefixes = ('sqlalchemy', 'redis', 'app.database', 'app.models',"
            " 'app.services.package_service')\n"
            "loaded = sorted(m for m in sys.modules if m.startswith(prefixes))\n"
            "print(loaded)\n"
        )
        backend = Path(__file__).resolve().parents[3]

        result = subprocess.run(
            [sys.executable, "-c", program],
            cwd=backend,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().splitlines()[-1] == "[]"


# ---------------------------------------------------------------------------
# Operational logs
# ---------------------------------------------------------------------------


def _events(
    logs: list[MutableMapping[str, Any]], event: str
) -> list[MutableMapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == event]


class TestRepositoryFailedLog:
    async def test_one_event_per_failed_repository_at_exit_with_affected_count(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(SUFFIXLESS, _repository(_matching()))
        server.script(server.repomd_url(X86), _status(403))
        matched = candidate(current=[SUFFIXLESS, X86])
        affected = [
            candidate(current=[SUFFIXLESS, X86], package_name="other-1"),
            candidate(current=[X86], package_name="other-2"),
            candidate(historical=[X86], package_name="other-3"),
        ]
        items = [matched, *affected]

        with capture_logs() as logs:
            async with (
                server.client() as client,
                ProductRepositoryDownloads(
                    client, items, base_url=TEST_BASE_URL
                ) as downloads,
            ):
                outcomes = [await downloads.observe(i.occurrence_id) for i in items]
                # Observing an occurrence again does not count it twice.
                await downloads.observe(affected[0].occurrence_id)
                assert _events(logs, REPOSITORY_FAILED_EVENT) == []

        assert isinstance(outcomes[0], ProductReleaseMatch)
        assert all(isinstance(o, ProductReleaseIncomplete) for o in outcomes[1:])
        assert _events(logs, REPOSITORY_FAILED_EVENT) == [
            {
                "event": REPOSITORY_FAILED_EVENT,
                "log_level": "warning",
                "repository": X86,
                "affected_occurrence_count": 3,
                "reason_category": "http_status",
                "http_status": 403,
            }
        ]

    async def test_each_failed_repository_has_its_own_event(self) -> None:
        server = DownloadServer()
        server.script(server.repomd_url(X86), _status(403))
        server.script(server.repomd_url(AARCH64), _status(500))

        with capture_logs() as logs:
            await _observe_all(
                server,
                candidate(current=[X86]),
                candidate(current=[AARCH64]),
                candidate(current=[AARCH64]),
            )

        events = sorted(
            _events(logs, REPOSITORY_FAILED_EVENT), key=lambda e: e["repository"]
        )
        assert [(e["repository"], e["affected_occurrence_count"]) for e in events] == [
            (AARCH64, 2),
            (X86, 1),
        ]

    @pytest.mark.parametrize(
        ("responder", "category", "http_status"),
        [
            pytest.param(_status(403), "http_status", 403, id="http-status"),
            pytest.param(
                lambda _: redirect_response("https://dist.example.test/x", status=301),
                "redirect",
                301,
                id="redirect-301",
            ),
            pytest.param(
                lambda _: redirect_response(f"https://evil.example.test/{MARKER}"),
                "redirect",
                302,
                id="redirect-302",
            ),
            pytest.param(
                lambda _: xml_response(b"<repomd/>", content_type="text/html"),
                "content_type",
                None,
                id="content-type",
            ),
            pytest.param(
                _raise(httpx.ConnectError(MARKER)),
                "transport",
                None,
                id="transport",
            ),
            pytest.param(
                lambda _: xml_response(b"<repomd/>"),
                "xml_structure",
                None,
                id="xml-structure",
            ),
        ],
    )
    async def test_http_status_field_present_only_for_status_and_redirect(
        self,
        responder: Responder,
        category: RepositoryFailureCategory,
        http_status: int | None,
    ) -> None:
        server = DownloadServer()
        server.script(server.repomd_url(X86), responder)

        with capture_logs() as logs:
            await _observe_all(server, candidate(current=[X86]))

        expected: dict[str, Any] = {
            "event": REPOSITORY_FAILED_EVENT,
            "log_level": "warning",
            "repository": X86,
            "affected_occurrence_count": 1,
            "reason_category": category,
        }
        if http_status is not None:
            expected["http_status"] = http_status
        assert logs == [expected]

    async def test_successful_and_non_matching_repositories_emit_no_event(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(X86, _repository(_matching()))
        server.add(SUFFIXLESS, None)

        with capture_logs() as logs:
            await _observe_all(
                server,
                candidate(current=[SUFFIXLESS, X86]),
                candidate(current=[AARCH64, SUFFIXLESS, X86], package_name="other"),
            )

        assert logs == []


_MALFORMED_SECURITY: Final = (
    _matching("SUSE-Example-2024-7").replace('<issued date="1717068854"/>', ""),
    _matching("SUSE-Example-2024-8", issued="+1"),
    # A malformed non-security advisory is never authoritative or counted.
    advisory("SUSE-Example-2024-9", type_="recommended", cves=[DEFAULT_CVE]),
)


class TestAdvisoriesIgnoredLog:
    async def test_one_event_per_repository_with_malformed_advisory_count(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(X86, _repository(*_MALFORMED_SECURITY, _matching()))

        with capture_logs() as logs:
            outcomes = await _observe_all(
                server,
                candidate(current=[X86]),
                candidate(current=[X86], package_name="other"),
                candidate(historical=[X86], package_name="other"),
            )

        assert outcomes[0] == _match(X86, MATCH_ID, 1717068854)
        assert logs == [
            {
                "event": ADVISORIES_IGNORED_EVENT,
                "log_level": "warning",
                "repository": X86,
                "reason_category": "malformed_advisory",
                "advisory_count": 2,
            }
        ]

    async def test_event_repeats_once_per_invocation(self) -> None:
        server = DownloadServer()
        server.add(X86, _repository(*_MALFORMED_SECURITY))

        with capture_logs() as logs:
            async with server.client() as client:
                await observe(client, candidate(current=[X86]))
                await observe(client, candidate(current=[X86]))

        assert len(_events(logs, ADVISORIES_IGNORED_EVENT)) == 2

    async def test_repository_without_malformed_advisory_emits_no_event(
        self,
    ) -> None:
        server = DownloadServer()
        server.add(X86, _repository(_matching(), _MALFORMED_SECURITY[2]))

        with capture_logs() as logs:
            await _observe_all(server, candidate(current=[X86]))

        assert logs == []


class TestLogContent:
    async def test_logs_contain_no_url_credential_upstream_text_or_advisory_id(
        self,
    ) -> None:
        malformed = _matching(f"SUSE-{MARKER}-1", issued="+1").replace(
            "Fictional title", f"Title {MARKER}"
        )
        server = DownloadServer()
        server.add(SUFFIXLESS, _repository(malformed, _matching(sources=["other"])))
        server.script(
            server.repomd_url(X86),
            lambda _: redirect_response(f"https://evil.example.test/{MARKER}?x=1"),
        )
        server.script(
            server.repomd_url(AARCH64),
            lambda _: xml_response(f"<repomd>{MARKER}".encode()),
        )
        client = httpx.AsyncClient(
            transport=server.transport(),
            headers={"Authorization": "Bearer fictional-token"},
            auth=("fictional-user", "fictional-pass"),
            cookies={"session": "fictional-cookie"},
        )

        with capture_logs() as logs:
            async with client:
                await observe(
                    client,
                    candidate(current=[SUFFIXLESS, X86]),
                    candidate(current=[SUFFIXLESS, AARCH64]),
                )

        assert {entry["event"] for entry in logs} == {
            REPOSITORY_FAILED_EVENT,
            ADVISORIES_IGNORED_EVENT,
        }
        rendered = repr(logs)
        for fragment in (
            TEST_BASE_URL,
            "download.example.test",
            "evil.example.test",
            REDIRECT_HOST,
            "/",
            "repomd",
            "updateinfo",
            "<",
            MARKER,
            "SUSE-Example",
            "Fictional",
            "fictional-token",
            "fictional-user",
            "fictional-pass",
            "fictional-cookie",
            "Bearer",
        ):
            assert fragment not in rendered


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_duplicate_occurrence_id_is_rejected(self) -> None:
        item = candidate(current=[X86])
        duplicate = ProductOccurrenceCandidate(
            occurrence_id=item.occurrence_id,
            cve_id="CVE-2024-0002",
            package_name="other",
            current_repositories=(),
            historical_repositories=(),
        )

        with pytest.raises(ValueError, match="duplicate occurrence ID"):
            ProductRepositoryDownloads(
                DownloadServer().client(), [item, duplicate], base_url=TEST_BASE_URL
            )

    async def test_unknown_occurrence_raises_key_error_without_request(self) -> None:
        server = DownloadServer()

        async with (
            server.client() as client,
            ProductRepositoryDownloads(
                client, [candidate(current=[X86])], base_url=TEST_BASE_URL
            ) as downloads,
        ):
            with pytest.raises(KeyError):
                await downloads.observe(uuid.uuid4())

        assert server.requests == []

    async def test_base_url_defaults_to_configured_download_base(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            settings, "ibs_download_base_url", "https://mirror.example.test/base"
        )
        server = DownloadServer()

        async with server.client() as client:
            outcomes = await observe(client, candidate(current=[X86]), base_url=None)

        assert outcomes == [ProductReleaseNoMatch()]
        assert [str(request.url) for request in server.requests] == [
            "https://mirror.example.test/base/SUSE/Updates/Example/1/x86_64/update"
            "/repodata/repomd.xml"
        ]


# ---------------------------------------------------------------------------
# End to end with the sanitized live captures
# ---------------------------------------------------------------------------

BASESYSTEM: Final = "SUSE:Updates:SLE-Module-Basesystem:15-SP6:x86_64"
LEGACY: Final = "SUSE:Updates:SLE-SERVER:11-SP4:x86_64"


class TestLiveCaptures:
    async def test_current_capture_in_live_response_shape(self) -> None:
        item = artifact(load_updateinfo_fixture("current"), timestamp=LIVE_TIMESTAMP)
        server = DownloadServer()
        server.add(BASESYSTEM, item)

        def occurrence(package: str, cve: str) -> ProductOccurrenceCandidate:
            return candidate(current=[BASESYSTEM], package_name=package, cve_id=cve)

        with capture_logs() as logs:
            outcomes = await _observe_all(
                server,
                occurrence("rpm", "CVE-2021-3521"),
                occurrence("python-rpm", "CVE-2021-3521"),
                occurrence("RPM", "CVE-2021-3521"),
                occurrence("wireshark", "CVE-2024-4855"),
                occurrence("rsync", "CVE-2024-12084"),
                occurrence("mozilla-nss", "CVE-2023-5388"),
                occurrence("kernel-default", "CVE-2023-0160"),
            )

        rpm = _match(
            BASESYSTEM, "SUSE-SLE-Module-Basesystem-15-SP6-2024-1557", 1717068854
        )
        assert outcomes == [
            rpm,
            rpm,
            ProductReleaseNoMatch(),
            _match(
                BASESYSTEM, "SUSE-SLE-Module-Basesystem-15-SP6-2024-1865", 1717071611
            ),
            ProductReleaseNoMatch(),
            ProductReleaseNoMatch(),
            _match(
                BASESYSTEM, "SUSE-SLE-Module-Basesystem-15-SP6-2024-2203", 1719320682
            ),
        ]
        assert logs == []
        redirect, target = server.requests[1:3]
        assert target.url.host == REDIRECT_HOST
        assert target.url.raw_path == redirect.url.raw_path
        assert len(server.requests) == 4

    async def test_legacy_sha1_capture_matches(self) -> None:
        item = artifact(
            load_updateinfo_fixture("legacy_sha1"),
            checksum_type="sha",
            timestamp=LIVE_TIMESTAMP,
        )
        server = DownloadServer()
        server.add(LEGACY, item)

        outcomes = await _observe_all(
            server,
            candidate(
                current=[LEGACY], package_name="kernel-default", cve_id="CVE-2019-7222"
            ),
            candidate(
                current=[LEGACY], package_name="MozillaFirefox", cve_id="CVE-2015-4487"
            ),
        )

        assert outcomes == [
            _match(LEGACY, "slessp4-kernel-20190225-13979", 1552657768),
            _match(LEGACY, "slessp4-firefox38-20150820-12083", 1441839048),
        ]
