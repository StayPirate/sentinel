"""Unit tests for `cve_service.build_post_ingest_tasks()`.

Implements docs/features/tickets/cve-service.md (PostIngestTasks;
`build_post_ingest_tasks()`; UpsertResult Design Context) and the
`build_post_ingest_tasks()` item of docs/features/platform/testing-strategy.md
(CVE Ingestion and Ticket Composition): pure extraction with no database,
mapping, Redis, Celery, or network call; exact deduplication;
deterministic ascending Unicode code-point order; JSON-serializable
output; filtered invalid package-name candidates; and `None` for empty
input. Empty replacements and remove operations contribute no candidate.

The `UpsertResult` carries transient `CVE` and `Ticket` instances with
fixed identifiers; nothing is persisted. All identifiers, CPEs, vendors,
and package names are fictional.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import uuid
from typing import Any

import pytest

from app.models.cve import CVE
from app.models.ticket import Ticket
from app.services.cve_ingest import (
    CVEIngestPayload,
    PostIngestTasks,
    UpsertAction,
    UpsertResult,
)
from app.services.cve_service import build_post_ingest_tasks
from tests.support.no_outbound import OutboundGuard

pytest_plugins = ["tests.support.no_outbound_fixtures"]

_TICKET_PK = uuid.UUID("0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0")
_CVE_PK = uuid.UUID("11111111-2222-4333-8444-555555555555")
_MCID_1 = "1aaaaaaa-0000-4000-8000-000000000001"
_MCID_A = "aaaaaaaa-0000-4000-8000-000000000002"
_CPE_A = "cpe:2.3:a:example:alpha:1.0:*:*:*:*:*:*:*"
_CPE_B = "cpe:2.3:a:example:beta:1.0:*:*:*:*:*:*:*"


def _result() -> UpsertResult:
    return UpsertResult(
        cve=CVE(id=_CVE_PK, cve_id="CVE-2099-0001"),
        ticket=Ticket(id=_TICKET_PK),
        action=UpsertAction.UNCHANGED,
    )


def _build(**fields: Any) -> PostIngestTasks | None:
    return build_post_ingest_tasks(_result(), CVEIngestPayload.model_validate(fields))


def _tasks(**fields: Any) -> PostIngestTasks:
    tasks = _build(**fields)
    assert tasks is not None
    return tasks


def _replace(scope: str, *entries: dict[str, Any]) -> dict[str, Any]:
    return {"source_container": scope, "operation": "replace", "entries": list(entries)}


def _remove(scope: str) -> dict[str, Any]:
    return {"source_container": scope, "operation": "remove"}


def _match(criteria: str, vulnerable: bool, mcid: str | None = None) -> dict[str, Any]:
    return {"criteria": criteria, "vulnerable": vulnerable, "match_criteria_id": mcid}


@pytest.mark.unit
class TestNoCandidates:
    @pytest.mark.parametrize(
        "fields",
        [
            {},
            {"title": "Fictional title", "cve_state": "PUBLISHED"},
            {"cwe_classifications": [{"cwe_id": "CWE-79", "source": "NVD"}]},
            {"cpe_matches": []},
            {"resolved_packages": []},
            {"affected_version_operations": []},
            {"affected_version_operations": [_replace("cna")]},
            {"affected_version_operations": [_remove("cna"), _remove("adp:EXAMPLE")]},
            {"resolved_packages": ["", "a/b", "a:b", "a b", "x" * 51]},
            {
                "affected_version_operations": [
                    _replace(
                        "cna",
                        {"package_name": "a/b"},
                        {"package_name": ""},
                        {"vendor": "example"},
                        {"product": "widget", "version": "1.0"},
                    )
                ]
            },
        ],
        ids=[
            "empty",
            "global-fields-only",
            "persisted-children-only",
            "empty-cpe-matches",
            "empty-resolved-packages",
            "empty-operation-list",
            "empty-replacement",
            "remove-only",
            "only-filtered-direct-names",
            "only-filtered-or-incomplete-entries",
        ],
    )
    def test_payload_without_candidates_returns_none(
        self, fields: dict[str, Any]
    ) -> None:
        assert _build(**fields) is None


@pytest.mark.unit
class TestTicketId:
    def test_ticket_id_is_the_canonical_uuid_string(self) -> None:
        tasks = _tasks(resolved_packages=["example-package"])

        assert tasks.ticket_id == "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
        assert tasks.ticket_id == str(_TICKET_PK)

    def test_unused_collections_are_empty_lists(self) -> None:
        tasks = _tasks(resolved_packages=["example-package"])

        assert tasks.cpe_matches == []
        assert tasks.affected_cpes == []
        assert tasks.vendor_products == []
        assert tasks.resolved_packages == ["example-package"]


@pytest.mark.unit
class TestCPEMatches:
    def test_matches_are_deduplicated_and_ordered(self) -> None:
        tasks = _tasks(
            cpe_matches=[
                _match(_CPE_B, True, _MCID_A),
                _match(_CPE_A, True, _MCID_A),
                _match(_CPE_A, True),
                _match(_CPE_A, False, _MCID_A),
                _match(_CPE_A, False, _MCID_1),
                _match(_CPE_A, False),
                _match(_CPE_A, True, _MCID_A.upper()),
                _match(_CPE_A, False),
                _match(_CPE_B, False),
            ]
        )

        assert tasks.cpe_matches == [
            {"criteria": _CPE_A, "vulnerable": False, "match_criteria_id": None},
            {"criteria": _CPE_A, "vulnerable": False, "match_criteria_id": _MCID_1},
            {"criteria": _CPE_A, "vulnerable": False, "match_criteria_id": _MCID_A},
            {"criteria": _CPE_A, "vulnerable": True, "match_criteria_id": None},
            {"criteria": _CPE_A, "vulnerable": True, "match_criteria_id": _MCID_A},
            {"criteria": _CPE_B, "vulnerable": False, "match_criteria_id": None},
            {"criteria": _CPE_B, "vulnerable": True, "match_criteria_id": _MCID_A},
        ]

    def test_match_criteria_id_is_a_canonical_lowercase_string(self) -> None:
        (match,) = _tasks(
            cpe_matches=[_match(_CPE_A, True, _MCID_A.upper())]
        ).cpe_matches

        assert match["match_criteria_id"] == _MCID_A
        assert type(match["match_criteria_id"]) is str

    def test_serialized_match_has_exactly_the_three_primitive_keys(self) -> None:
        (match,) = _tasks(cpe_matches=[_match(_CPE_A, False, _MCID_1)]).cpe_matches

        assert type(match) is dict
        assert set(match) == {"criteria", "vulnerable", "match_criteria_id"}
        assert type(match["criteria"]) is str
        assert type(match["vulnerable"]) is bool

    def test_criteria_are_ordered_by_code_point(self) -> None:
        criteria = ["cpe:2.3:a:zeta", "cpe:2.3:a:Zeta", "cpe:2.3:a:alpha"]

        tasks = _tasks(cpe_matches=[_match(c, True) for c in criteria])

        assert [m["criteria"] for m in tasks.cpe_matches] == [
            "cpe:2.3:a:Zeta",
            "cpe:2.3:a:alpha",
            "cpe:2.3:a:zeta",
        ]


@pytest.mark.unit
class TestAffectedCPEs:
    def test_cpes_come_from_replace_entries_deduplicated_in_code_point_order(
        self,
    ) -> None:
        tasks = _tasks(
            affected_version_operations=[
                _replace(
                    "cna",
                    {"cpe": "cpe:2.3:a:éxample:widget", "version": "1"},
                    {"cpe": "cpe:2.3:a:example:widget", "version": "2"},
                    {"cpe": None, "version": "3"},
                ),
                _replace(
                    "adp:EXAMPLE",
                    {"cpe": "cpe:2.3:a:Example:widget", "version": "1"},
                    {"cpe": "cpe:2.3:a:example:widget", "version": "2"},
                ),
                _remove("adp:OTHER"),
            ]
        )

        assert tasks.affected_cpes == [
            "cpe:2.3:a:Example:widget",
            "cpe:2.3:a:example:widget",
            "cpe:2.3:a:éxample:widget",
        ]

    def test_cpe_matches_and_affected_cpes_stay_separate(self) -> None:
        tasks = _tasks(
            cpe_matches=[_match(_CPE_A, True)],
            affected_version_operations=[_replace("cna", {"cpe": _CPE_B})],
        )

        assert [m["criteria"] for m in tasks.cpe_matches] == [_CPE_A]
        assert tasks.affected_cpes == [_CPE_B]

    def test_empty_string_cpe_is_transported(self) -> None:
        """The specification filters only `None` CPEs; every value is a
        candidate that later package-domain validation may discard."""
        assert _tasks(
            affected_version_operations=[_replace("cna", {"cpe": ""})]
        ).affected_cpes == [""]


@pytest.mark.unit
class TestVendorProducts:
    def test_pairs_require_both_values_and_are_ordered_vendor_then_product(
        self,
    ) -> None:
        tasks = _tasks(
            affected_version_operations=[
                _replace(
                    "cna",
                    {"vendor": "example", "product": "beta"},
                    {"vendor": "example", "product": "alpha"},
                    {"vendor": "Example", "product": "zeta"},
                    {"vendor": None, "product": "orphan"},
                    {"vendor": "lonely", "product": None},
                ),
                _replace(
                    "adp:EXAMPLE",
                    {"vendor": "example", "product": "alpha", "version": "9"},
                    {"vendor": "éxample", "product": "alpha"},
                ),
            ]
        )

        assert tasks.vendor_products == [
            ["Example", "zeta"],
            ["example", "alpha"],
            ["example", "beta"],
            ["éxample", "alpha"],
        ]
        assert all(
            type(pair) is list and len(pair) == 2 and all(type(v) is str for v in pair)
            for pair in tasks.vendor_products
        )

    def test_vendor_only_entries_yield_no_pair(self) -> None:
        tasks = _tasks(
            affected_version_operations=[_replace("cna", {"vendor": "example"})],
            resolved_packages=["example-package"],
        )

        assert tasks.vendor_products == []


_ACCEPTED_NAMES = [
    "a",
    "x" * 50,
    "kernel-source",
    "python3-example_pkg.1+git",
    "paquete-ñ",
]
_REJECTED_NAMES = [
    "",
    "x" * 51,
    "example/package",
    "example:package",
    "example package",
    "example\tpackage",
    "example\npackage",
    " example",
    "example\u00a0package",
    "example\u2003package",
    "example\u3000package",
    "example\x0bpackage",
]


def _name_payload(source: str, name: str) -> dict[str, Any]:
    if source == "direct":
        return {"resolved_packages": [name]}
    return {"affected_version_operations": [_replace("cna", {"package_name": name})]}


@pytest.mark.unit
class TestResolvedPackages:
    @pytest.mark.parametrize("source", ["direct", "package_name"])
    @pytest.mark.parametrize("name", _ACCEPTED_NAMES)
    def test_valid_name_is_a_candidate(self, source: str, name: str) -> None:
        assert _tasks(**_name_payload(source, name)).resolved_packages == [name]

    @pytest.mark.parametrize("source", ["direct", "package_name"])
    @pytest.mark.parametrize("name", _REJECTED_NAMES)
    def test_invalid_name_is_filtered(self, source: str, name: str) -> None:
        assert _build(**_name_payload(source, name)) is None

    def test_direct_and_entry_names_are_merged_deduplicated_and_ordered(
        self,
    ) -> None:
        tasks = _tasks(
            resolved_packages=["zeta", "kernel-source", "zeta", "Zeta", "bad/name"],
            affected_version_operations=[
                _replace(
                    "cna",
                    {"package_name": "kernel-source", "version": "1"},
                    {"package_name": "alpha", "version": "2"},
                    {"package_name": "bad:name", "version": "3"},
                ),
                _replace("adp:EXAMPLE", {"package_name": "ñame"}),
            ],
        )

        assert tasks.resolved_packages == [
            "Zeta",
            "alpha",
            "kernel-source",
            "zeta",
            "ñame",
        ]

    def test_filtered_entry_name_does_not_suppress_its_other_candidates(
        self,
    ) -> None:
        tasks = _tasks(
            affected_version_operations=[
                _replace(
                    "cna",
                    {
                        "vendor": "example",
                        "product": "widget",
                        "cpe": _CPE_A,
                        "package_name": "example/widget",
                    },
                )
            ]
        )

        assert tasks.affected_cpes == [_CPE_A]
        assert tasks.vendor_products == [["example", "widget"]]
        assert tasks.resolved_packages == []


@pytest.mark.unit
class TestOperationsContribution:
    def test_remove_and_empty_replacement_contribute_nothing(self) -> None:
        tasks = _tasks(
            affected_version_operations=[
                _remove("adp:GONE"),
                _replace("adp:EMPTY"),
                _replace(
                    "cna",
                    {
                        "vendor": "example",
                        "product": "widget",
                        "cpe": _CPE_A,
                        "package_name": "widget",
                    },
                ),
            ]
        )

        assert tasks == PostIngestTasks(
            ticket_id=str(_TICKET_PK),
            cpe_matches=[],
            affected_cpes=[_CPE_A],
            vendor_products=[["example", "widget"]],
            resolved_packages=["widget"],
        )

    def test_input_order_does_not_change_the_result(self) -> None:
        operations = [
            _replace(
                "cna",
                {"vendor": "b", "product": "y", "cpe": _CPE_B, "package_name": "b"},
                {"vendor": "a", "product": "x", "cpe": _CPE_A, "package_name": "a"},
            ),
            _replace("adp:EXAMPLE", {"vendor": "c", "product": "z"}),
        ]
        matches = [_match(_CPE_B, True), _match(_CPE_A, False, _MCID_1)]
        names = ["kernel-source", "alpha"]

        forward = _tasks(
            affected_version_operations=operations,
            cpe_matches=matches,
            resolved_packages=names,
        )
        backward = _tasks(
            affected_version_operations=[
                {**op, "entries": op["entries"][::-1]} for op in operations[::-1]
            ],
            cpe_matches=matches[::-1],
            resolved_packages=names[::-1],
        )

        assert forward == backward

    def test_result_action_does_not_gate_extraction(self) -> None:
        payload = CVEIngestPayload(resolved_packages=["widget"])
        results = [
            UpsertResult(
                cve=CVE(id=_CVE_PK, cve_id="CVE-2099-0001"),
                ticket=Ticket(id=_TICKET_PK),
                action=action,
            )
            for action in UpsertAction
        ]

        expected = PostIngestTasks(
            ticket_id=str(_TICKET_PK),
            cpe_matches=[],
            affected_cpes=[],
            vendor_products=[],
            resolved_packages=["widget"],
        )
        for result in results:
            assert build_post_ingest_tasks(result, payload) == expected


@pytest.mark.unit
class TestSerializationAndPurity:
    def test_result_is_json_serializable(self) -> None:
        tasks = _tasks(
            cpe_matches=[_match(_CPE_A, True, _MCID_1), _match(_CPE_A, False)],
            affected_version_operations=[
                _replace(
                    "cna",
                    {
                        "vendor": "example",
                        "product": "widget",
                        "cpe": _CPE_B,
                        "package_name": "widget",
                    },
                )
            ],
            resolved_packages=["kernel-source"],
        )
        values = dataclasses.asdict(tasks)

        assert json.loads(json.dumps(values)) == values
        assert values == {
            "ticket_id": str(_TICKET_PK),
            "cpe_matches": [
                {"criteria": _CPE_A, "vulnerable": False, "match_criteria_id": None},
                {"criteria": _CPE_A, "vulnerable": True, "match_criteria_id": _MCID_1},
            ],
            "affected_cpes": [_CPE_B],
            "vendor_products": [["example", "widget"]],
            "resolved_packages": ["kernel-source", "widget"],
        }

    def test_helper_is_synchronous(self) -> None:
        assert not inspect.iscoroutinefunction(build_post_ingest_tasks)

    def test_extraction_performs_no_outbound_call(
        self, no_outbound: OutboundGuard
    ) -> None:
        tasks = _tasks(
            cpe_matches=[_match(_CPE_A, True)],
            affected_version_operations=[
                _replace("cna", {"vendor": "example", "product": "widget"})
            ],
            resolved_packages=["widget"],
        )

        assert tasks.resolved_packages == ["widget"]
        assert no_outbound.attempts == []
