"""Unit tests for the source-neutral CVE ingestion values in
backend/app/services/cve_ingest.py.

Implements docs/features/tickets/cve-service.md:

- CVEIngestPayload Schema (and its Design notes): every field optional,
  `model_fields_set` as the authority for global-field presence, UTC
  timestamp normalization, field bounds aligned with CVE JSON 5.x and the
  data model, untrusted vector-only CVSS candidates, and the
  affected-version operation shapes.
- Canonical Payload Duplicate Handling: the affected-version entry
  conflict key, identical-entry collapse, and same-key differing-content
  rejection before any database write.
- Affected-Version Snapshot Operations: at most one operation per
  `source_container`, identical duplicate operations collapse, differing
  operations for one scope are rejected, and scopes never interact.
- UpsertResult and PostIngestTasks: the action values and the frozen
  handoff value.
- Exceptions: canonical payload validation raises
  `pydantic.ValidationError` during construction.

Issue #750 decisions pinned here: every payload model forbids unknown
fields, is frozen, and hides input values in validation errors (D12);
`ExternalIdentifierEntry.source` is `CVEExternalIdentifierSource` (D4);
naive datetimes are UTC and every payload datetime is aware UTC (D5;
docs/conventions.md, Timestamps & Timezones).

All identifiers, hosts, and names are fictional.
"""

from __future__ import annotations

import dataclasses
import math
import uuid
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, get_args

import pytest
from pydantic import BaseModel, ValidationError

from app.core.enums import (
    CVEExternalIdentifierSource,
    CveState,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
)
from app.services.cve_ingest import (
    AFFECTED_VERSION_FIELDS,
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CPEMatchEntry,
    CVEIngestPayload,
    CVSSAssessmentEntry,
    CWEEntry,
    EPSSEntry,
    ExternalIdentifierEntry,
    KEVEntry,
    NormalizedScopeOperation,
    PostIngestTasks,
    SSVCEntry,
    UpsertAction,
    affected_version_content,
    normalize_affected_version_operations,
    normalize_cwe_classifications,
    normalize_external_identifiers,
)

_GLOBAL_FIELDS = (
    "title",
    "description",
    "published_date",
    "modified_date",
    "date_rejected",
    "cve_state",
)
_NULLABLE_GLOBAL_FIELDS = tuple(f for f in _GLOBAL_FIELDS if f != "cve_state")

_CPE = "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"
_SSVC: dict[str, Any] = {
    "exploitation": "none",
    "automatable": "no",
    "technical_impact": "partial",
    "version": "2.0.3",
}

# Minimal valid input of each payload model, used as the base of bound tests.
_BASES: dict[type[BaseModel], dict[str, Any]] = {
    CVEIngestPayload: {},
    CWEEntry: {"cwe_id": "CWE-79", "source": "NVD"},
    AffectedVersionEntry: {},
    AffectedVersionScopeOperation: {"source_container": "cna", "operation": "remove"},
    SSVCEntry: _SSVC,
    KEVEntry: {"date_added": "2099-01-01"},
    EPSSEntry: {"score": 0.5, "percentile": 0.5, "assessed_at": "2099-01-01"},
    CPEMatchEntry: {"criteria": _CPE, "vulnerable": True},
    ExternalIdentifierEntry: {"source": "GHSA", "identifier": "GHSA-0000-0000-0000"},
    CVSSAssessmentEntry: {"provider_name": "nvd", "vector_string": "AV:N"},
}


def _build(model: type[BaseModel], **overrides: Any) -> BaseModel:
    return model.model_validate({**_BASES[model], **overrides})


def _entry(**values: Any) -> AffectedVersionEntry:
    return AffectedVersionEntry.model_validate(values)


def _replace(
    scope: str, *entries: AffectedVersionEntry
) -> AffectedVersionScopeOperation:
    return AffectedVersionScopeOperation(
        source_container=scope, operation="replace", entries=list(entries)
    )


def _remove(scope: str) -> AffectedVersionScopeOperation:
    return AffectedVersionScopeOperation(source_container=scope, operation="remove")


def _payload_with_operations(
    *operations: AffectedVersionScopeOperation,
) -> CVEIngestPayload:
    return CVEIngestPayload(affected_version_operations=list(operations))


@pytest.mark.unit
class TestFieldPresence:
    def test_empty_payload_is_valid_with_every_field_unset(self) -> None:
        payload = CVEIngestPayload()

        assert payload.model_fields_set == set()
        assert all(
            getattr(payload, name) is None for name in CVEIngestPayload.model_fields
        )

    @pytest.mark.parametrize("field", _GLOBAL_FIELDS)
    def test_omitted_global_field_is_not_in_fields_set(self, field: str) -> None:
        payload = CVEIngestPayload(resolved_packages=["example-package"])

        assert payload.model_fields_set == {"resolved_packages"}
        assert getattr(payload, field) is None

    @pytest.mark.parametrize("field", _NULLABLE_GLOBAL_FIELDS)
    def test_explicit_null_global_field_is_in_fields_set(self, field: str) -> None:
        payload = CVEIngestPayload.model_validate({field: None})

        assert payload.model_fields_set == {field}
        assert getattr(payload, field) is None

    def test_explicit_null_cve_state_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="cve_state"):
            CVEIngestPayload.model_validate({"cve_state": None})

    @pytest.mark.parametrize("state", list(CveState))
    def test_each_cve_state_is_accepted(self, state: CveState) -> None:
        payload = CVEIngestPayload(cve_state=state.value)

        assert payload.cve_state is state
        assert "cve_state" in payload.model_fields_set

    def test_unknown_cve_state_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CVEIngestPayload(cve_state="RESERVED")

    def test_published_with_date_rejected_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="PUBLISHED"):
            CVEIngestPayload(
                cve_state=CveState.PUBLISHED,
                date_rejected=datetime(2099, 1, 1, tzinfo=UTC),
            )

    def test_rejected_with_date_rejected_is_accepted(self) -> None:
        payload = CVEIngestPayload(
            cve_state=CveState.REJECTED,
            date_rejected=datetime(2099, 1, 1, tzinfo=UTC),
        )

        assert payload.date_rejected == datetime(2099, 1, 1, tzinfo=UTC)

    def test_published_with_omitted_date_rejected_is_accepted(self) -> None:
        payload = CVEIngestPayload(cve_state=CveState.PUBLISHED)

        assert "date_rejected" not in payload.model_fields_set

    def test_published_with_null_date_rejected_is_accepted(self) -> None:
        payload = CVEIngestPayload(cve_state=CveState.PUBLISHED, date_rejected=None)

        assert payload.model_fields_set == {"cve_state", "date_rejected"}

    def test_date_rejected_without_cve_state_is_accepted(self) -> None:
        """Only an explicit `PUBLISHED` state conflicts with a rejection date."""
        payload = CVEIngestPayload(date_rejected=datetime(2099, 1, 1, tzinfo=UTC))

        assert payload.cve_state is None


_DATETIME_FIELDS: list[tuple[str, Callable[[datetime], datetime | None]]] = [
    ("published_date", lambda v: CVEIngestPayload(published_date=v).published_date),
    ("modified_date", lambda v: CVEIngestPayload(modified_date=v).modified_date),
    (
        "date_rejected",
        lambda v: (
            CVEIngestPayload(cve_state=CveState.REJECTED, date_rejected=v).date_rejected
        ),
    ),
    (
        "ssvc_assessed_at",
        lambda v: SSVCEntry.model_validate({**_SSVC, "assessed_at": v}).assessed_at,
    ),
]


@pytest.mark.unit
class TestDatetimeNormalization:
    @pytest.mark.parametrize(("field", "parse"), _DATETIME_FIELDS)
    def test_naive_datetime_is_utc_with_same_wall_clock(
        self, field: str, parse: Callable[[datetime], datetime | None]
    ) -> None:
        naive = datetime(2099, 3, 4, 5, 6, 7, 890)  # noqa: DTZ001 - naive input under test

        value = parse(naive)

        assert value is not None
        assert value.tzinfo is UTC
        assert value.replace(tzinfo=None) == naive

    @pytest.mark.parametrize(("field", "parse"), _DATETIME_FIELDS)
    def test_offset_datetime_is_converted_to_the_utc_instant(
        self, field: str, parse: Callable[[datetime], datetime | None]
    ) -> None:
        offset = datetime(2099, 3, 4, 1, 30, tzinfo=timezone(timedelta(hours=+2)))

        value = parse(offset)

        assert value is not None
        assert value.tzinfo is UTC
        assert value == offset
        assert (value.day, value.hour, value.minute) == (3, 23, 30)

    def test_iso_strings_are_normalized_like_datetimes(self) -> None:
        payload = CVEIngestPayload(
            published_date="2099-03-04T05:06:07",
            modified_date="2099-03-04T05:06:07-05:00",
        )

        assert payload.published_date == datetime(2099, 3, 4, 5, 6, 7, tzinfo=UTC)
        assert payload.modified_date == datetime(2099, 3, 4, 10, 6, 7, tzinfo=UTC)
        assert payload.modified_date is not None
        assert payload.modified_date.tzinfo is UTC

    def test_ssvc_assessed_at_may_be_omitted(self) -> None:
        assert SSVCEntry.model_validate(_SSVC).assessed_at is None


@pytest.mark.unit
class TestModelConfiguration:
    @pytest.mark.parametrize("model", list(_BASES), ids=lambda m: m.__name__)
    def test_extra_field_is_rejected(self, model: type[BaseModel]) -> None:
        with pytest.raises(ValidationError, match="extra_forbidden"):
            _build(model, unexpected_field="value")

    def test_extra_field_in_nested_payload_input_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match=r"kev_data\.unexpected_field"):
            CVEIngestPayload.model_validate(
                {"kev_data": {"date_added": "2099-01-01", "unexpected_field": 1}}
            )

    @pytest.mark.parametrize("model", list(_BASES), ids=lambda m: m.__name__)
    def test_model_is_frozen(self, model: type[BaseModel]) -> None:
        instance = _build(model)
        name = next(iter(model.model_fields))

        with pytest.raises(ValidationError, match="frozen_instance"):
            setattr(instance, name, getattr(instance, name))

    def test_overlong_title_error_hides_the_input(self) -> None:
        marker = "FICTIONAL-SECRET-MARKER-7f3a"
        with pytest.raises(ValidationError) as excinfo:
            CVEIngestPayload(title="t" * 256 + marker)

        assert marker not in str(excinfo.value)
        assert marker not in repr(excinfo.value)

    def test_extra_field_error_hides_the_value(self) -> None:
        marker = "FICTIONAL-SECRET-MARKER-91bc"
        with pytest.raises(ValidationError) as excinfo:
            CVEIngestPayload.model_validate(
                {"affected_version_operations": [{"bogus": marker}]}
            )

        assert marker not in str(excinfo.value)
        assert marker not in repr(excinfo.value)

    def test_model_validator_error_hides_the_input(self) -> None:
        marker = "FICTIONAL-SECRET-MARKER-c0de"
        with pytest.raises(ValidationError) as excinfo:
            _payload_with_operations(
                _replace(
                    "cna",
                    _entry(vendor="v", product="p", program_files=["a"]),
                    _entry(vendor="v", product="p", program_files=[marker]),
                )
            )

        assert marker not in str(excinfo.value)


# (model, field, maximum length)
_STRING_BOUNDS: list[tuple[type[BaseModel], str, int]] = [
    (CVEIngestPayload, "title", 256),
    (CWEEntry, "source", 100),
    (AffectedVersionEntry, "vendor", 512),
    (AffectedVersionEntry, "package_url", 2048),
    (AffectedVersionEntry, "collection_url", 2048),
    (AffectedVersionEntry, "package_name", 2048),
    (AffectedVersionEntry, "repo", 2048),
    (AffectedVersionEntry, "cpe", 2048),
    (AffectedVersionEntry, "version_type", 128),
    (AffectedVersionEntry, "ecosystem", 50),
    (AffectedVersionEntry, "status", 20),
    (AffectedVersionEntry, "default_status", 20),
    (AffectedVersionScopeOperation, "source_container", 100),
    (SSVCEntry, "version", 10),
    (KEVEntry, "reference_url", 2048),
    (CPEMatchEntry, "criteria", 2048),
    (ExternalIdentifierEntry, "identifier", 100),
    (ExternalIdentifierEntry, "url", 2048),
]

_UNBOUNDED: list[tuple[type[BaseModel], str]] = [
    (CVEIngestPayload, "description"),
    (AffectedVersionEntry, "product"),
    (AffectedVersionEntry, "version"),
    (AffectedVersionEntry, "version_end"),
]


def _bound_id(case: tuple[Any, ...]) -> str:
    return f"{case[0].__name__}.{case[1]}"


@pytest.mark.unit
class TestFieldBounds:
    @pytest.mark.parametrize(
        ("model", "field", "maximum"),
        _STRING_BOUNDS,
        ids=map(_bound_id, _STRING_BOUNDS),
    )
    def test_string_at_maximum_length_is_accepted(
        self, model: type[BaseModel], field: str, maximum: int
    ) -> None:
        assert getattr(_build(model, **{field: "x" * maximum}), field) == "x" * maximum

    @pytest.mark.parametrize(
        ("model", "field", "maximum"),
        _STRING_BOUNDS,
        ids=map(_bound_id, _STRING_BOUNDS),
    )
    def test_string_over_maximum_length_is_rejected(
        self, model: type[BaseModel], field: str, maximum: int
    ) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            _build(model, **{field: "x" * (maximum + 1)})

    @pytest.mark.parametrize(
        ("model", "field"), _UNBOUNDED, ids=map(_bound_id, _UNBOUNDED)
    )
    def test_unbounded_string_accepts_a_long_value(
        self, model: type[BaseModel], field: str
    ) -> None:
        value = "x" * 100_000

        assert getattr(_build(model, **{field: value}), field) == value

    def test_cwe_id_at_maximum_length_is_accepted(self) -> None:
        cwe_id = "CWE-" + "1" * 16

        assert len(cwe_id) == 20
        assert CWEEntry(cwe_id=cwe_id, source="NVD").cwe_id == cwe_id

    def test_cwe_id_over_maximum_length_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="string_too_long"):
            CWEEntry(cwe_id="CWE-" + "1" * 17, source="NVD")

    @pytest.mark.parametrize("cwe_id", ["CWE-1", "CWE-79", "CWE-1004"])
    def test_cwe_id_matching_the_pattern_is_accepted(self, cwe_id: str) -> None:
        assert CWEEntry(cwe_id=cwe_id, source="NVD").cwe_id == cwe_id

    @pytest.mark.parametrize(
        "cwe_id",
        ["CWE-0", "CWE-079", "cwe-79", "CWE-", "CWE79", "NVD-CWE-Other", "CWE-79a"],
    )
    def test_cwe_id_violating_the_pattern_is_rejected(self, cwe_id: str) -> None:
        with pytest.raises(ValidationError, match="string_pattern_mismatch"):
            CWEEntry(cwe_id=cwe_id, source="NVD")

    def test_cwe_id_with_trailing_newline_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CWEEntry(cwe_id="CWE-79\n", source="NVD")

    @pytest.mark.parametrize("field", ["score", "percentile"])
    @pytest.mark.parametrize("value", [0.0, 1.0, 0.5])
    def test_epss_value_within_inclusive_bounds_is_accepted(
        self, field: str, value: float
    ) -> None:
        assert getattr(_build(EPSSEntry, **{field: value}), field) == value

    @pytest.mark.parametrize("field", ["score", "percentile"])
    @pytest.mark.parametrize(
        "value", [math.nextafter(0.0, -1.0), math.nextafter(1.0, 2.0), -1.0, 1.5]
    )
    def test_epss_value_outside_bounds_is_rejected(
        self, field: str, value: float
    ) -> None:
        with pytest.raises(ValidationError):
            _build(EPSSEntry, **{field: value})

    @pytest.mark.parametrize(
        ("field", "enum"),
        [
            ("exploitation", SSVCExploitation),
            ("automatable", SSVCAutomatable),
            ("technical_impact", SSVCTechnicalImpact),
        ],
    )
    def test_ssvc_decision_points_accept_exactly_their_enum(
        self, field: str, enum: type[SSVCExploitation]
    ) -> None:
        for member in enum:
            assert getattr(_build(SSVCEntry, **{field: member.value}), field) is member
        with pytest.raises(ValidationError):
            _build(SSVCEntry, **{field: "unknown"})

    @pytest.mark.parametrize("source", list(CVEExternalIdentifierSource))
    def test_external_identifier_source_accepts_each_enum_value(
        self, source: CVEExternalIdentifierSource
    ) -> None:
        entry = _build(ExternalIdentifierEntry, source=source.value)

        assert isinstance(entry, ExternalIdentifierEntry)
        assert entry.source is source

    @pytest.mark.parametrize("source", ["ghsa", "OSV", ""])
    def test_external_identifier_unknown_source_is_rejected(self, source: str) -> None:
        with pytest.raises(ValidationError):
            _build(ExternalIdentifierEntry, source=source)

    def test_cpe_match_criteria_id_is_parsed_as_uuid(self) -> None:
        entry = CPEMatchEntry(
            criteria=_CPE,
            vulnerable=False,
            match_criteria_id="0A1B2C3D-0000-4000-8000-000000000001",
        )

        assert entry.match_criteria_id == uuid.UUID(
            "0a1b2c3d-0000-4000-8000-000000000001"
        )

    def test_cpe_match_malformed_criteria_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CPEMatchEntry(criteria=_CPE, vulnerable=True, match_criteria_id="nope")


def _string_fields(model: type[BaseModel]) -> list[tuple[str, bool]]:
    """`(field, is_list)` for every `str` and `list[str]` field of `model`."""
    fields = []
    for name, info in model.model_fields.items():
        members = get_args(info.annotation) or (info.annotation,)
        if str in members:
            fields.append((name, False))
        elif list[str] in members:
            fields.append((name, True))
    return fields


# Every string-bearing field, pinned so the derived cases cannot be vacuous.
_NUL_CASES: list[tuple[type[BaseModel], str, bool]] = [
    (model, name, is_list)
    for model in _BASES
    if model is not CVSSAssessmentEntry
    for name, is_list in _string_fields(model)
]
_NUL_TEMPLATES = ["\x00", "\x00{}", "{}\x00{}", "{}\x00"]
_NUL_MARKER = "FICTIONAL-SECRET-MARKER-0000"


def _nul_id(case: tuple[Any, ...]) -> str:
    return f"{case[0].__name__}.{case[1]}"


@pytest.mark.unit
class TestNulRejection:
    """External String Admissibility (cve-service.md, CVEIngestPayload
    Schema design notes): U+0000 in any string value is a payload
    validation failure; untyped CVSS candidates are excluded."""

    def test_every_string_field_is_covered(self) -> None:
        assert {(model.__name__, name) for model, name, _ in _NUL_CASES} == {
            ("CVEIngestPayload", "title"),
            ("CVEIngestPayload", "description"),
            ("CVEIngestPayload", "resolved_packages"),
            ("CWEEntry", "cwe_id"),
            ("CWEEntry", "source"),
            *(
                ("AffectedVersionEntry", name)
                for name in AFFECTED_VERSION_FIELDS
                if name != "version_end_inclusive"
            ),
            ("AffectedVersionScopeOperation", "source_container"),
            ("SSVCEntry", "version"),
            ("KEVEntry", "reference_url"),
            ("CPEMatchEntry", "criteria"),
            ("ExternalIdentifierEntry", "identifier"),
            ("ExternalIdentifierEntry", "url"),
        }

    @pytest.mark.parametrize("template", _NUL_TEMPLATES)
    @pytest.mark.parametrize(
        ("model", "field", "is_list"), _NUL_CASES, ids=map(_nul_id, _NUL_CASES)
    )
    def test_string_containing_nul_is_rejected(
        self, model: type[BaseModel], field: str, is_list: bool, template: str
    ) -> None:
        value = template.format("1", "2")

        with pytest.raises(ValidationError):
            _build(model, **{field: ["valid", value] if is_list else value})

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({"title": f"{_NUL_MARKER}\x00"}, id="global"),
            pytest.param(
                {
                    "affected_version_operations": [
                        {
                            "source_container": "cna",
                            "operation": "replace",
                            "entries": [{"program_files": [f"{_NUL_MARKER}\x00"]}],
                        }
                    ]
                },
                id="nested-jsonb-item",
            ),
            pytest.param(
                {
                    "cpe_matches": [
                        {"criteria": f"{_NUL_MARKER}\x00", "vulnerable": True}
                    ]
                },
                id="non-persisted-candidate",
            ),
            pytest.param(
                {"resolved_packages": ["widget", f"{_NUL_MARKER}\x00"]},
                id="package-candidate",
            ),
        ],
    )
    def test_payload_rejects_nul_without_rendering_the_value(
        self, data: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError) as excinfo:
            CVEIngestPayload.model_validate(data)

        assert _NUL_MARKER not in str(excinfo.value)
        assert _NUL_MARKER not in repr(excinfo.value)

    def test_cvss_candidate_containing_nul_is_carried_for_individual_skip(
        self,
    ) -> None:
        payload = CVEIngestPayload(
            cvss_assessments=[
                CVSSAssessmentEntry(
                    provider_name="Example\x00CNA", vector_string="CVSS:3.1\x00"
                )
            ]
        )

        assert payload.cvss_assessments is not None
        assert payload.cvss_assessments[0].provider_name == "Example\x00CNA"


@pytest.mark.unit
class TestCVSSAssessmentEntry:
    @pytest.mark.parametrize(
        "value",
        [None, 42, 3.5, "", "x" * 10_000, ["AV:N"], {"vector": "AV:N"}, b"AV:N"],
    )
    def test_any_object_is_accepted_unchanged(self, value: object) -> None:
        entry = CVSSAssessmentEntry(provider_name=value, vector_string=value)

        assert entry.provider_name == value
        assert entry.vector_string == value

    def test_both_fields_are_required(self) -> None:
        with pytest.raises(ValidationError):
            CVSSAssessmentEntry.model_validate({"provider_name": "nvd"})

    def test_payload_carries_invalid_candidates_beside_valid_ones(self) -> None:
        payload = CVEIngestPayload.model_validate(
            {
                "cvss_assessments": [
                    {"provider_name": 7, "vector_string": None},
                    {"provider_name": "nvd", "vector_string": "CVSS:3.1/AV:N"},
                ]
            }
        )

        assert payload.cvss_assessments is not None
        assert len(payload.cvss_assessments) == 2


@pytest.mark.unit
class TestAffectedVersionOperationShape:
    def test_replace_without_entries_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="requires entries"):
            AffectedVersionScopeOperation(source_container="cna", operation="replace")

    def test_replace_with_explicit_null_entries_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="requires entries"):
            AffectedVersionScopeOperation(
                source_container="cna", operation="replace", entries=None
            )

    def test_replace_with_empty_entries_is_accepted(self) -> None:
        operation = AffectedVersionScopeOperation(
            source_container="cna", operation="replace", entries=[]
        )

        assert operation.operation is AffectedVersionOperation.REPLACE
        assert operation.entries == []

    @pytest.mark.parametrize("entries", [[], [{"vendor": "example"}]])
    def test_remove_with_entries_is_rejected(
        self, entries: list[dict[str, Any]]
    ) -> None:
        with pytest.raises(ValidationError, match="must not supply entries"):
            AffectedVersionScopeOperation.model_validate(
                {"source_container": "cna", "operation": "remove", "entries": entries}
            )

    @pytest.mark.parametrize("explicit", [False, True])
    def test_remove_without_entries_is_accepted(self, explicit: bool) -> None:
        data: dict[str, Any] = {"source_container": "cna", "operation": "remove"}
        if explicit:
            data["entries"] = None

        assert AffectedVersionScopeOperation.model_validate(data).entries is None

    def test_unknown_operation_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AffectedVersionScopeOperation(
                source_container="cna", operation="merge", entries=[]
            )

    def test_payload_with_malformed_operation_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CVEIngestPayload.model_validate(
                {
                    "affected_version_operations": [
                        {"source_container": "cna", "operation": "replace"}
                    ]
                }
            )

    @pytest.mark.parametrize("operations", [None, []])
    def test_absent_or_empty_operations_normalize_to_nothing(
        self, operations: list[AffectedVersionScopeOperation] | None
    ) -> None:
        assert normalize_affected_version_operations(operations) == ()


_A = {"vendor": "example", "product": "widget", "version": "1.0"}
_B = {"vendor": "example", "product": "widget", "version": "2.0"}
_C = {"vendor": "example", "product": "gadget"}


@pytest.mark.unit
class TestSameScopeDuplicateOperations:
    def test_identical_duplicate_operations_collapse(self) -> None:
        (normalized,) = normalize_affected_version_operations(
            [_replace("cna", _entry(**_A)), _replace("cna", _entry(**_A))]
        )

        assert normalized.entries == (_entry(**_A),)

    def test_identical_sets_in_different_order_collapse_to_the_first(self) -> None:
        (normalized,) = normalize_affected_version_operations(
            [
                _replace("cna", _entry(**_A), _entry(**_B)),
                _replace("cna", _entry(**_B), _entry(**_A), _entry(**_B)),
            ]
        )

        assert normalized.entries == (_entry(**_A), _entry(**_B))

    def test_identical_remove_operations_collapse(self) -> None:
        (normalized,) = normalize_affected_version_operations(
            [_remove("cna"), _remove("cna")]
        )

        assert normalized.operation is AffectedVersionOperation.REMOVE
        assert normalized.entries is None

    def test_identical_empty_replacements_collapse(self) -> None:
        (normalized,) = normalize_affected_version_operations(
            [_replace("cna"), _replace("cna")]
        )

        assert normalized.entries == ()

    @pytest.mark.parametrize(
        ("first", "second"),
        [
            (_replace("cna", _entry(**_A)), _remove("cna")),
            (_replace("cna"), _remove("cna")),
            (_replace("cna", _entry(**_A)), _replace("cna", _entry(**_B))),
            (
                _replace("cna", _entry(**_A)),
                _replace("cna", _entry(**_A), _entry(**_B)),
            ),
            (_replace("cna", _entry(**_A)), _replace("cna")),
        ],
        ids=[
            "replace-vs-remove",
            "empty-replace-vs-remove",
            "different-sets",
            "subset",
            "non-empty-vs-empty",
        ],
    )
    def test_differing_operations_for_one_scope_are_rejected(
        self,
        first: AffectedVersionScopeOperation,
        second: AffectedVersionScopeOperation,
    ) -> None:
        with pytest.raises(ValueError, match="Differing operations"):
            normalize_affected_version_operations([first, second])
        with pytest.raises(ValidationError, match="Differing operations"):
            _payload_with_operations(first, second)

    def test_differing_operations_for_different_scopes_are_kept(self) -> None:
        normalized = normalize_affected_version_operations(
            [_replace("cna", _entry(**_A)), _remove("adp:EXAMPLE")]
        )

        assert [(n.source_container, n.operation) for n in normalized] == [
            ("adp:EXAMPLE", AffectedVersionOperation.REMOVE),
            ("cna", AffectedVersionOperation.REPLACE),
        ]


_KEY_ONLY: dict[str, Any] = {"vendor": "example", "product": "widget"}


def _entries_of(*entries: AffectedVersionEntry) -> tuple[AffectedVersionEntry, ...]:
    (normalized,) = normalize_affected_version_operations([_replace("cna", *entries)])
    assert normalized.entries is not None
    return normalized.entries


@pytest.mark.unit
class TestEntryConflictKey:
    def test_identical_entries_collapse(self) -> None:
        entry = {**_A, "cpe": _CPE, "program_files": ["bin/widget"]}

        assert _entries_of(_entry(**entry), _entry(**entry)) == (_entry(**entry),)

    @pytest.mark.parametrize(
        ("field", "first", "second"),
        [
            ("status", "affected", "unaffected"),
            ("default_status", "affected", "unknown"),
            ("cpe", _CPE, None),
            ("program_files", ["bin/a"], ["bin/b"]),
            ("program_files", ["bin/a"], None),
            ("package_url", "pkg:generic/widget", None),
            ("collection_url", "https://example.test/a", "https://example.test/b"),
            ("version_end_inclusive", True, False),
        ],
    )
    def test_same_key_with_differing_content_is_rejected(
        self, field: str, first: object, second: object
    ) -> None:
        a = _entry(**_KEY_ONLY, **{field: first})
        b = _entry(**_KEY_ONLY, **{field: second})

        with pytest.raises(ValueError, match="conflict key"):
            _entries_of(a, b)
        with pytest.raises(ValidationError, match="conflict key"):
            _payload_with_operations(_replace("cna", a, b))

    @pytest.mark.parametrize("field", ["vendor", "product"])
    def test_absent_vendor_or_product_differs_from_empty_string(
        self, field: str
    ) -> None:
        absent = _entry(**{**_KEY_ONLY, field: None}, status="affected")
        empty = _entry(**{**_KEY_ONLY, field: ""}, status="unaffected")

        assert _entries_of(absent, empty) == (absent, empty)

    @pytest.mark.parametrize(
        "field",
        [
            "version_type",
            "version",
            "version_end",
            "package_name",
            "ecosystem",
            "repo",
        ],
    )
    def test_absent_coalesced_field_equals_empty_string_in_the_key(
        self, field: str
    ) -> None:
        """An absent value and `""` share one conflict key, but they persist
        different values, so otherwise-identical entries are contradictory
        rather than collapsed: input order never chooses the stored form
        (cve-service.md, Canonical Payload Duplicate Handling)."""
        absent = _entry(**_KEY_ONLY, **{field: None})
        empty = _entry(**_KEY_ONLY, **{field: ""})

        with pytest.raises(ValueError, match="conflict key"):
            _entries_of(absent, empty)
        with pytest.raises(ValueError, match="conflict key"):
            _entries_of(empty, absent)

    @pytest.mark.parametrize(
        "field",
        [
            "version_type",
            "version",
            "version_end",
            "package_name",
            "ecosystem",
            "repo",
        ],
    )
    def test_differing_key_field_values_are_distinct_entries(self, field: str) -> None:
        first = _entry(**_KEY_ONLY, **{field: "one"}, status="affected")
        second = _entry(**_KEY_ONLY, **{field: "two"}, status="unaffected")

        assert _entries_of(first, second) == (first, second)

    def test_entries_in_different_scopes_never_conflict(self) -> None:
        first = _entry(**_KEY_ONLY, status="affected")
        second = _entry(**_KEY_ONLY, status="unaffected")

        normalized = normalize_affected_version_operations(
            [_replace("cna", first), _replace("adp:EXAMPLE", second)]
        )

        assert [(n.source_container, n.entries) for n in normalized] == [
            ("adp:EXAMPLE", (second,)),
            ("cna", (first,)),
        ]


@pytest.mark.unit
class TestNormalizeAffectedVersionOperations:
    def test_scopes_are_ordered_by_code_point(self) -> None:
        scopes = ["cna", "\u00c1dp:example", "adp:alpha", "adp:Zeta"]

        normalized = normalize_affected_version_operations(
            [_remove(scope) for scope in scopes]
        )

        assert [n.source_container for n in normalized] == [
            "adp:Zeta",
            "adp:alpha",
            "cna",
            "\u00c1dp:example",
        ]

    def test_entries_keep_first_occurrence_order(self) -> None:
        b, a, c = _entry(**_B), _entry(**_A), _entry(**_C)

        assert _entries_of(b, a, b, c, a) == (b, a, c)

    def test_result_is_a_normalized_scope_operation(self) -> None:
        (normalized,) = normalize_affected_version_operations(
            [_replace("cna", _entry(**_A))]
        )

        assert normalized == NormalizedScopeOperation(
            source_container="cna",
            operation=AffectedVersionOperation.REPLACE,
            entries=(_entry(**_A),),
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            normalized.source_container = "other"  # type: ignore[misc]

    def test_content_is_the_set_of_entry_contents(self) -> None:
        (normalized,) = normalize_affected_version_operations(
            [_replace("cna", _entry(**_A), _entry(**_B), _entry(**_A))]
        )

        assert normalized.content() == frozenset(
            {
                affected_version_content(_entry(**_A)),
                affected_version_content(_entry(**_B)),
            }
        )

    @pytest.mark.parametrize(
        "operation", [_remove("cna"), _replace("cna")], ids=["remove", "empty-replace"]
    )
    def test_content_of_remove_and_empty_replace_is_empty(
        self, operation: AffectedVersionScopeOperation
    ) -> None:
        (normalized,) = normalize_affected_version_operations([operation])

        assert normalized.content() == frozenset()

    def test_payload_keeps_its_input_operations_unchanged(self) -> None:
        """Normalization validates the payload; the payload still carries
        the received operations for `upsert_cve()` to normalize again."""
        operations = [_replace("cna", _entry(**_A), _entry(**_A)), _remove("adp:X")]

        payload = _payload_with_operations(*operations)

        assert payload.affected_version_operations == operations


@pytest.mark.unit
class TestAffectedVersionContent:
    def test_content_follows_the_persisted_field_order(self) -> None:
        values: dict[str, object] = {
            name: f"value-{name}" for name in AFFECTED_VERSION_FIELDS
        }
        values["version_end_inclusive"] = True
        values["program_files"] = ["bin/a", "bin/b"]
        entry = _entry(**values)

        content = affected_version_content(entry)

        assert len(content) == len(AFFECTED_VERSION_FIELDS) == 15
        assert content[AFFECTED_VERSION_FIELDS.index("program_files")] == (
            "bin/a",
            "bin/b",
        )
        assert content[0] == "value-vendor"
        hash(content)

    def test_absent_program_files_stay_none(self) -> None:
        content = affected_version_content(_entry())

        assert content == (None,) * len(AFFECTED_VERSION_FIELDS)

    def test_stored_row_and_entry_have_equal_content(self) -> None:
        entry = _entry(**_A, program_files=["bin/a"])
        row = SimpleNamespace(
            **{name: getattr(entry, name) for name in AFFECTED_VERSION_FIELDS}
        )

        assert affected_version_content(row) == affected_version_content(entry)

    def test_fields_match_the_entry_model(self) -> None:
        assert set(AFFECTED_VERSION_FIELDS) == set(AffectedVersionEntry.model_fields)


@pytest.mark.unit
class TestNormalizeCWEClassifications:
    def test_duplicates_collapse_in_code_point_order(self) -> None:
        entries = [
            CWEEntry(cwe_id="CWE-79", source="cna:Example"),
            CWEEntry(cwe_id="CWE-20", source="NVD"),
            CWEEntry(cwe_id="CWE-79", source="NVD"),
            CWEEntry(cwe_id="CWE-79", source="cna:Example"),
            CWEEntry(cwe_id="CWE-100", source="NVD"),
        ]

        assert normalize_cwe_classifications(entries) == (
            ("CWE-100", "NVD"),
            ("CWE-20", "NVD"),
            ("CWE-79", "NVD"),
            ("CWE-79", "cna:Example"),
        )

    @pytest.mark.parametrize("entries", [None, []])
    def test_absent_or_empty_is_empty(self, entries: list[CWEEntry] | None) -> None:
        assert normalize_cwe_classifications(entries) == ()

    def test_payload_accepts_identical_duplicates(self) -> None:
        payload = CVEIngestPayload.model_validate(
            {"cwe_classifications": [{"cwe_id": "CWE-79", "source": "NVD"}] * 2}
        )

        assert payload.cwe_classifications is not None
        assert len(payload.cwe_classifications) == 2


def _ext(
    source: str, identifier: str, url: str | None = None
) -> ExternalIdentifierEntry:
    return ExternalIdentifierEntry(source=source, identifier=identifier, url=url)


@pytest.mark.unit
class TestNormalizeExternalIdentifiers:
    def test_identical_entries_collapse(self) -> None:
        entry = _ext("GHSA", "GHSA-aaaa-bbbb-cccc", "https://example.test/a")

        assert normalize_external_identifiers([entry, entry]) == (entry,)

    @pytest.mark.parametrize(
        ("first", "second"),
        [
            ("https://example.test/a", "https://example.test/b"),
            ("https://example.test/a", None),
        ],
    )
    def test_same_key_with_differing_url_is_rejected(
        self, first: str | None, second: str | None
    ) -> None:
        entries = [_ext("GHSA", "GHSA-1", first), _ext("GHSA", "GHSA-1", second)]

        with pytest.raises(ValueError, match="differing content"):
            normalize_external_identifiers(entries)
        with pytest.raises(ValidationError, match="differing content"):
            CVEIngestPayload(external_identifiers=entries)

    def test_same_identifier_under_different_sources_is_distinct(self) -> None:
        entries = [_ext("PYSEC", "ID-1", "u1"), _ext("GHSA", "ID-1", "u2")]

        assert normalize_external_identifiers(entries) == (entries[1], entries[0])

    def test_entries_are_ordered_by_source_then_identifier(self) -> None:
        entries = [
            _ext("RUSTSEC", "RUSTSEC-2099-0001"),
            _ext("GHSA", "GHSA-zzzz"),
            _ext("PYSEC", "PYSEC-2099-1"),
            _ext("GHSA", "GHSA-Zzzz"),
            _ext("GHSA", "GHSA-aaaa"),
        ]

        assert [
            (e.source.value, e.identifier)
            for e in normalize_external_identifiers(entries)
        ] == [
            ("GHSA", "GHSA-Zzzz"),
            ("GHSA", "GHSA-aaaa"),
            ("GHSA", "GHSA-zzzz"),
            ("PYSEC", "PYSEC-2099-1"),
            ("RUSTSEC", "RUSTSEC-2099-0001"),
        ]

    @pytest.mark.parametrize("entries", [None, []])
    def test_absent_or_empty_is_empty(
        self, entries: list[ExternalIdentifierEntry] | None
    ) -> None:
        assert normalize_external_identifiers(entries) == ()


@pytest.mark.unit
class TestResultValues:
    def test_upsert_action_values(self) -> None:
        assert {a.value for a in UpsertAction} == {"created", "updated", "unchanged"}

    def test_affected_version_operation_values(self) -> None:
        assert {o.value for o in AffectedVersionOperation} == {"replace", "remove"}

    def test_post_ingest_tasks_is_a_frozen_dataclass(self) -> None:
        tasks = PostIngestTasks(
            ticket_id=str(uuid.UUID(int=1)),
            cpe_matches=[],
            affected_cpes=[],
            vendor_products=[],
            resolved_packages=[],
        )

        assert dataclasses.is_dataclass(tasks)
        assert [f.name for f in dataclasses.fields(tasks)] == [
            "ticket_id",
            "cpe_matches",
            "affected_cpes",
            "vendor_products",
            "resolved_packages",
        ]
        with pytest.raises(dataclasses.FrozenInstanceError):
            tasks.ticket_id = "other"  # type: ignore[misc]

    def test_kev_and_epss_dates_stay_dates(self) -> None:
        payload = CVEIngestPayload.model_validate(
            {
                "kev_data": {"date_added": "2099-01-02"},
                "epss_score": {
                    "score": 0.1,
                    "percentile": 0.2,
                    "assessed_at": "2099-01-03",
                },
            }
        )

        assert payload.kev_data is not None
        assert payload.kev_data.date_added == date(2099, 1, 2)
        assert payload.epss_score is not None
        assert payload.epss_score.assessed_at == date(2099, 1, 3)
