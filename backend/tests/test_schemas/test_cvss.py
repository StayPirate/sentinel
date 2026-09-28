"""Unit tests for the CVSS request and response schemas
(`backend/app/schemas/cvss.py`).

See docs/features/tickets/cvss-scoring.md (API Endpoints > Shared
Assessment Item, Get CVSS Assessments for a CVE, and Set or Update SUSE
CVSS Assessment; Input Rules; Accepted Base Vectors > per-version Base
metrics and API wire values) for the authoritative contract under test.
"""

from __future__ import annotations

import json
import typing
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from pydantic import TypeAdapter, ValidationError

from app.schemas.cvss import (
    CVECVSSAssessments,
    CVECVSSAssessmentsResponse,
    CVSS2Metrics,
    CVSS3Metrics,
    CVSS4Metrics,
    CVSS20Assessment,
    CVSS30Assessment,
    CVSS31Assessment,
    CVSS40Assessment,
    CVSSAssessmentItem,
    CVSSAssessmentResponse,
    CVSSVersionValue,
    DefaultCVSSVersionValue,
    SUSECVSSAssessmentRequest,
)

ITEM: TypeAdapter[CVSSAssessmentItem] = TypeAdapter(CVSSAssessmentItem)
ASSESSMENT_ID = UUID("01994c20-7c00-7000-8000-000000000001")
CREATED_AT = datetime(2026, 9, 10, 10, 30, tzinfo=UTC)
UPDATED_AT = datetime(2026, 9, 10, 10, 31, tzinfo=UTC)

ITEM_FIELDS = [
    "id",
    "provider_name",
    "cvss_version",
    "score",
    "severity",
    "vector_string",
    "metrics",
    "created_at",
    "updated_at",
]

V2_METRICS = {
    "access_vector": "network",
    "access_complexity": "low",
    "authentication": "none",
    "confidentiality_impact": "complete",
    "integrity_impact": "complete",
    "availability_impact": "complete",
}
V3_METRICS = {
    "attack_vector": "network",
    "attack_complexity": "low",
    "privileges_required": "none",
    "user_interaction": "none",
    "scope": "unchanged",
    "confidentiality_impact": "high",
    "integrity_impact": "high",
    "availability_impact": "high",
}
V4_METRICS = {
    "attack_vector": "network",
    "attack_complexity": "low",
    "attack_requirements": "none",
    "privileges_required": "none",
    "user_interaction": "none",
    "vulnerable_system_confidentiality": "high",
    "vulnerable_system_integrity": "high",
    "vulnerable_system_availability": "high",
    "subsequent_system_confidentiality": "none",
    "subsequent_system_integrity": "none",
    "subsequent_system_availability": "none",
}
BY_VERSION: dict[str, tuple[type[Any], dict[str, str], str, float, str]] = {
    "2.0": (CVSS20Assessment, V2_METRICS, "AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0, "high"),
    "3.0": (
        CVSS30Assessment,
        V3_METRICS,
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        9.8,
        "critical",
    ),
    "3.1": (
        CVSS31Assessment,
        V3_METRICS,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        9.8,
        "critical",
    ),
    "4.0": (
        CVSS40Assessment,
        V4_METRICS,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        9.3,
        "critical",
    ),
}


def _item(version: str, **overrides: Any) -> dict[str, Any]:
    _, metrics, vector, score, severity = BY_VERSION[version]
    payload: dict[str, Any] = {
        "id": ASSESSMENT_ID,
        "provider_name": "Example Vendor",
        "cvss_version": version,
        "score": score,
        "severity": severity,
        "vector_string": vector,
        "metrics": metrics,
        "created_at": CREATED_AT,
        "updated_at": UPDATED_AT,
    }
    payload.update(overrides)
    return payload


def _composite(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "assessments": [_item("3.1")],
        "default_cvss_version": "3.1",
        "severity": {
            "score": 9.8,
            "version": "3.1",
            "provider": "Example Vendor",
            "label": "critical",
        },
        "eligibility": {"score": 10.0, "source": "fallback"},
    }
    payload.update(overrides)
    return payload


@pytest.mark.unit
class TestAssessmentItem:
    @pytest.mark.parametrize("version", list(BY_VERSION))
    def test_each_version_validates_to_its_own_member(self, version: str) -> None:
        model, metrics, _, _, _ = BY_VERSION[version]

        item = ITEM.validate_python(_item(version))

        assert type(item) is model
        assert item.metrics.model_dump(mode="json") == metrics

    @pytest.mark.parametrize(
        ("version", "foreign_metrics"),
        [
            ("2.0", V3_METRICS),
            ("2.0", V4_METRICS),
            ("3.0", V2_METRICS),
            ("3.1", V4_METRICS),
            ("4.0", V3_METRICS),
            ("4.0", V2_METRICS),
        ],
    )
    def test_metrics_of_another_version_are_rejected(
        self, version: str, foreign_metrics: dict[str, str]
    ) -> None:
        with pytest.raises(ValidationError):
            ITEM.validate_python(_item(version, metrics=foreign_metrics))

    def test_mixed_version_metric_fields_are_rejected(self) -> None:
        mixed = {**V3_METRICS, "access_vector": "network"}
        del mixed["attack_vector"]

        with pytest.raises(ValidationError):
            ITEM.validate_python(_item("3.1", metrics=mixed))

    @pytest.mark.parametrize("version", ["1.0", "3.2", "4", "", None])
    def test_unknown_version_is_rejected(self, version: str | None) -> None:
        with pytest.raises(ValidationError):
            ITEM.validate_python(_item("3.1", cvss_version=version))

    def test_uppercase_metric_values_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ITEM.validate_python(
                _item("3.1", metrics={**V3_METRICS, "attack_vector": "NETWORK"})
            )

    def test_v30_and_v31_share_the_metrics_shape(self) -> None:
        assert CVSS30Assessment.model_fields["metrics"].annotation is CVSS3Metrics
        assert CVSS31Assessment.model_fields["metrics"].annotation is CVSS3Metrics
        assert CVSS20Assessment.model_fields["metrics"].annotation is CVSS2Metrics
        assert CVSS40Assessment.model_fields["metrics"].annotation is CVSS4Metrics

    @pytest.mark.parametrize("version", list(BY_VERSION))
    def test_json_dump_has_the_specified_keys_in_order(self, version: str) -> None:
        _, metrics, vector, score, severity = BY_VERSION[version]

        dumped = json.loads(ITEM.dump_json(ITEM.validate_python(_item(version))))

        assert list(dumped) == ITEM_FIELDS
        assert list(dumped["metrics"]) == list(metrics)
        assert dumped == {
            "id": "01994c20-7c00-7000-8000-000000000001",
            "provider_name": "Example Vendor",
            "cvss_version": version,
            "score": score,
            "severity": severity,
            "vector_string": vector,
            "metrics": metrics,
            "created_at": "2026-09-10T10:30:00Z",
            "updated_at": "2026-09-10T10:31:00Z",
        }
        assert isinstance(dumped["score"], float)

    def test_score_is_a_json_number(self) -> None:
        raw = ITEM.dump_json(ITEM.validate_python(_item("4.0"))).decode()

        assert '"score":9.3' in raw

    def test_item_has_no_cve_identifier_field(self) -> None:
        for model, *_ in BY_VERSION.values():
            assert not {"cve_id", "cve_uuid"} & set(model.model_fields)


@pytest.mark.unit
class TestComposite:
    def test_valid_composite_round_trips(self) -> None:
        composite = CVECVSSAssessments.model_validate(_composite())

        dumped = json.loads(
            CVECVSSAssessmentsResponse(data=composite).model_dump_json()
        )

        assert list(dumped) == ["data"]
        assert list(dumped["data"]) == [
            "assessments",
            "default_cvss_version",
            "severity",
            "eligibility",
        ]
        assert dumped["data"]["severity"] == {
            "score": 9.8,
            "version": "3.1",
            "provider": "Example Vendor",
            "label": "critical",
        }
        assert dumped["data"]["eligibility"] == {"score": 10.0, "source": "fallback"}

    def test_severity_is_nullable_and_serialized_as_null(self) -> None:
        composite = CVECVSSAssessments.model_validate(
            _composite(assessments=[], severity=None)
        )

        dumped = json.loads(composite.model_dump_json())

        assert dumped["severity"] is None
        assert dumped["assessments"] == []

    @pytest.mark.parametrize("field", ["severity", "eligibility", "assessments"])
    def test_required_keys_have_no_default(self, field: str) -> None:
        payload = _composite()
        del payload[field]

        with pytest.raises(ValidationError):
            CVECVSSAssessments.model_validate(payload)

    def test_eligibility_is_not_nullable(self) -> None:
        with pytest.raises(ValidationError):
            CVECVSSAssessments.model_validate(_composite(eligibility=None))

    @pytest.mark.parametrize("value", ["2.0", "3.0", "4", ""])
    def test_default_version_accepts_only_31_and_40(self, value: str) -> None:
        with pytest.raises(ValidationError):
            CVECVSSAssessments.model_validate(_composite(default_cvss_version=value))

    @pytest.mark.parametrize("value", ["3.1", "4.0"])
    def test_default_version_values(self, value: str) -> None:
        composite = CVECVSSAssessments.model_validate(
            _composite(default_cvss_version=value)
        )

        assert composite.default_cvss_version == value

    def test_version_literals(self) -> None:
        assert set(typing.get_args(CVSSVersionValue.__value__)) == {
            "2.0",
            "3.0",
            "3.1",
            "4.0",
        }
        assert set(typing.get_args(DefaultCVSSVersionValue.__value__)) == {
            "3.1",
            "4.0",
        }

    @pytest.mark.parametrize(
        ("field", "value"),
        [("label", "Critical"), ("version", "3.2"), ("label", None)],
    )
    def test_severity_result_uses_lowercase_unified_labels(
        self, field: str, value: str | None
    ) -> None:
        severity = {
            "score": 9.8,
            "version": "3.1",
            "provider": "Example Vendor",
            "label": "critical",
            field: value,
        }

        with pytest.raises(ValidationError):
            CVECVSSAssessments.model_validate(_composite(severity=severity))

    @pytest.mark.parametrize("source", ["SUSE", "nvd", None])
    def test_eligibility_source_is_suse_or_fallback(self, source: str | None) -> None:
        with pytest.raises(ValidationError):
            CVECVSSAssessments.model_validate(
                _composite(eligibility={"score": 10.0, "source": source})
            )


@pytest.mark.unit
class TestSUSEAssessmentRequest:
    """Pydantic owns only the transport shape; the received-length limit is
    checked before any trimming (cvss-scoring.md, Input Rules rule 1)."""

    def test_exactly_200_received_characters_are_accepted_untrimmed(self) -> None:
        value = " " * 10 + "x" * 180 + " " * 10

        request = SUSECVSSAssessmentRequest.model_validate({"vector_string": value})

        assert request.vector_string == value
        assert len(request.vector_string) == 200

    def test_201_received_characters_are_rejected_even_if_trimming_would_fit(
        self,
    ) -> None:
        value = " " + "x" * 199 + " "

        with pytest.raises(ValidationError) as caught:
            SUSECVSSAssessmentRequest.model_validate({"vector_string": value})

        assert [e["type"] for e in caught.value.errors()] == ["string_too_long"]

    @pytest.mark.parametrize(
        ("body", "error_type"),
        [
            pytest.param({}, "missing", id="missing"),
            pytest.param({"vector_string": None}, "string_type", id="null"),
            pytest.param({"vector_string": 3.1}, "string_type", id="number"),
            pytest.param({"vector_string": ["x"]}, "string_type", id="list"),
        ],
    )
    def test_non_string_or_missing_value_is_rejected(
        self, body: dict[str, Any], error_type: str
    ) -> None:
        with pytest.raises(ValidationError) as caught:
            SUSECVSSAssessmentRequest.model_validate(body)

        assert [e["type"] for e in caught.value.errors()] == [error_type]

    def test_domain_rules_are_left_to_the_parser(self) -> None:
        for value in ("", "   ", "cvss:3.1/AV:N", "CVSS:3.1/AV:N /AC:L"):
            request = SUSECVSSAssessmentRequest.model_validate({"vector_string": value})
            assert request.vector_string == value

    def test_response_envelope_wraps_the_shared_item(self) -> None:
        schema = CVSSAssessmentResponse.model_json_schema()

        assert list(schema["properties"]) == ["data"]
        assert schema["required"] == ["data"]
        item = schema["$defs"][schema["properties"]["data"]["$ref"].rsplit("/", 1)[1]]
        assert item["discriminator"]["propertyName"] == "cvss_version"
