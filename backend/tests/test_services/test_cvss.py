"""Unit tests for the pure CVSS module (backend/app/services/cvss.py).

Covers `docs/features/tickets/cvss-scoring.md` (Required Tests: Parser Unit Tests
and Resolution Unit Tests). The received-length 200/201 tests are
owned by the CVSS endpoint request schema (Input Rules rule 1 is enforced
by Pydantic, not by the parser) and are deferred to that work item.

The expected Base-metric wire values below are transcribed independently
from the specification tables rather than read back from the module, so a
drift in the module's grammar table fails these tests.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import itertools
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import pytest

from app.core.enums import (
    CVSS3Scope,
    CVSSAssessmentSeverity,
    CVSSVersion,
    EligibilitySource,
    Severity,
)
from app.core.exceptions import ServiceError
from app.services import cvss
from app.services.cvss import (
    CVSS2BaseMetrics,
    CVSS3BaseMetrics,
    CVSS4BaseMetrics,
    EligibilityResolution,
    ParsedCVSSVector,
    SeverityResolution,
    calculate_severity,
    is_reserved_provider_name,
    resolve_eligibility_score,
    resolve_severity_score,
    validate_cvss_vector,
)
from app.services.ticket_mutations_errors import (
    InvalidCVSSVectorError,
    TicketMutationsError,
)

APP_ROOT = Path(__file__).resolve().parents[2] / "app"

# ---------------------------------------------------------------------------
# Specification tables (cvss-scoring.md, Accepted Base Vectors)
# ---------------------------------------------------------------------------

# version -> (prefix, [(abbreviation, field, {official value: wire value})])
SPEC_GRAMMAR: dict[str, tuple[str, list[tuple[str, str, dict[str, str]]]]] = {
    "2.0": (
        "",
        [
            (
                "AV",
                "access_vector",
                {"L": "local", "A": "adjacent_network", "N": "network"},
            ),
            ("AC", "access_complexity", {"H": "high", "M": "medium", "L": "low"}),
            ("Au", "authentication", {"M": "multiple", "S": "single", "N": "none"}),
            (
                "C",
                "confidentiality_impact",
                {"N": "none", "P": "partial", "C": "complete"},
            ),
            ("I", "integrity_impact", {"N": "none", "P": "partial", "C": "complete"}),
            (
                "A",
                "availability_impact",
                {"N": "none", "P": "partial", "C": "complete"},
            ),
        ],
    ),
}
_V3_GRAMMAR = [
    (
        "AV",
        "attack_vector",
        {"N": "network", "A": "adjacent", "L": "local", "P": "physical"},
    ),
    ("AC", "attack_complexity", {"L": "low", "H": "high"}),
    ("PR", "privileges_required", {"N": "none", "L": "low", "H": "high"}),
    ("UI", "user_interaction", {"N": "none", "R": "required"}),
    ("S", "scope", {"U": "unchanged", "C": "changed"}),
    ("C", "confidentiality_impact", {"N": "none", "L": "low", "H": "high"}),
    ("I", "integrity_impact", {"N": "none", "L": "low", "H": "high"}),
    ("A", "availability_impact", {"N": "none", "L": "low", "H": "high"}),
]
SPEC_GRAMMAR["3.0"] = ("CVSS:3.0/", _V3_GRAMMAR)
SPEC_GRAMMAR["3.1"] = ("CVSS:3.1/", _V3_GRAMMAR)
_V4_IMPACT = {"H": "high", "L": "low", "N": "none"}
SPEC_GRAMMAR["4.0"] = (
    "CVSS:4.0/",
    [
        (
            "AV",
            "attack_vector",
            {"N": "network", "A": "adjacent", "L": "local", "P": "physical"},
        ),
        ("AC", "attack_complexity", {"L": "low", "H": "high"}),
        ("AT", "attack_requirements", {"N": "none", "P": "present"}),
        ("PR", "privileges_required", {"N": "none", "L": "low", "H": "high"}),
        ("UI", "user_interaction", {"N": "none", "P": "passive", "A": "active"}),
        ("VC", "vulnerable_system_confidentiality", _V4_IMPACT),
        ("VI", "vulnerable_system_integrity", _V4_IMPACT),
        ("VA", "vulnerable_system_availability", _V4_IMPACT),
        ("SC", "subsequent_system_confidentiality", _V4_IMPACT),
        ("SI", "subsequent_system_integrity", _V4_IMPACT),
        ("SA", "subsequent_system_availability", _V4_IMPACT),
    ],
)

# One complete, valid canonical vector per version with varied values.
VALID_VECTORS: dict[str, str] = {
    "2.0": "AV:A/AC:M/Au:S/C:P/I:N/A:C",
    "3.0": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H",
    "3.1": "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N",
    "4.0": "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:N/SC:L/SI:H/SA:N",
}
METRICS_TYPES: dict[str, type] = {
    "2.0": CVSS2BaseMetrics,
    "3.0": CVSS3BaseMetrics,
    "3.1": CVSS3BaseMetrics,
    "4.0": CVSS4BaseMetrics,
}
VERSIONS = list(VALID_VECTORS)


def _split(vector: str, version: str) -> tuple[str, list[str]]:
    prefix = SPEC_GRAMMAR[version][0]
    return prefix, vector.removeprefix(prefix).split("/")


def _join(prefix: str, tokens: list[str]) -> str:
    return prefix + "/".join(tokens)


def _missing_metric_cases() -> list[tuple[str, str]]:
    cases = []
    for version, vector in VALID_VECTORS.items():
        prefix, tokens = _split(vector, version)
        for index in range(len(tokens)):
            remaining = tokens[:index] + tokens[index + 1 :]
            cases.append(
                (f"{version}-without-{tokens[index]}", _join(prefix, remaining))
            )
    return cases


def _duplicate_metric_cases() -> list[tuple[str, str]]:
    cases = []
    for version, vector in VALID_VECTORS.items():
        prefix, tokens = _split(vector, version)
        grammar = {abbr: values for abbr, _, values in SPEC_GRAMMAR[version][1]}
        for token in tokens:
            abbreviation, value = token.split(":")
            cases.append((f"{version}-same-{token}", _join(prefix, [*tokens, token])))
            other = next(v for v in grammar[abbreviation] if v != value)
            conflicting = f"{abbreviation}:{other}"
            cases.append(
                (
                    f"{version}-conflicting-{token}",
                    _join(prefix, [*tokens, conflicting]),
                )
            )
    return cases


# Representative non-Base metrics appended to a valid vector.
NON_BASE_METRIC_CASES: list[tuple[str, str]] = [
    # CVSS v2.0 Temporal and Environmental
    ("2.0", "E:F"),
    ("2.0", "RL:OF"),
    ("2.0", "RC:C"),
    ("2.0", "CDP:N"),
    ("2.0", "TD:H"),
    ("2.0", "CR:M"),
    # CVSS v3.x Temporal and Environmental
    ("3.0", "E:F"),
    ("3.1", "RL:O"),
    ("3.1", "RC:C"),
    ("3.1", "CR:H"),
    ("3.0", "MAV:N"),
    ("3.1", "MS:U"),
    # CVSS v4.0 Threat, Environmental, and Supplemental
    ("4.0", "E:A"),
    ("4.0", "CR:H"),
    ("4.0", "MAV:N"),
    ("4.0", "MSI:S"),
    ("4.0", "S:N"),
    ("4.0", "AU:Y"),
    ("4.0", "R:A"),
    ("4.0", "V:D"),
    ("4.0", "RE:L"),
    ("4.0", "U:Red"),
]


# ---------------------------------------------------------------------------
# Parser: valid vectors
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestValidateCvssVectorValid:
    """One complete vector per version yields the full stable parsed result."""

    @pytest.mark.parametrize(
        ("version", "expected_score", "expected_severity"),
        [
            ("2.0", Decimal("5.8"), CVSSAssessmentSeverity.MEDIUM),
            ("3.0", Decimal("6.1"), CVSSAssessmentSeverity.MEDIUM),
            ("3.1", Decimal("4.6"), CVSSAssessmentSeverity.MEDIUM),
            ("4.0", Decimal("5.7"), CVSSAssessmentSeverity.MEDIUM),
        ],
    )
    def test_validate_complete_vector_returns_full_parsed_result(
        self,
        version: str,
        expected_score: Decimal,
        expected_severity: CVSSAssessmentSeverity,
    ) -> None:
        vector = VALID_VECTORS[version]
        result = validate_cvss_vector(vector)

        assert isinstance(result, ParsedCVSSVector)
        assert result.canonical_vector == vector
        assert result.version == version
        assert result.version is CVSSVersion(version)
        assert isinstance(result.score, Decimal)
        assert result.score == expected_score
        assert result.score.as_tuple().exponent == -1
        assert result.severity is expected_severity
        assert type(result.metrics) is METRICS_TYPES[version]

        _, tokens = _split(vector, version)
        official = dict(token.split(":") for token in tokens)
        expected_metrics = {
            field: values[official[abbreviation]]
            for abbreviation, field, values in SPEC_GRAMMAR[version][1]
        }
        assert dataclasses.asdict(result.metrics) == expected_metrics

    @pytest.mark.parametrize(
        ("vector", "expected_score", "expected_metrics"),
        [
            (
                "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                Decimal("10.0"),
                {
                    "access_vector": "network",
                    "access_complexity": "low",
                    "authentication": "none",
                    "confidentiality_impact": "complete",
                    "integrity_impact": "complete",
                    "availability_impact": "complete",
                },
            ),
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                Decimal("9.8"),
                {
                    "attack_vector": "network",
                    "attack_complexity": "low",
                    "privileges_required": "none",
                    "user_interaction": "none",
                    "scope": "unchanged",
                    "confidentiality_impact": "high",
                    "integrity_impact": "high",
                    "availability_impact": "high",
                },
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                Decimal("9.3"),
                {
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
                },
            ),
        ],
    )
    def test_validate_specification_examples_match_documented_shapes(
        self, vector: str, expected_score: Decimal, expected_metrics: dict[str, str]
    ) -> None:
        result = validate_cvss_vector(vector)

        assert result.score == expected_score
        assert dataclasses.asdict(result.metrics) == expected_metrics

    @pytest.mark.parametrize(
        ("version", "abbreviation", "field", "official", "wire"),
        [
            (version, abbreviation, field, official, wire)
            for version, (_, grammar) in SPEC_GRAMMAR.items()
            for abbreviation, field, values in grammar
            for official, wire in values.items()
        ],
    )
    def test_validate_every_official_value_maps_to_documented_wire_value(
        self, version: str, abbreviation: str, field: str, official: str, wire: str
    ) -> None:
        prefix, tokens = _split(VALID_VECTORS[version], version)
        tokens = [
            f"{abbreviation}:{official}" if t.split(":")[0] == abbreviation else t
            for t in tokens
        ]

        result = validate_cvss_vector(_join(prefix, tokens))

        assert getattr(result.metrics, field) == wire

    def test_validate_v2_unprefixed_vector_is_accepted(self) -> None:
        result = validate_cvss_vector("AV:N/AC:L/Au:N/C:N/I:N/A:P")

        assert result.version is CVSSVersion.V2_0
        assert not result.canonical_vector.startswith("CVSS:")

    def test_validate_v30_and_v31_keep_distinct_version_identities(self) -> None:
        body = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        v30 = validate_cvss_vector(f"CVSS:3.0/{body}")
        v31 = validate_cvss_vector(f"CVSS:3.1/{body}")

        assert v30.version is CVSSVersion.V3_0
        assert v31.version is CVSSVersion.V3_1
        assert v30.canonical_vector.startswith("CVSS:3.0/")
        assert v31.canonical_vector.startswith("CVSS:3.1/")

    @pytest.mark.parametrize("version", VERSIONS)
    @pytest.mark.parametrize(
        "padding",
        [(" ", " "), ("\t", ""), ("", "\n"), ("\r\n ", "  \t"), ("\u00a0", "")],
    )
    def test_validate_outer_whitespace_is_trimmed_and_accepted(
        self, version: str, padding: tuple[str, str]
    ) -> None:
        vector = VALID_VECTORS[version]

        result = validate_cvss_vector(f"{padding[0]}{vector}{padding[1]}")

        assert result.canonical_vector == vector

    @pytest.mark.parametrize("version", VERSIONS)
    def test_validate_reversed_metric_order_canonicalizes_to_first_order(
        self, version: str
    ) -> None:
        vector = VALID_VECTORS[version]
        prefix, tokens = _split(vector, version)

        result = validate_cvss_vector(_join(prefix, list(reversed(tokens))))

        assert result.canonical_vector == vector
        assert result == validate_cvss_vector(vector)

    @pytest.mark.parametrize("version", VERSIONS)
    def test_validate_every_rotation_canonicalizes_to_first_order(
        self, version: str
    ) -> None:
        vector = VALID_VECTORS[version]
        prefix, tokens = _split(vector, version)

        for shift in range(1, len(tokens)):
            rotated = tokens[shift:] + tokens[:shift]
            assert validate_cvss_vector(_join(prefix, rotated)).canonical_vector == (
                vector
            )

    def test_validate_v4_interleaved_order_uses_compatibility_extension(self) -> None:
        shuffled = "CVSS:4.0/SA:N/VC:H/AV:A/SI:H/PR:L/AC:H/VA:N/UI:A/SC:L/AT:P/VI:L"

        result = validate_cvss_vector(shuffled)

        assert result.canonical_vector == VALID_VECTORS["4.0"]

    def test_validate_result_is_immutable(self) -> None:
        result = validate_cvss_vector(VALID_VECTORS["3.1"])

        with pytest.raises(dataclasses.FrozenInstanceError):
            result.score = Decimal("0.0")  # type: ignore[misc]
        metrics = result.metrics
        assert isinstance(metrics, CVSS3BaseMetrics)
        with pytest.raises(dataclasses.FrozenInstanceError):
            metrics.scope = CVSS3Scope.CHANGED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Parser: rejected vectors
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestValidateCvssVectorInvalid:
    """Every violation of Input Rules 2-6 raises `InvalidCVSSVectorError`."""

    @pytest.mark.parametrize("vector", ["", " ", "\t\n", "\u00a0 \u2003"])
    def test_validate_empty_after_trim_raises(self, vector: str) -> None:
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    @pytest.mark.parametrize(
        "vector",
        [
            "CVSS:3.1/AV:N /AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/ A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A: H",
            "CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "AV:N/AC:L/Au:N/C:C/I:C/A:C\tAV:N",
            "AV:N/AC:L/Au:N/C:C/I:C/\nA:C",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/\u00a0SA:N",
        ],
    )
    def test_validate_embedded_whitespace_raises(self, vector: str) -> None:
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    @pytest.mark.parametrize(
        "vector",
        [
            # v2.0 must be unprefixed
            "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "CVSS:2/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            # unsupported versions
            "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:5.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            # prefix without separator or body
            "CVSS:3.1",
            "CVSS:3.1/",
            "CVSS:3.1AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            # missing v3/v4 prefix
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            # mismatched prefix and body
            "CVSS:3.1/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:3.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            # repeated or surrounding prefix material
            "CVSS:3.1/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "(AV:N/AC:L/Au:N/C:C/I:C/A:C)",
            "/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ],
    )
    def test_validate_unsupported_missing_or_mismatched_prefix_raises(
        self, vector: str
    ) -> None:
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    @pytest.mark.parametrize(
        "vector",
        [
            # prefix case
            "cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            # abbreviation case
            "CVSS:3.1/av:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/Ac:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/vc:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "AV:N/AC:L/AU:N/C:C/I:C/A:C",
            "AV:N/AC:L/au:N/C:C/I:C/A:C",
            "av:N/ac:L/au:N/c:C/i:C/a:C",
            # value case
            "CVSS:3.1/AV:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:u/C:H/I:H/A:H",
            "CVSS:4.0/AV:N/AC:L/AT:n/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "AV:N/AC:l/Au:N/C:C/I:C/A:C",
        ],
    )
    def test_validate_case_variants_raise(self, vector: str) -> None:
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    @pytest.mark.parametrize(
        "vector",
        [vector for _, vector in _missing_metric_cases()],
        ids=[case_id for case_id, _ in _missing_metric_cases()],
    )
    def test_validate_each_missing_metric_raises(self, vector: str) -> None:
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    @pytest.mark.parametrize(
        "vector",
        [vector for _, vector in _duplicate_metric_cases()],
        ids=[case_id for case_id, _ in _duplicate_metric_cases()],
    )
    def test_validate_each_duplicate_metric_raises(self, vector: str) -> None:
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    @pytest.mark.parametrize(
        ("version", "extra"),
        [
            ("2.0", "XX:N"),
            ("3.1", "XX:N"),
            ("4.0", "XX:N"),
            ("2.0", "PR:N"),
            ("3.1", "Au:N"),
            ("3.1", "AT:N"),
            ("4.0", "S:U"),
            ("4.0", "C:H"),
        ],
    )
    def test_validate_unknown_metric_raises(self, version: str, extra: str) -> None:
        prefix, tokens = _split(VALID_VECTORS[version], version)

        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(_join(prefix, [*tokens, extra]))

    @pytest.mark.parametrize(("version", "extra"), NON_BASE_METRIC_CASES)
    def test_validate_non_base_metric_raises(self, version: str, extra: str) -> None:
        prefix, tokens = _split(VALID_VECTORS[version], version)

        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(_join(prefix, [*tokens, extra]))

    @pytest.mark.parametrize(
        "vector",
        [
            # unknown value for a Base metric
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:P/S:U/C:H/I:H/A:H",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "AV:P/AC:L/Au:N/C:C/I:C/A:C",
            "AV:N/AC:L/Au:N/C:H/I:C/A:C",
            # empty value, missing colon, extra colon
            "CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            # empty tokens
            "CVSS:3.1//AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",
            "AV:N/AC:L/Au:N//C:C/I:C/A:C",
            "/",
            # other separators
            "CVSS:3.1/AV:N,AC:L,PR:N,UI:N,S:U,C:H,I:H,A:H",
        ],
    )
    def test_validate_malformed_metric_tokens_raise(self, vector: str) -> None:
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    def test_validate_error_message_never_contains_input(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/SENTINEL-MARKER:1"

        with pytest.raises(InvalidCVSSVectorError) as excinfo:
            validate_cvss_vector(vector)

        assert "SENTINEL-MARKER" not in str(excinfo.value)
        assert str(excinfo.value) == "Invalid CVSS vector."


@pytest.mark.unit
class TestValidateCvssVectorInterface:
    """Score, version, severity, and metrics never enter the parser as input."""

    def test_validate_accepts_only_the_vector_string(self) -> None:
        parameters = inspect.signature(validate_cvss_vector).parameters

        assert list(parameters) == ["vector_string"]

    @pytest.mark.parametrize("keyword", ["score", "version", "severity", "metrics"])
    def test_validate_rejects_independent_authority_keywords(
        self, keyword: str
    ) -> None:
        with pytest.raises(TypeError):
            validate_cvss_vector(VALID_VECTORS["3.1"], **{keyword: "10.0"})


# ---------------------------------------------------------------------------
# Assessment severity
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAssessmentSeverity:
    """Version-specific assessment severity (legacy v2.0 or FIRST scale)."""

    @pytest.mark.parametrize(
        ("vector", "score", "severity"),
        [
            ("AV:L/AC:H/Au:M/C:N/I:N/A:N", "0.0", "low"),
            ("AV:L/AC:H/Au:M/C:N/I:N/A:P", "0.8", "low"),
            ("AV:L/AC:H/Au:S/C:N/I:N/A:C", "3.8", "low"),
            ("AV:L/AC:H/Au:N/C:N/I:N/A:C", "4.0", "medium"),
            ("AV:L/AC:M/Au:N/C:C/I:C/A:C", "6.9", "medium"),
            ("AV:A/AC:M/Au:M/C:C/I:C/A:C", "7.0", "high"),
            ("AV:N/AC:L/Au:N/C:C/I:C/A:C", "10.0", "high"),
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "0.0", "none"),
            ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", "3.9", "low"),
            ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L", "4.0", "medium"),
            ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:L/A:H", "6.9", "medium"),
            ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H", "7.0", "high"),
            ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:H", "8.9", "high"),
            ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", "9.0", "critical"),
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H", "10.0", "critical"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "0.0", "none"),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L", "1.6", "low"),
            ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", "3.9", "low"),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L", "4.0", "medium"),
            ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:L/A:H", "6.9", "medium"),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H", "7.0", "high"),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:H", "8.9", "high"),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", "9.0", "critical"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H", "10.0", "critical"),
            (
                "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
                "0.0",
                "none",
            ),
            (
                "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:L",
                "1.0",
                "low",
            ),
            (
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:A/VC:N/VI:L/VA:N/SC:L/SI:N/SA:N",
                "2.4",
                "low",
            ),
            (
                "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:H",
                "4.0",
                "medium",
            ),
            (
                "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:H",
                "6.9",
                "medium",
            ),
            (
                "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N",
                "7.0",
                "high",
            ),
            (
                "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
                "8.9",
                "high",
            ),
            (
                "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:H/SA:L",
                "9.0",
                "critical",
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:H/SA:H",
                "10.0",
                "critical",
            ),
        ],
    )
    def test_parsed_score_boundary_maps_to_version_specific_severity(
        self, vector: str, score: str, severity: str
    ) -> None:
        result = validate_cvss_vector(vector)

        assert result.score == Decimal(score)
        assert result.severity == severity

    # Some table boundaries (for example v2.0 3.9 or v4.0 0.1) are not
    # produced by any real Base vector, so the version table is also
    # asserted directly at every documented boundary.
    @pytest.mark.parametrize(
        ("score", "severity"),
        [
            ("0.0", "low"),
            ("0.1", "low"),
            ("3.9", "low"),
            ("4.0", "medium"),
            ("6.9", "medium"),
            ("7.0", "high"),
            ("8.9", "high"),
            ("9.0", "high"),
            ("10.0", "high"),
        ],
    )
    def test_v2_table_boundaries_use_legacy_three_label_mapping(
        self, score: str, severity: str
    ) -> None:
        result = cvss._assessment_severity(CVSSVersion.V2_0, Decimal(score))

        assert result == severity

    @pytest.mark.parametrize("version", ["3.0", "3.1", "4.0"])
    @pytest.mark.parametrize(
        ("score", "severity"),
        [
            ("0.0", "none"),
            ("0.1", "low"),
            ("3.9", "low"),
            ("4.0", "medium"),
            ("6.9", "medium"),
            ("7.0", "high"),
            ("8.9", "high"),
            ("9.0", "critical"),
            ("10.0", "critical"),
        ],
    )
    def test_v3_v4_table_boundaries_use_first_scale(
        self, version: str, score: str, severity: str
    ) -> None:
        result = cvss._assessment_severity(CVSSVersion(version), Decimal(score))

        assert result == severity


# ---------------------------------------------------------------------------
# Unified severity
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCalculateSeverity:
    """`calculate_severity()` implements the unified five-label scale."""

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            ("0.0", Severity.NONE),
            ("0", Severity.NONE),
            ("0.1", Severity.LOW),
            ("3.9", Severity.LOW),
            ("4.0", Severity.MEDIUM),
            ("6.9", Severity.MEDIUM),
            ("7.0", Severity.HIGH),
            ("8.9", Severity.HIGH),
            ("9.0", Severity.CRITICAL),
            ("10.0", Severity.CRITICAL),
        ],
    )
    def test_calculate_severity_boundaries(
        self, score: str, expected: Severity
    ) -> None:
        assert calculate_severity(Decimal(score)) is expected

    @pytest.mark.parametrize(
        "score", ["-0.1", "10.1", "-1", "100", "NaN", "sNaN", "Infinity", "-Infinity"]
    )
    def test_calculate_severity_out_of_domain_raises_value_error(
        self, score: str
    ) -> None:
        with pytest.raises(ValueError, match=r"0\.0 through 10\.0"):
            calculate_severity(Decimal(score))


# ---------------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Assessment:
    """Structural stand-in for a persisted assessment row."""

    provider_name: str
    cvss_version: str
    score: Decimal


def _a(provider: str, version: str, score: str) -> Assessment:
    return Assessment(provider, version, Decimal(score))


# ---------------------------------------------------------------------------
# Severity Resolution Cascade
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResolveSeverityScore:
    """Deterministic Severity Resolution Cascade."""

    def test_resolve_severity_no_assessments_returns_none(self) -> None:
        assert resolve_severity_score([], "3.1") is None
        assert resolve_severity_score(iter(()), "4.0") is None

    def test_resolve_severity_step1_suse_default_beats_all_others(self) -> None:
        assessments = [
            _a("SUSE", "3.1", "5.0"),
            _a("SUSE", "4.0", "9.9"),
            _a("NVD", "3.1", "9.8"),
            _a("NVD", "4.0", "10.0"),
        ]

        result = resolve_severity_score(assessments, "3.1")

        assert result == SeverityResolution(
            score=Decimal("5.0"),
            version=CVSSVersion.V3_1,
            provider="SUSE",
            label=Severity.MEDIUM,
        )

    def test_resolve_severity_step2_suse_other_version_beats_non_suse_default(
        self,
    ) -> None:
        assessments = [
            _a("SUSE", "2.0", "3.0"),
            _a("NVD", "3.1", "9.8"),
            _a("Red Hat", "4.0", "10.0"),
        ]

        result = resolve_severity_score(assessments, "3.1")

        assert result is not None
        assert (result.provider, result.version, result.score) == (
            "SUSE",
            "2.0",
            Decimal("3.0"),
        )

    def test_resolve_severity_step2_uses_version_priority_before_score(self) -> None:
        assessments = [
            _a("SUSE", "2.0", "10.0"),
            _a("SUSE", "3.0", "9.9"),
            _a("SUSE", "3.1", "1.0"),
        ]

        result = resolve_severity_score(assessments, "4.0")

        assert result is not None
        assert result.version is CVSSVersion.V3_1
        assert result.score == Decimal("1.0")
        assert result.label is Severity.LOW

    def test_resolve_severity_step3_non_suse_default_beats_other_versions(
        self,
    ) -> None:
        assessments = [
            _a("NVD", "3.1", "2.0"),
            _a("NVD", "4.0", "10.0"),
            _a("Red Hat", "3.0", "9.0"),
        ]

        result = resolve_severity_score(assessments, "3.1")

        assert result is not None
        assert (result.provider, result.version) == ("NVD", "3.1")

    def test_resolve_severity_step4_version_priority_4_31_30_20(self) -> None:
        candidates = [
            _a("NVD", "4.0", "1.0"),
            _a("Red Hat", "3.1", "2.0"),
            _a("Intel Corporation", "3.0", "3.0"),
            _a("Example CNA", "2.0", "4.0"),
        ]

        # Default 3.1 has no candidate at 3.1 once that one is removed.
        expected_order = ["4.0", "3.0", "2.0"]
        remaining = [c for c in candidates if c.cvss_version != "3.1"]
        for expected in expected_order:
            result = resolve_severity_score(remaining, "3.1")
            assert result is not None
            assert result.version == expected
            remaining = [c for c in remaining if c.cvss_version != expected]

        # Default 4.0 has no candidate at 4.0 once that one is removed.
        expected_order = ["3.1", "3.0", "2.0"]
        remaining = [c for c in candidates if c.cvss_version != "4.0"]
        for expected in expected_order:
            result = resolve_severity_score(remaining, "4.0")
            assert result is not None
            assert result.version == expected
            remaining = [c for c in remaining if c.cvss_version != expected]

    @pytest.mark.parametrize(
        ("default", "expected_version"), [("3.1", "3.1"), ("4.0", "4.0")]
    )
    def test_resolve_severity_prefers_configured_default_version(
        self, default: str, expected_version: str
    ) -> None:
        assessments = [_a("SUSE", "3.1", "4.2"), _a("SUSE", "4.0", "8.1")]

        result = resolve_severity_score(assessments, default)

        assert result is not None
        assert result.version == expected_version

    def test_resolve_severity_higher_score_wins_within_step_and_version(self) -> None:
        assessments = [
            _a("Alpha CNA", "3.1", "6.1"),
            _a("Beta CNA", "3.1", "7.5"),
            _a("Gamma CNA", "3.1", "7.4"),
        ]

        result = resolve_severity_score(assessments, "3.1")

        assert result is not None
        assert result.provider == "Beta CNA"
        assert result.label is Severity.HIGH

    def test_resolve_severity_equal_score_ties_break_by_provider_ascending(
        self,
    ) -> None:
        assessments = [_a("Red Hat", "3.1", "7.5"), _a("NVD", "3.1", "7.5")]

        result = resolve_severity_score(assessments, "3.1")

        assert result is not None
        assert result.provider == "NVD"

    @pytest.mark.parametrize(
        ("providers", "expected"),
        [
            # Code point: "Z" (U+005A) < "a" (U+0061); a case-insensitive
            # collation would sort "alpha" first.
            (["alpha", "Zeta"], "Zeta"),
            # Code point: "Z" (U+005A) < "Ö" (U+00D6); a typical linguistic
            # collation sorts "Ölander" with "O", before "Zeta".
            (["Ölander", "Zeta"], "Zeta"),
            # Code point: "é" (U+00E9) > "f" (U+0066); a typical collation
            # sorts "école" before "foo".
            (["école", "foo"], "foo"),
        ],
    )
    def test_resolve_severity_tie_break_uses_unicode_code_points_not_collation(
        self, providers: list[str], expected: str
    ) -> None:
        assessments = [_a(name, "4.0", "8.8") for name in providers]

        for ordering in (assessments, list(reversed(assessments))):
            result = resolve_severity_score(ordering, "4.0")
            assert result is not None
            assert result.provider == expected

    def test_resolve_severity_shuffled_input_produces_identical_result(self) -> None:
        assessments = [
            _a("SUSE", "2.0", "5.0"),
            _a("SUSE", "3.0", "5.0"),
            _a("NVD", "4.0", "9.1"),
            _a("Zeta", "3.1", "7.5"),
            _a("alpha", "3.1", "7.5"),
        ]
        expected = resolve_severity_score(assessments, "4.0")

        results = {
            resolve_severity_score(list(permutation), "4.0")
            for permutation in itertools.permutations(assessments)
        }

        assert results == {expected}
        assert expected is not None
        assert (expected.provider, expected.version) == ("SUSE", "3.0")

    @pytest.mark.parametrize(
        ("score", "assessment_severity", "unified"),
        [
            ("0.0", "low", Severity.NONE),
            ("3.9", "low", Severity.LOW),
            ("6.9", "medium", Severity.MEDIUM),
            ("8.9", "high", Severity.HIGH),
            ("9.3", "high", Severity.CRITICAL),
        ],
    )
    def test_resolve_severity_v2_winner_maps_to_unified_scale(
        self, score: str, assessment_severity: str, unified: Severity
    ) -> None:
        assert cvss._assessment_severity(CVSSVersion.V2_0, Decimal(score)) == (
            assessment_severity
        )

        result = resolve_severity_score([_a("SUSE", "2.0", score)], "3.1")

        assert result is not None
        assert result.version is CVSSVersion.V2_0
        assert result.label is unified

    @pytest.mark.parametrize(
        ("score", "label"),
        [
            ("0.0", Severity.NONE),
            ("0.1", Severity.LOW),
            ("3.9", Severity.LOW),
            ("4.0", Severity.MEDIUM),
            ("6.9", Severity.MEDIUM),
            ("7.0", Severity.HIGH),
            ("8.9", Severity.HIGH),
            ("9.0", Severity.CRITICAL),
            ("10.0", Severity.CRITICAL),
        ],
    )
    def test_resolve_severity_winner_label_uses_unified_boundaries(
        self, score: str, label: Severity
    ) -> None:
        result = resolve_severity_score([_a("NVD", "4.0", score)], "4.0")

        assert result is not None
        assert result.label is label
        assert result.score == Decimal(score)

    @pytest.mark.parametrize("variant", ["suse", " SUSE", "SUSE ", "Suse"])
    def test_resolve_severity_non_canonical_suse_variant_is_not_suse(
        self, variant: str
    ) -> None:
        assessments = [_a(variant, "3.1", "9.9"), _a("SUSE", "2.0", "1.0")]

        result = resolve_severity_score(assessments, "3.1")

        assert result is not None
        assert result.provider == "SUSE"
        assert result.version is CVSSVersion.V2_0

    def test_resolve_severity_result_is_immutable(self) -> None:
        result = resolve_severity_score([_a("NVD", "3.1", "5.0")], "3.1")

        assert result is not None
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.provider = "SUSE"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Eligibility Score Resolution
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResolveEligibilityScore:
    """Eligibility uses only canonical SUSE at the default version."""

    @pytest.mark.parametrize(("default", "score"), [("3.1", "7.5"), ("4.0", "0.0")])
    def test_resolve_eligibility_suse_default_returns_suse_score(
        self, default: str, score: str
    ) -> None:
        assessments = [
            _a("SUSE", default, score),
            _a("SUSE", "2.0", "9.9"),
            _a("NVD", default, "10.0"),
        ]

        result = resolve_eligibility_score(assessments, default)

        assert result == EligibilityResolution(
            score=Decimal(score), source=EligibilitySource.SUSE
        )

    def test_resolve_eligibility_no_assessments_returns_fallback(self) -> None:
        result = resolve_eligibility_score([], "3.1")

        assert result.source is EligibilitySource.FALLBACK
        assert result.score == Decimal("10.0")
        assert str(result.score) == "10.0"

    @pytest.mark.parametrize(
        ("default", "assessments"),
        [
            # Another SUSE version does not participate.
            ("4.0", [_a("SUSE", "3.1", "9.8")]),
            ("3.1", [_a("SUSE", "4.0", "1.0"), _a("SUSE", "3.0", "2.0")]),
            ("4.0", [_a("SUSE", "2.0", "0.0"), _a("SUSE", "3.0", "0.0")]),
            # External providers never participate, even at the default.
            ("3.1", [_a("NVD", "3.1", "9.9")]),
            ("4.0", [_a("NVD", "4.0", "0.5"), _a("Red Hat", "4.0", "1.0")]),
            # Non-canonical reserved variants are not canonical SUSE.
            ("3.1", [_a("suse", "3.1", "2.0"), _a(" SUSE ", "4.0", "2.0")]),
        ],
    )
    def test_resolve_eligibility_without_suse_default_returns_fallback(
        self, default: str, assessments: list[Assessment]
    ) -> None:
        result = resolve_eligibility_score(assessments, default)

        assert result == EligibilityResolution(
            score=Decimal("10.0"), source=EligibilitySource.FALLBACK
        )

    def test_resolve_eligibility_ignores_higher_external_and_other_suse(
        self,
    ) -> None:
        assessments = [
            _a("NVD", "4.0", "9.9"),
            _a("SUSE", "3.1", "9.8"),
            _a("SUSE", "4.0", "5.0"),
        ]

        result = resolve_eligibility_score(assessments, "4.0")

        assert result.score == Decimal("5.0")
        assert result.source is EligibilitySource.SUSE

    def test_resolve_eligibility_is_independent_of_severity_winner(self) -> None:
        assessments = [_a("SUSE", "3.1", "9.8"), _a("NVD", "4.0", "3.0")]

        severity = resolve_severity_score(assessments, "4.0")
        eligibility = resolve_eligibility_score(assessments, "4.0")

        assert severity is not None
        assert (severity.provider, severity.score) == ("SUSE", Decimal("9.8"))
        assert eligibility.source is EligibilitySource.FALLBACK
        assert eligibility.score == Decimal("10.0")

    def test_resolve_eligibility_shuffled_input_produces_identical_result(
        self,
    ) -> None:
        assessments = [
            _a("NVD", "3.1", "9.1"),
            _a("SUSE", "3.1", "6.4"),
            _a("SUSE", "4.0", "7.7"),
        ]

        results = {
            resolve_eligibility_score(list(permutation), "3.1")
            for permutation in itertools.permutations(assessments)
        }

        assert results == {
            EligibilityResolution(score=Decimal("6.4"), source=EligibilitySource.SUSE)
        }


# ---------------------------------------------------------------------------
# Out-of-domain inputs (internal contract violations)
# ---------------------------------------------------------------------------

RESOLVERS = [resolve_severity_score, resolve_eligibility_score]


@pytest.mark.unit
class TestResolutionContractViolations:
    """Out-of-domain resolution inputs raise `ValueError`."""

    @pytest.mark.parametrize("resolver", RESOLVERS)
    @pytest.mark.parametrize(
        "default", ["2.0", "3.0", "3.2", "5.0", "", " 3.1", "3.10", "4", "V3_1"]
    )
    def test_resolve_invalid_default_version_raises_value_error(
        self, resolver: Callable[..., object], default: str
    ) -> None:
        with pytest.raises(ValueError, match="Default CVSS version"):
            resolver([_a("SUSE", "3.1", "5.0")], default)

    @pytest.mark.parametrize("resolver", RESOLVERS)
    def test_resolve_invalid_default_version_raises_even_for_empty_set(
        self, resolver: Callable[..., object]
    ) -> None:
        with pytest.raises(ValueError, match="Default CVSS version"):
            resolver([], "3.0")

    @pytest.mark.parametrize("resolver", RESOLVERS)
    @pytest.mark.parametrize("version", ["1.0", "3.2", "4", "", "v3.1", " 3.1"])
    def test_resolve_unsupported_assessment_version_raises_value_error(
        self, resolver: Callable[..., object], version: str
    ) -> None:
        with pytest.raises(ValueError, match="Unsupported CVSS assessment version"):
            resolver([_a("NVD", "3.1", "5.0"), _a("NVD", version, "5.0")], "3.1")

    @pytest.mark.parametrize("resolver", RESOLVERS)
    @pytest.mark.parametrize(
        "duplicate",
        [
            (_a("NVD", "3.1", "5.0"), _a("NVD", "3.1", "5.0")),
            (_a("NVD", "3.1", "5.0"), _a("NVD", "3.1", "9.0")),
            (_a("SUSE", "4.0", "5.0"), _a("SUSE", "4.0", "6.0")),
        ],
    )
    def test_resolve_duplicate_natural_key_raises_value_error(
        self, resolver: Callable[..., object], duplicate: tuple[Assessment, Assessment]
    ) -> None:
        with pytest.raises(ValueError, match="Duplicate"):
            resolver([duplicate[0], _a("Red Hat", "3.1", "1.0"), duplicate[1]], "4.0")

    def test_resolve_same_provider_different_versions_is_not_duplicate(self) -> None:
        assessments = [_a("NVD", "3.1", "5.0"), _a("NVD", "4.0", "6.0")]

        assert resolve_severity_score(assessments, "3.1") is not None
        assert resolve_eligibility_score(assessments, "3.1").source is (
            EligibilitySource.FALLBACK
        )

    @pytest.mark.parametrize("score", ["10.1", "-0.1"])
    def test_resolve_severity_winner_score_out_of_range_raises_value_error(
        self, score: str
    ) -> None:
        with pytest.raises(ValueError, match=r"0\.0 through 10\.0"):
            resolve_severity_score([_a("NVD", "3.1", score)], "3.1")


# ---------------------------------------------------------------------------
# Reserved provider comparison
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIsReservedProviderName:
    """Trimmed, Unicode case-folded comparison with `suse`."""

    @pytest.mark.parametrize(
        "name",
        [
            "SUSE",
            "suse",
            "Suse",
            "sUsE",
            " SUSE",
            "SUSE ",
            "\tsuse\n",
            "\u00a0SuSe\u2003",
            # U+017F LATIN SMALL LETTER LONG S case-folds to "s".
            "\u017fuse",
        ],
    )
    def test_reserved_variants_match(self, name: str) -> None:
        assert is_reserved_provider_name(name) is True

    @pytest.mark.parametrize(
        "name",
        ["NVD", "Red Hat", "", "   ", "SUSE Linux", "S USE", "SUS E", "SUSE.", "SUSEX"],
    )
    def test_non_reserved_names_do_not_match(self, name: str) -> None:
        assert is_reserved_provider_name(name) is False


# ---------------------------------------------------------------------------
# Exceptions and module boundaries
# ---------------------------------------------------------------------------


def _imported_modules(path: Path) -> set[str]:
    """Absolute module names imported by a module under `app/services/`.

    Relative imports are resolved against the `app.services` package so a
    `from ..models import X` cannot bypass the boundary assertions.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    package_parts = ["app", "services"]
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:
                parent = package_parts[: len(package_parts) - (node.level - 1)]
                base = ".".join([*parent, node.module] if node.module else parent)
            if node.module:
                modules.add(base)
            else:
                modules.update(f"{base}.{alias.name}" for alias in node.names)
    return modules


@pytest.mark.unit
class TestExceptionsAndBoundaries:
    """Exception hierarchy, leaf placement, and purity of the new modules."""

    def test_invalid_vector_error_hierarchy(self) -> None:
        error = InvalidCVSSVectorError()

        assert isinstance(error, TicketMutationsError)
        assert isinstance(error, ServiceError)
        assert issubclass(TicketMutationsError, ServiceError)
        assert not issubclass(TicketMutationsError, ValueError)

    def test_errors_module_is_a_leaf_importing_no_service(self) -> None:
        modules = _imported_modules(
            APP_ROOT / "services" / "ticket_mutations_errors.py"
        )

        app_modules = {m for m in modules if m.startswith("app.")}
        assert app_modules == {"app.core.exceptions"}

    @pytest.mark.parametrize("module", ["cvss.py", "ticket_mutations_errors.py"])
    def test_pure_modules_import_no_model_settings_or_io(self, module: str) -> None:
        modules = _imported_modules(APP_ROOT / "services" / module)
        forbidden_prefixes = (
            "app.models",
            "app.config",
            "app.database",
            "app.api",
            "app.schemas",
            "app.tasks",
            "app.cli",
            "sqlalchemy",
            "redis",
            "httpx",
            "celery",
            "logging",
            "os",
            "pathlib",
            "socket",
        )

        offending = {
            m
            for m in modules
            if any(m == p or m.startswith(f"{p}.") for p in forbidden_prefixes)
        }
        assert offending == set()

    def test_import_collector_resolves_relative_imports(self, tmp_path: Path) -> None:
        source = tmp_path / "probe.py"
        source.write_text(
            "from ..models import cve\nfrom . import cvss\nfrom .x import y\n",
            encoding="utf-8",
        )

        assert _imported_modules(source) == {
            "app.models",
            "app.services.cvss",
            "app.services.x",
        }

    def test_cvss_imports_only_core_and_errors_leaf_from_app(self) -> None:
        modules = _imported_modules(APP_ROOT / "services" / "cvss.py")

        app_modules = {m for m in modules if m.startswith("app.")}
        assert app_modules == {
            "app.core.enums",
            "app.services.ticket_mutations_errors",
        }
