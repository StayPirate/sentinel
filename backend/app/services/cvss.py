"""Pure CVSS vector parsing and score resolution.

Single database-free formula owner for CVSS semantics. See
`docs/features/tickets/cvss-scoring.md` for the complete contract:
Accepted Base Vectors (Input Rules, Stable Parsed Result, per-version
Base metrics), Severity (Version-Specific Assessment Severity, Unified CVE
Severity, Severity Resolution Cascade), Eligibility Score Resolution,
Provider Identity and Authority (reserved-name comparison), and Service
Boundaries (Pure CVSS Logic).

Every function is deterministic and side-effect-free: no database access,
no I/O, and no settings reads — callers pass the configured default CVSS
version explicitly. Resolution inputs are typed structurally
(`CVSSAssessmentLike`) so persisted assessment rows satisfy them without
this module importing any Model.

Exceptions:

- `InvalidCVSSVectorError` — `validate_cvss_vector()` rejects a vector
  that violates Input Rules 2-6 (domain failure, `422 CVSS_INVALID_VECTOR`).
- `ValueError` — internal contract violations by a caller: a default
  version other than `3.1`/`4.0`, an unsupported assessment version,
  duplicate `(provider_name, cvss_version)` natural keys, or a
  `calculate_severity()` score outside 0.0-10.0.

The received-length limit (Input Rule 1) is owned by the Pydantic request
schema and is deliberately not enforced here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Protocol

from cvss import CVSS2, CVSS3, CVSS4

from app.core.enums import (
    CVSS2AccessComplexity,
    CVSS2AccessVector,
    CVSS2Authentication,
    CVSS2Impact,
    CVSS3Scope,
    CVSS3UserInteraction,
    CVSS4AttackRequirements,
    CVSS4UserInteraction,
    CVSSAssessmentSeverity,
    CVSSAttackComplexity,
    CVSSAttackVector,
    CVSSImpact,
    CVSSPrivilegesRequired,
    CVSSVersion,
    EligibilitySource,
    Severity,
)
from app.services.ticket_mutations_errors import InvalidCVSSVectorError

SUSE_PROVIDER_NAME = "SUSE"
"""The only stored form of the reserved internal provider identity."""

DEFAULT_CVSS_VERSIONS: frozenset[CVSSVersion] = frozenset(
    {CVSSVersion.V3_1, CVSSVersion.V4_0}
)
"""Values accepted for the configured `default_cvss_version`."""

ELIGIBILITY_FALLBACK_SCORE = Decimal("10.0")
"""Conservative eligibility score used when no SUSE default-version score exists."""

_MIN_SCORE = Decimal("0.0")
_MAX_SCORE = Decimal("10.0")
_SCORE_QUANTUM = Decimal("0.1")

# Applicable version priority for the Severity Resolution Cascade,
# highest first: 4.0 > 3.1 > 3.0 > 2.0.
_VERSION_PRIORITY: Mapping[CVSSVersion, int] = {
    CVSSVersion.V4_0: 4,
    CVSSVersion.V3_1: 3,
    CVSSVersion.V3_0: 2,
    CVSSVersion.V2_0: 1,
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CVSS2BaseMetrics:
    """Expanded CVSS v2.0 Base metrics in API wire values."""

    access_vector: CVSS2AccessVector
    access_complexity: CVSS2AccessComplexity
    authentication: CVSS2Authentication
    confidentiality_impact: CVSS2Impact
    integrity_impact: CVSS2Impact
    availability_impact: CVSS2Impact


@dataclass(frozen=True, slots=True)
class CVSS3BaseMetrics:
    """Expanded CVSS v3.0 / v3.1 Base metrics in API wire values."""

    attack_vector: CVSSAttackVector
    attack_complexity: CVSSAttackComplexity
    privileges_required: CVSSPrivilegesRequired
    user_interaction: CVSS3UserInteraction
    scope: CVSS3Scope
    confidentiality_impact: CVSSImpact
    integrity_impact: CVSSImpact
    availability_impact: CVSSImpact


@dataclass(frozen=True, slots=True)
class CVSS4BaseMetrics:
    """Expanded CVSS v4.0 Base metrics in API wire values."""

    attack_vector: CVSSAttackVector
    attack_complexity: CVSSAttackComplexity
    attack_requirements: CVSS4AttackRequirements
    privileges_required: CVSSPrivilegesRequired
    user_interaction: CVSS4UserInteraction
    vulnerable_system_confidentiality: CVSSImpact
    vulnerable_system_integrity: CVSSImpact
    vulnerable_system_availability: CVSSImpact
    subsequent_system_confidentiality: CVSSImpact
    subsequent_system_integrity: CVSSImpact
    subsequent_system_availability: CVSSImpact


CVSSBaseMetrics = CVSS2BaseMetrics | CVSS3BaseMetrics | CVSS4BaseMetrics
"""Version-discriminated expanded metrics: v2.0, v3.x, or v4.0 shape."""


@dataclass(frozen=True, slots=True)
class ParsedCVSSVector:
    """Stable parsed result of one accepted CVSS Base vector.

    `metrics` has the shape determined by `version`: `CVSS2BaseMetrics`
    for 2.0, `CVSS3BaseMetrics` for 3.0 and 3.1, `CVSS4BaseMetrics` for
    4.0.
    """

    canonical_vector: str
    version: CVSSVersion
    score: Decimal
    severity: CVSSAssessmentSeverity
    metrics: CVSSBaseMetrics


@dataclass(frozen=True, slots=True)
class SeverityResolution:
    """Winning assessment of the Severity Resolution Cascade."""

    score: Decimal
    version: CVSSVersion
    provider: str
    label: Severity


@dataclass(frozen=True, slots=True)
class EligibilityResolution:
    """Result of the Eligibility Score Resolution."""

    score: Decimal
    source: EligibilitySource


class CVSSAssessmentLike(Protocol):
    """Structural input for the pure resolutions.

    Satisfied by persisted assessment rows and by any object exposing the
    canonical persisted provider name, the exact version string, and the
    Base score.
    """

    @property
    def provider_name(self) -> str: ...

    @property
    def cvss_version(self) -> str: ...

    @property
    def score(self) -> Decimal: ...


# ---------------------------------------------------------------------------
# Accepted Base-vector grammar (Sentinel-owned)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _MetricSpec:
    abbreviation: str
    field: str
    values: Mapping[str, StrEnum]


@dataclass(frozen=True, slots=True)
class _VersionSpec:
    prefix: str
    metrics: tuple[_MetricSpec, ...]
    metrics_type: Callable[..., CVSSBaseMetrics]
    score: Callable[[str], float]

    def metric(self, abbreviation: str) -> _MetricSpec | None:
        for spec in self.metrics:
            if spec.abbreviation == abbreviation:
                return spec
        return None


_V2_IMPACT = {
    "N": CVSS2Impact.NONE,
    "P": CVSS2Impact.PARTIAL,
    "C": CVSS2Impact.COMPLETE,
}
_V34_ATTACK_VECTOR = {
    "N": CVSSAttackVector.NETWORK,
    "A": CVSSAttackVector.ADJACENT,
    "L": CVSSAttackVector.LOCAL,
    "P": CVSSAttackVector.PHYSICAL,
}
_V34_ATTACK_COMPLEXITY = {"L": CVSSAttackComplexity.LOW, "H": CVSSAttackComplexity.HIGH}
_V34_PRIVILEGES_REQUIRED = {
    "N": CVSSPrivilegesRequired.NONE,
    "L": CVSSPrivilegesRequired.LOW,
    "H": CVSSPrivilegesRequired.HIGH,
}
_V34_IMPACT = {"N": CVSSImpact.NONE, "L": CVSSImpact.LOW, "H": CVSSImpact.HIGH}


def _score_v2(vector: str) -> float:
    score: float = CVSS2(vector).scores()[0]
    return score


def _score_v3(vector: str) -> float:
    score: float = CVSS3(vector).scores()[0]
    return score


def _score_v4(vector: str) -> float:
    score: float = CVSS4(vector).base_score
    return score


_V2_SPEC = _VersionSpec(
    prefix="",
    metrics=(
        _MetricSpec(
            "AV",
            "access_vector",
            {
                "L": CVSS2AccessVector.LOCAL,
                "A": CVSS2AccessVector.ADJACENT_NETWORK,
                "N": CVSS2AccessVector.NETWORK,
            },
        ),
        _MetricSpec(
            "AC",
            "access_complexity",
            {
                "H": CVSS2AccessComplexity.HIGH,
                "M": CVSS2AccessComplexity.MEDIUM,
                "L": CVSS2AccessComplexity.LOW,
            },
        ),
        _MetricSpec(
            "Au",
            "authentication",
            {
                "M": CVSS2Authentication.MULTIPLE,
                "S": CVSS2Authentication.SINGLE,
                "N": CVSS2Authentication.NONE,
            },
        ),
        _MetricSpec("C", "confidentiality_impact", _V2_IMPACT),
        _MetricSpec("I", "integrity_impact", _V2_IMPACT),
        _MetricSpec("A", "availability_impact", _V2_IMPACT),
    ),
    metrics_type=CVSS2BaseMetrics,
    score=_score_v2,
)

_V3_METRICS = (
    _MetricSpec("AV", "attack_vector", _V34_ATTACK_VECTOR),
    _MetricSpec("AC", "attack_complexity", _V34_ATTACK_COMPLEXITY),
    _MetricSpec("PR", "privileges_required", _V34_PRIVILEGES_REQUIRED),
    _MetricSpec(
        "UI",
        "user_interaction",
        {"N": CVSS3UserInteraction.NONE, "R": CVSS3UserInteraction.REQUIRED},
    ),
    _MetricSpec(
        "S",
        "scope",
        {"U": CVSS3Scope.UNCHANGED, "C": CVSS3Scope.CHANGED},
    ),
    _MetricSpec("C", "confidentiality_impact", _V34_IMPACT),
    _MetricSpec("I", "integrity_impact", _V34_IMPACT),
    _MetricSpec("A", "availability_impact", _V34_IMPACT),
)

_V4_SPEC = _VersionSpec(
    prefix="CVSS:4.0/",
    metrics=(
        _MetricSpec("AV", "attack_vector", _V34_ATTACK_VECTOR),
        _MetricSpec("AC", "attack_complexity", _V34_ATTACK_COMPLEXITY),
        _MetricSpec(
            "AT",
            "attack_requirements",
            {
                "N": CVSS4AttackRequirements.NONE,
                "P": CVSS4AttackRequirements.PRESENT,
            },
        ),
        _MetricSpec("PR", "privileges_required", _V34_PRIVILEGES_REQUIRED),
        _MetricSpec(
            "UI",
            "user_interaction",
            {
                "N": CVSS4UserInteraction.NONE,
                "P": CVSS4UserInteraction.PASSIVE,
                "A": CVSS4UserInteraction.ACTIVE,
            },
        ),
        _MetricSpec("VC", "vulnerable_system_confidentiality", _V34_IMPACT),
        _MetricSpec("VI", "vulnerable_system_integrity", _V34_IMPACT),
        _MetricSpec("VA", "vulnerable_system_availability", _V34_IMPACT),
        _MetricSpec("SC", "subsequent_system_confidentiality", _V34_IMPACT),
        _MetricSpec("SI", "subsequent_system_integrity", _V34_IMPACT),
        _MetricSpec("SA", "subsequent_system_availability", _V34_IMPACT),
    ),
    metrics_type=CVSS4BaseMetrics,
    score=_score_v4,
)

_VERSION_SPECS: Mapping[CVSSVersion, _VersionSpec] = {
    CVSSVersion.V2_0: _V2_SPEC,
    CVSSVersion.V3_0: _VersionSpec(
        prefix="CVSS:3.0/",
        metrics=_V3_METRICS,
        metrics_type=CVSS3BaseMetrics,
        score=_score_v3,
    ),
    CVSSVersion.V3_1: _VersionSpec(
        prefix="CVSS:3.1/",
        metrics=_V3_METRICS,
        metrics_type=CVSS3BaseMetrics,
        score=_score_v3,
    ),
    CVSSVersion.V4_0: _V4_SPEC,
}

# Exact prefix (without the trailing "/") -> version, for prefixed versions.
_PREFIXED_VERSIONS: Mapping[str, CVSSVersion] = {
    spec.prefix.removesuffix("/"): version
    for version, spec in _VERSION_SPECS.items()
    if spec.prefix
}
_PREFIX_MARKER = "CVSS:"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _detect_version(candidate: str) -> tuple[CVSSVersion, str]:
    """Return the version and the metrics body of a trimmed vector.

    A candidate starting with `CVSS:` must carry one exact accepted
    prefix; any other candidate is parsed as unprefixed CVSS v2.0 (so a
    missing v3/v4 prefix fails later on unknown metrics).
    """
    if not candidate.startswith(_PREFIX_MARKER):
        return CVSSVersion.V2_0, candidate
    prefix, separator, body = candidate.partition("/")
    version = _PREFIXED_VERSIONS.get(prefix)
    if version is None or not separator:
        raise InvalidCVSSVectorError
    return version, body


def _parse_metrics(spec: _VersionSpec, body: str) -> dict[str, str]:
    """Map each Base-metric abbreviation to its official value.

    Enforces Rules 3, 5, and 6: official case, any input order, and every
    Base metric exactly once with no missing, duplicate, unknown, or
    non-Base metric.
    """
    official_values: dict[str, str] = {}
    for token in body.split("/"):
        abbreviation, separator, value = token.partition(":")
        metric = spec.metric(abbreviation)
        if (
            not separator
            or metric is None
            or abbreviation in official_values
            or value not in metric.values
        ):
            raise InvalidCVSSVectorError
        official_values[abbreviation] = value
    if len(official_values) != len(spec.metrics):
        raise InvalidCVSSVectorError
    return official_values


def _assessment_severity(
    version: CVSSVersion, score: Decimal
) -> CVSSAssessmentSeverity:
    """Version-specific assessment severity (legacy v2.0 or FIRST scale)."""
    if version is CVSSVersion.V2_0:
        if score < Decimal("4.0"):
            return CVSSAssessmentSeverity.LOW
        if score < Decimal("7.0"):
            return CVSSAssessmentSeverity.MEDIUM
        return CVSSAssessmentSeverity.HIGH
    if score == _MIN_SCORE:
        return CVSSAssessmentSeverity.NONE
    if score < Decimal("4.0"):
        return CVSSAssessmentSeverity.LOW
    if score < Decimal("7.0"):
        return CVSSAssessmentSeverity.MEDIUM
    if score < Decimal("9.0"):
        return CVSSAssessmentSeverity.HIGH
    return CVSSAssessmentSeverity.CRITICAL


def validate_cvss_vector(vector_string: str) -> ParsedCVSSVector:
    """Parse one received CVSS Base vector into its stable parsed result.

    Applies Input Rules 2-7 of `cvss-scoring.md` in order: trims outer
    whitespace only; rejects empty input and embedded whitespace; requires
    the official case and exact version prefix (none for v2.0,
    `CVSS:3.0/`, `CVSS:3.1/`, `CVSS:4.0/`); accepts Base metrics in any
    order but requires each exactly once and rejects missing, duplicate,
    unknown, and non-Base metrics. Only the canonical vector (FIRST Base
    metric order) is handed to the `cvss` library, which computes the Base
    score. Score, version, severity, and metrics are always derived from
    the vector and never accepted as input.

    Raises:
        InvalidCVSSVectorError: The vector violates the accepted
            Base-vector contract.
    """
    candidate = vector_string.strip()
    if not candidate or any(character.isspace() for character in candidate):
        raise InvalidCVSSVectorError
    version, body = _detect_version(candidate)
    spec = _VERSION_SPECS[version]
    official_values = _parse_metrics(spec, body)

    canonical_vector = spec.prefix + "/".join(
        f"{metric.abbreviation}:{official_values[metric.abbreviation]}"
        for metric in spec.metrics
    )
    metrics = spec.metrics_type(
        **{
            metric.field: metric.values[official_values[metric.abbreviation]]
            for metric in spec.metrics
        }
    )
    score = Decimal(str(spec.score(canonical_vector))).quantize(_SCORE_QUANTUM)
    return ParsedCVSSVector(
        canonical_vector=canonical_vector,
        version=version,
        score=score,
        severity=_assessment_severity(version, score),
        metrics=metrics,
    )


# ---------------------------------------------------------------------------
# Severity and eligibility resolution
# ---------------------------------------------------------------------------


def calculate_severity(score: Decimal) -> Severity:
    """Map a Base score to the unified severity scale.

    `0.0` → `None`, `0.1-3.9` → `Low`, `4.0-6.9` → `Medium`,
    `7.0-8.9` → `High`, `9.0-10.0` → `Critical`, regardless of the CVSS
    version the score came from.

    Raises:
        ValueError: `score` is not a finite value from 0.0 through 10.0.
    """
    if not score.is_finite() or not _MIN_SCORE <= score <= _MAX_SCORE:
        raise ValueError("CVSS score must be a finite value from 0.0 through 10.0.")
    if score == _MIN_SCORE:
        return Severity.NONE
    if score < Decimal("4.0"):
        return Severity.LOW
    if score < Decimal("7.0"):
        return Severity.MEDIUM
    if score < Decimal("9.0"):
        return Severity.HIGH
    return Severity.CRITICAL


def is_reserved_provider_name(provider_name: str) -> bool:
    """Whether a supplied provider name is equivalent to the reserved `SUSE`.

    The comparison trims outer whitespace and applies Unicode
    case-folding, so every case or surrounding-whitespace variant of
    `SUSE` is reserved.
    """
    return provider_name.strip().casefold() == SUSE_PROVIDER_NAME.casefold()


def _validated_default_version(default_cvss_version: str) -> CVSSVersion:
    if default_cvss_version not in DEFAULT_CVSS_VERSIONS:
        raise ValueError("Default CVSS version must be 3.1 or 4.0.")
    return CVSSVersion(default_cvss_version)


def _validated_assessments(
    assessments: Iterable[CVSSAssessmentLike],
) -> list[tuple[CVSSAssessmentLike, CVSSVersion]]:
    """Pair each assessment with its accepted version; reject duplicates."""
    validated: list[tuple[CVSSAssessmentLike, CVSSVersion]] = []
    natural_keys: set[tuple[str, CVSSVersion]] = set()
    for assessment in assessments:
        if assessment.cvss_version not in _VERSION_PRIORITY:
            raise ValueError("Unsupported CVSS assessment version.")
        version = CVSSVersion(assessment.cvss_version)
        natural_key = (assessment.provider_name, version)
        if natural_key in natural_keys:
            raise ValueError("Duplicate (provider_name, cvss_version) assessment.")
        natural_keys.add(natural_key)
        validated.append((assessment, version))
    return validated


def resolve_severity_score(
    assessments: Iterable[CVSSAssessmentLike],
    default_cvss_version: str,
) -> SeverityResolution | None:
    """Select the Severity Resolution Cascade winner of one CVE.

    `assessments` must be the complete, unfiltered assessment set of one
    CVE. Each candidate is ranked by the deterministic key of
    `cvss-scoring.md` (Severity Resolution Cascade): cascade step
    (canonical `SUSE` at the default version, canonical `SUSE` at another
    version, non-SUSE at the default version, non-SUSE at another
    version), then version priority `4.0 > 3.1 > 3.0 > 2.0`, then score
    descending, then provider name ascending by Unicode code point
    (independent of database collation and locale). Only the exact
    persisted string `SUSE` is canonical SUSE. Input order never affects
    the winner.

    Returns the winner's score, version, provider, and unified severity
    label, or `None` when the set is empty.

    Raises:
        ValueError: The default version is not `3.1` or `4.0`, an
            assessment has an unsupported version, two assessments share
            one `(provider_name, cvss_version)` key, or the winning score
            is outside 0.0-10.0.
    """
    default_version = _validated_default_version(default_cvss_version)
    candidates = _validated_assessments(assessments)
    if not candidates:
        return None

    def cascade_key(
        candidate: tuple[CVSSAssessmentLike, CVSSVersion],
    ) -> tuple[int, int, Decimal, str]:
        assessment, version = candidate
        is_suse = assessment.provider_name == SUSE_PROVIDER_NAME
        is_default = version == default_version
        step = (0 if is_suse else 2) + (0 if is_default else 1)
        return (
            step,
            -_VERSION_PRIORITY[version],
            -assessment.score,
            assessment.provider_name,
        )

    winner, version = min(candidates, key=cascade_key)
    return SeverityResolution(
        score=winner.score,
        version=version,
        provider=winner.provider_name,
        label=calculate_severity(winner.score),
    )


def resolve_eligibility_score(
    assessments: Iterable[CVSSAssessmentLike],
    default_cvss_version: str,
) -> EligibilityResolution:
    """Resolve the eligibility score of one CVE.

    Returns the score of the canonical `SUSE` assessment at the given
    default version with `source = suse`; otherwise exactly `10.0` with
    `source = fallback`. No other SUSE version and no external provider
    ever participates. The result always exists, including for an empty
    set. `assessments` must be the complete, unfiltered assessment set.

    Raises:
        ValueError: The default version is not `3.1` or `4.0`, an
            assessment has an unsupported version, or two assessments
            share one `(provider_name, cvss_version)` key.
    """
    default_version = _validated_default_version(default_cvss_version)
    for assessment, version in _validated_assessments(assessments):
        if (
            assessment.provider_name == SUSE_PROVIDER_NAME
            and version == default_version
        ):
            return EligibilityResolution(
                score=assessment.score, source=EligibilitySource.SUSE
            )
    return EligibilityResolution(
        score=ELIGIBILITY_FALLBACK_SCORE, source=EligibilitySource.FALLBACK
    )
