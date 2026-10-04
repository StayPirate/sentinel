"""Unit tests for the pure phases of post-ingest CVE package resolution in
`package_service` (backend/app/services/package_service.py): the
`resolve_ticket_packages` task argument validation
`parse_post_ingest_arguments()`, the public package-name grammar, and the
deterministic candidate resolution `resolve_post_ingest_candidates()`.

Owning specifications:

- docs/features/packages/package-service.md (Post-ingest CVE package
  resolution: Task boundary and arguments; Deterministic candidate
  resolution; Audit and observability, the `failed` event and log privacy).
- docs/features/packages/cpe-package-mapping.md (Resolution Function;
  Consumers: the four post-ingest rows).
- docs/features/tickets/cve-service.md (PostIngestTasks; the "No U+0000 in
  string values" bullet of the payload schema; `build_post_ingest_tasks()`
  package-name heuristic).
- docs/features/platform/testing-strategy.md (Post-Ingest Package
  Resolution: argument validation, deduplication, grammar, and ordering
  bullets; External String Admissibility).
- Issue #786 decisions D1 (U+0000 in any string argument is a caller-contract
  failure) and D2 (the workflow events carry no candidate value).

Validation and candidate resolution touch no database, HTTP client, or
SMELT; the resolver tests substitute the two `cpe_mapping` resolvers that
`package_service` imports by name, except `TestRealResolvers`, which runs
the real resolvers over a small fictional mapping file that replaces the
committed resource. Expected values are transcribed
from the specifications, never computed with the module under test. All
identifiers, CPEs, vendors, and package names are fictional.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Iterator, MutableMapping
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from structlog.testing import capture_logs

from app.schemas.package import PACKAGE_NAME_PATTERN, PackageAdditionRequest
from app.services import cpe_mapping, package_service
from app.services.cpe_mapping import CPEMappingLoadError
from app.services.package_service import (
    PACKAGE_NAME_GRAMMAR,
    PostIngestArgumentError,
    PostIngestArguments,
    ValidatedCPEMatch,
    parse_post_ingest_arguments,
    resolve_post_ingest_candidates,
)

LogEntry = MutableMapping[str, Any]

TICKET_ID = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
MCID = "1aaaaaaa-0000-4000-8000-000000000001"
CPE_A = "cpe:2.3:a:example:alpha:1.0:*:*:*:*:*:*:*"
CPE_B = "cpe:2.3:a:example:beta:1.0:*:*:*:*:*:*:*"
CPE_C = "cpe:2.3:a:example:gamma:1.0:*:*:*:*:*:*:*"

FAILED = "ticket_package_resolution_failed"

MARKER = "Example-Confidential-Argument-Value"
"""A rejected value that must never reach a log or exception message."""

WIDE = "é"
"""A two-byte UTF-8 code point: lengths count code points, not bytes."""


def _match(
    criteria: object = CPE_A, vulnerable: object = True, mcid: object = MCID
) -> dict[str, object]:
    return {"criteria": criteria, "vulnerable": vulnerable, "match_criteria_id": mcid}


def _arguments(**overrides: object) -> dict[str, object]:
    """A valid minimal argument set (every list empty) with `overrides`."""
    arguments: dict[str, object] = {
        "ticket_id": TICKET_ID,
        "cpe_matches": [],
        "affected_cpes": [],
        "vendor_products": [],
        "resolved_packages": [],
    }
    arguments.update(overrides)
    return arguments


def _rejection(argument: str, *, with_ticket_id: bool = True) -> LogEntry:
    """The single validation ERROR (package-service.md, Audit and
    observability: an invalid `ticket_id` is omitted)."""
    entry: LogEntry = {
        "event": FAILED,
        "log_level": "error",
        "phase": "validation",
        "cause": "PostIngestArgumentError",
        "argument": argument,
    }
    if with_ticket_id:
        entry["ticket_id"] = TICKET_ID
    return entry


def _assert_rejected(
    arguments: dict[str, object], argument: str, *, with_ticket_id: bool = True
) -> None:
    """Validation raises `PostIngestArgumentError` (a `ValueError`) naming
    only `argument`, after exactly one ERROR, and no rejected value reaches
    the log or the exception."""
    with capture_logs() as logs, pytest.raises(PostIngestArgumentError) as raised:
        parse_post_ingest_arguments(**arguments)

    assert isinstance(raised.value, ValueError)
    assert raised.value.argument == argument
    assert logs == [_rejection(argument, with_ticket_id=with_ticket_id)]
    for text in (repr(logs), str(raised.value), repr(raised.value.args)):
        assert MARKER not in text
        assert "\x00" not in text


# ---------------------------------------------------------------------------
# Valid arguments (Task boundary and arguments)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestValidArguments:
    def test_minimal_payload_with_every_list_empty_is_accepted(self) -> None:
        with capture_logs() as logs:
            parsed = parse_post_ingest_arguments(**_arguments())

        assert parsed == PostIngestArguments(
            ticket_id=uuid.UUID(TICKET_ID),
            cpe_matches=(),
            affected_cpes=(),
            vendor_products=(),
            resolved_packages=(),
        )
        assert type(parsed.ticket_id) is uuid.UUID
        assert logs == []

    def test_full_payload_returns_typed_values_unchanged(self) -> None:
        """No value is trimmed, case-normalized, coerced, deduplicated, or
        dropped: surrounding spaces and upper case survive, a repeated
        affected CPE stays repeated, a `vulnerable = false` entry and a
        `null` `match_criteria_id` are kept, and a non-ASCII direct name
        that satisfies the producer heuristic is accepted (the package-name
        grammar is applied later, during candidate resolution)."""
        spaced = " cpe:2.3:a:Example:Alpha:1.0:*:*:*:*:*:*:* "
        with capture_logs() as logs:
            parsed = parse_post_ingest_arguments(
                **_arguments(
                    cpe_matches=[
                        _match(spaced, False, None),
                        _match(CPE_B, True, MCID),
                    ],
                    affected_cpes=[CPE_C, CPE_C, spaced],
                    vendor_products=[[" Example Vendor ", "Alpha Product"], ["", "*"]],
                    resolved_packages=[
                        "Fictional-Package",
                        "fictional-package",
                        "pkgé",
                    ],
                )
            )

        assert parsed == PostIngestArguments(
            ticket_id=uuid.UUID(TICKET_ID),
            cpe_matches=(
                ValidatedCPEMatch(spaced, False, None),
                ValidatedCPEMatch(CPE_B, True, uuid.UUID(MCID)),
            ),
            affected_cpes=(CPE_C, CPE_C, spaced),
            vendor_products=((" Example Vendor ", "Alpha Product"), ("", "*")),
            resolved_packages=("Fictional-Package", "fictional-package", "pkgé"),
        )
        assert type(parsed.cpe_matches[1].match_criteria_id) is uuid.UUID
        assert logs == []

    def test_every_individual_upper_bound_is_inclusive_in_code_points(self) -> None:
        """2048-code-point CPEs, a 512-code-point vendor, and a
        50-code-point direct name are accepted even though their UTF-8
        encodings are twice as long; the product has no bound."""
        cpe = WIDE * 2048
        vendor = WIDE * 512
        product = WIDE * 20_000
        name = WIDE * 50

        parsed = parse_post_ingest_arguments(
            **_arguments(
                cpe_matches=[_match(cpe)],
                affected_cpes=[cpe],
                vendor_products=[[vendor, product]],
                resolved_packages=[name],
            )
        )

        assert parsed.cpe_matches == (ValidatedCPEMatch(cpe, True, uuid.UUID(MCID)),)
        assert parsed.affected_cpes == (cpe,)
        assert parsed.vendor_products == ((vendor, product),)
        assert parsed.resolved_packages == (name,)


# ---------------------------------------------------------------------------
# Invalid `ticket_id`
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestInvalidTicketId:
    @pytest.mark.parametrize(
        "ticket_id",
        [
            pytest.param(12345, id="integer"),
            pytest.param(None, id="none"),
            pytest.param(uuid.UUID(TICKET_ID), id="uuid-object"),
            pytest.param([TICKET_ID], id="list"),
            pytest.param(TICKET_ID.upper(), id="uppercase"),
            pytest.param("{" + TICKET_ID + "}", id="braces"),
            pytest.param("urn:uuid:" + TICKET_ID, id="urn"),
            pytest.param(TICKET_ID.replace("-", ""), id="no-hyphens"),
            pytest.param(" " + TICKET_ID, id="leading-space"),
            pytest.param("", id="empty"),
            pytest.param(MARKER, id="not-a-uuid"),
            pytest.param("SNTL-42", id="public-locator"),
        ],
    )
    def test_non_canonical_ticket_id_is_rejected_without_ticket_id_field(
        self, ticket_id: object
    ) -> None:
        _assert_rejected(
            _arguments(ticket_id=ticket_id), "ticket_id", with_ticket_id=False
        )

    def test_invalid_ticket_id_is_reported_before_other_invalid_arguments(
        self,
    ) -> None:
        _assert_rejected(
            _arguments(ticket_id=MARKER, cpe_matches={}, resolved_packages=[MARKER]),
            "ticket_id",
            with_ticket_id=False,
        )


# ---------------------------------------------------------------------------
# Invalid containers
# ---------------------------------------------------------------------------

CONTAINERS = ["cpe_matches", "affected_cpes", "vendor_products", "resolved_packages"]

NON_LISTS = [
    pytest.param({}, id="dict"),
    pytest.param((), id="tuple"),
    pytest.param(MARKER, id="string"),
    pytest.param(None, id="none"),
    pytest.param(frozenset(), id="frozenset"),
    pytest.param(0, id="integer"),
]


@pytest.mark.unit
class TestInvalidContainers:
    @pytest.mark.parametrize("argument", CONTAINERS)
    @pytest.mark.parametrize("value", NON_LISTS)
    def test_container_that_is_not_a_json_array_is_rejected(
        self, argument: str, value: object
    ) -> None:
        _assert_rejected(_arguments(**{argument: value}), argument)


# ---------------------------------------------------------------------------
# Invalid items
# ---------------------------------------------------------------------------


def _without(key: str) -> dict[str, object]:
    match = _match()
    del match[key]
    return match


INVALID_CPE_MATCHES = [
    pytest.param(CPE_A, id="string-item"),
    pytest.param([CPE_A, True, MCID], id="array-item"),
    pytest.param(None, id="null-item"),
    pytest.param(_without("criteria"), id="missing-criteria"),
    pytest.param(_without("vulnerable"), id="missing-vulnerable"),
    pytest.param(_without("match_criteria_id"), id="missing-match-criteria-id"),
    pytest.param({**_match(), "negate": False}, id="extra-key"),
    pytest.param({}, id="empty-object"),
    pytest.param(_match(criteria=1), id="criteria-integer"),
    pytest.param(_match(criteria=None), id="criteria-null"),
    pytest.param(_match(criteria=[CPE_A]), id="criteria-array"),
    pytest.param(_match(criteria=WIDE * 2049), id="criteria-2049-code-points"),
    pytest.param(_match(vulnerable=1), id="vulnerable-one"),
    pytest.param(_match(vulnerable=0), id="vulnerable-zero"),
    pytest.param(_match(vulnerable="true"), id="vulnerable-string"),
    pytest.param(_match(vulnerable=None), id="vulnerable-null"),
    pytest.param(_match(mcid=MCID.upper()), id="mcid-uppercase"),
    pytest.param(_match(mcid="{" + MCID + "}"), id="mcid-braces"),
    pytest.param(_match(mcid="urn:uuid:" + MCID), id="mcid-urn"),
    pytest.param(_match(mcid=MCID.replace("-", "")), id="mcid-no-hyphens"),
    pytest.param(_match(mcid=MARKER), id="mcid-not-a-uuid"),
    pytest.param(_match(mcid=""), id="mcid-empty"),
    pytest.param(_match(mcid=1), id="mcid-integer"),
    pytest.param(_match(mcid=uuid.UUID(MCID)), id="mcid-uuid-object"),
]

INVALID_AFFECTED_CPES = [
    pytest.param(1, id="integer"),
    pytest.param(None, id="null"),
    pytest.param([CPE_A], id="array"),
    pytest.param(WIDE * 2049, id="2049-code-points"),
]

INVALID_VENDOR_PRODUCTS = [
    pytest.param(("example", "alpha"), id="tuple"),
    pytest.param(["example"], id="one-element"),
    pytest.param(["example", "alpha", "beta"], id="three-elements"),
    pytest.param([], id="empty"),
    pytest.param([1, "alpha"], id="vendor-integer"),
    pytest.param(["example", None], id="product-null"),
    pytest.param("example:alpha", id="string"),
    pytest.param({"vendor": "example", "product": "alpha"}, id="object"),
    pytest.param([WIDE * 513, "alpha"], id="vendor-513-code-points"),
]

INVALID_PACKAGE_CANDIDATES = [
    pytest.param("", id="empty"),
    pytest.param("x" * 51, id="51-characters"),
    pytest.param(WIDE * 51, id="51-code-points"),
    pytest.param("fictional/pkg", id="slash"),
    pytest.param("fictional:pkg", id="colon"),
    pytest.param("fictional pkg", id="space"),
    pytest.param("fictional\tpkg", id="tab"),
    pytest.param("fictional-pkg\n", id="newline"),
    pytest.param("fictional\u00a0pkg", id="no-break-space"),
    pytest.param(1, id="integer"),
    pytest.param(None, id="null"),
    pytest.param(["fictional-pkg"], id="array"),
]


@pytest.mark.unit
class TestInvalidItems:
    @pytest.mark.parametrize("item", INVALID_CPE_MATCHES)
    def test_invalid_cpe_match_is_rejected(self, item: object) -> None:
        _assert_rejected(_arguments(cpe_matches=[_match(CPE_B), item]), "cpe_matches")

    @pytest.mark.parametrize("item", INVALID_AFFECTED_CPES)
    def test_invalid_affected_cpe_is_rejected(self, item: object) -> None:
        _assert_rejected(_arguments(affected_cpes=[CPE_A, item]), "affected_cpes")

    @pytest.mark.parametrize("item", INVALID_VENDOR_PRODUCTS)
    def test_invalid_vendor_product_pair_is_rejected(self, item: object) -> None:
        _assert_rejected(
            _arguments(vendor_products=[["example", "alpha"], item]),
            "vendor_products",
        )

    @pytest.mark.parametrize("item", INVALID_PACKAGE_CANDIDATES)
    def test_invalid_package_name_candidate_is_rejected(self, item: object) -> None:
        _assert_rejected(
            _arguments(resolved_packages=["fictional-pkg", item]), "resolved_packages"
        )

    def test_rejected_value_never_reaches_the_log(self) -> None:
        """Each rejected item carries `MARKER`; `_assert_rejected` proves
        it is neither logged nor part of the exception."""
        for argument, value in [
            ("cpe_matches", [_match(criteria=MARKER + WIDE * 2048)]),
            ("cpe_matches", [_match(mcid=MARKER)]),
            ("affected_cpes", [MARKER + WIDE * 2048]),
            ("vendor_products", [[MARKER + WIDE * 512, "alpha"]]),
            ("resolved_packages", [MARKER + "/"]),
        ]:
            _assert_rejected(_arguments(**{argument: value}), argument)


# ---------------------------------------------------------------------------
# U+0000 in every string argument (issue #786 D1; testing-strategy.md,
# External String Admissibility)
# ---------------------------------------------------------------------------

NUL_CASES = [
    pytest.param(
        _arguments(cpe_matches=[_match(criteria=CPE_A + "\x00")]),
        "cpe_matches",
        id="criteria",
    ),
    pytest.param(
        _arguments(cpe_matches=[_match(mcid="\x00" + MCID)]),
        "cpe_matches",
        id="match-criteria-id",
    ),
    pytest.param(
        _arguments(affected_cpes=["\x00" + CPE_A]),
        "affected_cpes",
        id="affected-cpe",
    ),
    pytest.param(
        _arguments(vendor_products=[["exa\x00mple", "alpha"]]),
        "vendor_products",
        id="vendor",
    ),
    pytest.param(
        _arguments(vendor_products=[["example", "\x00"]]),
        "vendor_products",
        id="product",
    ),
    pytest.param(
        _arguments(resolved_packages=["fictional\x00pkg"]),
        "resolved_packages",
        id="package-name",
    ),
]
"""One U+0000 position per consumed string field (start, middle, end, and
the whole value are each used at least once)."""


@pytest.mark.unit
class TestNulCharacters:
    @pytest.mark.parametrize(("arguments", "argument"), NUL_CASES)
    def test_nul_in_a_string_argument_is_a_caller_contract_failure(
        self, arguments: dict[str, object], argument: str
    ) -> None:
        _assert_rejected(arguments, argument)

    def test_nul_in_ticket_id_is_rejected_without_ticket_id_field(self) -> None:
        _assert_rejected(
            _arguments(ticket_id=TICKET_ID[:8] + "\x00" + TICKET_ID[8:]),
            "ticket_id",
            with_ticket_id=False,
        )


# ---------------------------------------------------------------------------
# Public package-name grammar (Deterministic candidate resolution, step 4)
# ---------------------------------------------------------------------------

GRAMMAR_NAMES = [
    pytest.param("ab", True, id="two-characters"),
    pytest.param("a" * 255, True, id="255-characters"),
    pytest.param("openssl-3", True, id="hyphen"),
    pytest.param("Fictional.Pkg_1+2-3", True, id="every-punctuation"),
    pytest.param("a..b", True, id="inner-dots"),
    pytest.param("a", False, id="one-character"),
    pytest.param("a" * 256, False, id="256-characters"),
    pytest.param("", False, id="empty"),
    pytest.param("-ab", False, id="leading-hyphen"),
    pytest.param("ab-", False, id="trailing-hyphen"),
    pytest.param(".ab", False, id="leading-dot"),
    pytest.param("ab.", False, id="trailing-dot"),
    pytest.param("_ab", False, id="leading-underscore"),
    pytest.param("ab+", False, id="trailing-plus"),
    pytest.param("..", False, id="dot-dot"),
    pytest.param("pkgé", False, id="non-ascii"),
    pytest.param("ab\n", False, id="trailing-newline"),
    pytest.param("a b", False, id="space"),
    pytest.param("a/b", False, id="slash"),
    pytest.param("a:b", False, id="colon"),
]


@pytest.mark.unit
class TestPackageNameGrammar:
    def test_grammar_is_the_api_schema_pattern(self) -> None:
        assert PACKAGE_NAME_GRAMMAR.pattern == PACKAGE_NAME_PATTERN.removeprefix(
            "^"
        ).removesuffix("$")
        assert PACKAGE_NAME_PATTERN == (
            r"^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,253}[a-zA-Z0-9]$"
        )

    @pytest.mark.parametrize(("name", "valid"), GRAMMAR_NAMES)
    def test_grammar_matches_the_api_request_validation(
        self, name: str, valid: bool
    ) -> None:
        try:
            PackageAdditionRequest.model_validate({"package_name": name})
        except ValidationError:
            accepted_by_api = False
        else:
            accepted_by_api = True

        assert (PACKAGE_NAME_GRAMMAR.fullmatch(name) is not None) is valid
        assert accepted_by_api is valid


# ---------------------------------------------------------------------------
# Deterministic candidate resolution with substituted resolvers
# ---------------------------------------------------------------------------


class _Resolvers:
    """Substitutes for the two resolvers `package_service` imports by
    name; records every call in order and answers from fixed results."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.cpe_results: dict[str, set[str]] = {}
        self.pair_results: dict[tuple[str, str], set[str]] = {}
        self.failures: dict[tuple[str, ...], BaseException] = {}
        monkeypatch.setattr(package_service, "resolve_cpe_packages", self._cpe)
        monkeypatch.setattr(package_service, "resolve_vendor_product", self._pair)

    def _answer(self, call: tuple[str, ...], result: set[str]) -> set[str]:
        self.calls.append(call)
        if call in self.failures:
            raise self.failures[call]
        return set(result)

    def _cpe(self, cpe_criteria: str) -> set[str]:
        return self._answer(
            ("cpe", cpe_criteria), self.cpe_results.get(cpe_criteria, set())
        )

    def _pair(self, vendor: str, product: str) -> set[str]:
        return self._answer(
            ("pair", vendor, product), self.pair_results.get((vendor, product), set())
        )


@pytest.fixture
def resolvers(monkeypatch: pytest.MonkeyPatch) -> _Resolvers:
    return _Resolvers(monkeypatch)


def _candidates(
    *,
    cpe_matches: tuple[ValidatedCPEMatch, ...] = (),
    affected_cpes: tuple[str, ...] = (),
    vendor_products: tuple[tuple[str, str], ...] = (),
    resolved_packages: tuple[str, ...] = (),
) -> list[str]:
    return resolve_post_ingest_candidates(
        cpe_matches=cpe_matches,
        affected_cpes=affected_cpes,
        vendor_products=vendor_products,
        resolved_packages=resolved_packages,
    )


def _vm(
    criteria: str, vulnerable: bool = True, mcid: str | None = MCID
) -> ValidatedCPEMatch:
    return ValidatedCPEMatch(criteria, vulnerable, uuid.UUID(mcid) if mcid else None)


@pytest.mark.unit
class TestCandidateResolution:
    def test_empty_inputs_call_no_resolver_and_yield_no_name(
        self, resolvers: _Resolvers
    ) -> None:
        assert _candidates() == []
        assert resolvers.calls == []

    def test_cpes_are_exact_deduplicated_across_both_sources_before_resolving(
        self, resolvers: _Resolvers
    ) -> None:
        """`CPE_A` appears twice in `cpe_matches` (with different NVD
        metadata) and once in `affected_cpes`; `CPE_B` in both sources.
        Each distinct CPE is resolved exactly once, in code-point order."""
        resolvers.cpe_results = {
            CPE_A: {"fictional-alpha"},
            CPE_B: {"fictional-beta"},
            CPE_C: {"fictional-gamma"},
        }

        names = _candidates(
            cpe_matches=(_vm(CPE_C), _vm(CPE_A, True, MCID), _vm(CPE_A, False, None)),
            affected_cpes=(CPE_B, CPE_A, CPE_B),
        )

        assert resolvers.calls == [("cpe", CPE_A), ("cpe", CPE_B), ("cpe", CPE_C)]
        assert names == ["fictional-alpha", "fictional-beta", "fictional-gamma"]

    def test_nvd_metadata_is_not_reinterpreted(self, resolvers: _Resolvers) -> None:
        """A `vulnerable = false` entry with a `null` `match_criteria_id`
        is resolved like any other transported criteria."""
        resolvers.cpe_results = {CPE_A: {"fictional-alpha"}}

        names = _candidates(cpe_matches=(_vm(CPE_A, False, None),))

        assert resolvers.calls == [("cpe", CPE_A)]
        assert names == ["fictional-alpha"]

    def test_cpe_order_is_unicode_code_point_order_and_case_sensitive(
        self, resolvers: _Resolvers
    ) -> None:
        """Upper case (U+005A) precedes lower case (U+0061), which precedes
        `é` (U+00E9): a locale-aware order would put `alpha` first. CPEs
        differing only in case are distinct and resolved separately."""
        upper = "cpe:2.3:a:example:Zeta:1:*:*:*:*:*:*:*"
        lower = "cpe:2.3:a:example:alpha:1:*:*:*:*:*:*:*"
        mixed = "cpe:2.3:a:example:Alpha:1:*:*:*:*:*:*:*"
        accented = "cpe:2.3:a:example:éa:1:*:*:*:*:*:*:*"

        _candidates(
            cpe_matches=(_vm(accented), _vm(lower)), affected_cpes=(mixed, upper)
        )

        assert resolvers.calls == [
            ("cpe", mixed),
            ("cpe", upper),
            ("cpe", lower),
            ("cpe", accented),
        ]

    def test_pairs_are_deduplicated_and_resolved_vendor_then_product(
        self, resolvers: _Resolvers
    ) -> None:
        """Pairs are resolved after every CPE, once each, ordered by vendor
        then product in code-point order (`A` < `a`, `B` < `b`)."""
        _candidates(
            affected_cpes=(CPE_A,),
            vendor_products=(
                ("b", "a"),
                ("a", "z"),
                ("a", "b"),
                ("a", "z"),
                ("A", "z"),
                ("a", "B"),
                ("b", "a"),
            ),
        )

        assert resolvers.calls == [
            ("cpe", CPE_A),
            ("pair", "A", "z"),
            ("pair", "a", "B"),
            ("pair", "a", "b"),
            ("pair", "a", "z"),
            ("pair", "b", "a"),
        ]

    def test_candidates_preserve_case_and_exact_deduplicate_across_sources(
        self, resolvers: _Resolvers
    ) -> None:
        resolvers.cpe_results = {CPE_A: {"Fictional-Pkg", "fictional-pkg"}}
        resolvers.pair_results = {("example", "alpha"): {"fictional-pkg", "shared"}}

        names = _candidates(
            affected_cpes=(CPE_A,),
            vendor_products=(("example", "alpha"),),
            resolved_packages=("shared", "Shared", "Fictional-Pkg"),
        )

        assert names == ["Fictional-Pkg", "Shared", "fictional-pkg", "shared"]

    def test_names_outside_the_grammar_are_skipped(self, resolvers: _Resolvers) -> None:
        resolvers.cpe_results = {
            CPE_A: {"a", "a" * 256, "a" * 255, "-ab", "ab-", ".ab", "ab."},
        }
        resolvers.pair_results = {
            ("example", "alpha"): {"_ab", "..", "pkgé", "ab\n", "a b", "", "a..b"}
        }

        names = _candidates(
            affected_cpes=(CPE_A,),
            vendor_products=(("example", "alpha"),),
            resolved_packages=("ab", "x"),
        )

        assert names == ["a..b", "a" * 255, "ab"]

    def test_final_names_are_in_unicode_code_point_order(
        self, resolvers: _Resolvers
    ) -> None:
        """`+` (U+002B) < `-` (U+002D) < `.` (U+002E) < `0` (U+0030) <
        `Z` (U+005A) < `_` (U+005F) < `a` (U+0061)."""
        names = _candidates(
            resolved_packages=("zlib", "a_b", "a0", "a.b", "a-b", "a+b", "Zlib")
        )

        assert names == ["Zlib", "a+b", "a-b", "a.b", "a0", "a_b", "zlib"]

    def test_reordered_payload_yields_identical_calls_and_names(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cpe_matches = (_vm(CPE_C), _vm(CPE_A, False, None))
        affected_cpes = (CPE_B, CPE_A)
        vendor_products = (("b", "x"), ("a", "y"))
        resolved_packages = ("fictional-z", "fictional-m")
        observed: list[tuple[list[tuple[str, ...]], list[str]]] = []
        for reverse in (False, True):
            spy = _Resolvers(monkeypatch)
            spy.cpe_results = {CPE_A: {"fictional-a"}, CPE_C: {"fictional-c"}}
            spy.pair_results = {("a", "y"): {"fictional-y"}}
            order: Callable[[tuple[Any, ...]], tuple[Any, ...]] = (
                (lambda values: values[::-1]) if reverse else (lambda values: values)
            )
            names = _candidates(
                cpe_matches=order(cpe_matches),
                affected_cpes=order(affected_cpes),
                vendor_products=order(vendor_products),
                resolved_packages=order(resolved_packages),
            )
            observed.append((spy.calls, names))

        assert observed[0] == observed[1]
        assert observed[0][1] == [
            "fictional-a",
            "fictional-c",
            "fictional-m",
            "fictional-y",
            "fictional-z",
        ]

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: CPEMappingLoadError("fictional/path.json", "rule 2"),
                id="mapping-load-error",
            ),
            pytest.param(lambda: RuntimeError(MARKER), id="unexpected"),
        ],
    )
    @pytest.mark.parametrize("source", ["cpe", "pair"])
    def test_resolver_failure_propagates_unchanged(
        self,
        resolvers: _Resolvers,
        make_error: Callable[[], BaseException],
        source: str,
    ) -> None:
        """The failing call is the second CPE or the first pair; nothing
        after it is resolved and no name is returned."""
        error = make_error()
        failing = ("cpe", CPE_B) if source == "cpe" else ("pair", "example", "alpha")
        resolvers.failures[failing] = error

        with pytest.raises(type(error)) as raised:
            _candidates(
                affected_cpes=(CPE_A, CPE_B, CPE_C),
                vendor_products=(("example", "alpha"), ("example", "beta")),
                resolved_packages=("fictional-direct",),
            )

        assert raised.value is error
        assert resolvers.calls[-1] == failing
        expected_prefix: list[tuple[str, ...]] = (
            [("cpe", CPE_A)]
            if source == "cpe"
            else [("cpe", CPE_A), ("cpe", CPE_B), ("cpe", CPE_C)]
        )
        assert resolvers.calls == [*expected_prefix, failing]


# ---------------------------------------------------------------------------
# The real resolvers over a fictional mapping file (cpe-package-mapping.md,
# Resolution Function; Consumers)
# ---------------------------------------------------------------------------

FICTIONAL_MAPPING = {
    "example_vendor:example_product": ["fictional-pkg-a", "fictional-pkg-b"],
    "example_vendor:example_widget": ["fictional-pkg-c"],
}
"""A small mapping that replaces the committed resource for these tests."""


@pytest.fixture
def fictional_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Point the real loader at a temporary `FICTIONAL_MAPPING` file and
    isolate the process-local cache before and after the test (as the
    `mapping_file` fixture of `tests/test_services/test_cpe_mapping.py`)."""
    path = tmp_path / "cpe-package-mapping.json"
    path.write_text(json.dumps(FICTIONAL_MAPPING), encoding="utf-8")
    monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: path)
    cpe_mapping._load_mapping.cache_clear()
    yield
    cpe_mapping._load_mapping.cache_clear()


@pytest.mark.unit
@pytest.mark.usefixtures("fictional_mapping")
class TestRealResolvers:
    def test_every_consumer_row_contributes_its_candidates(self) -> None:
        """One value per Consumers row of cpe-package-mapping.md, through
        the real resolvers:

        - the NVD CPE `example_vendor:example_product` (a `vulnerable =
          false` entry) maps to `fictional-pkg-a` and `fictional-pkg-b`;
        - the affected-entry CPE of an unmapped concrete product falls back
          to its decoded, lowercased product `fictional-gadget`;
        - the free-text vendor/product pair `Example Vendor`/` Example
          Widget ` is normalized to the mapped `example_vendor:example_widget`,
          i.e. `fictional-pkg-c`, and the unmapped `Fictional Vendor`/
          `Fictional Tool` falls back to `fictional_tool`;
        - the package-name candidate keeps its case.

        A malformed CPE contributes nothing and logs `cpe_parse_failed`
        with its reason only."""
        with capture_logs() as logs:
            names = _candidates(
                cpe_matches=(
                    _vm(
                        "cpe:2.3:a:example_vendor:example_product:1.0:*:*:*:*:*:*:*",
                        False,
                        None,
                    ),
                ),
                affected_cpes=(
                    "cpe:2.3:a:fictional_vendor:Fictional-Gadget:1.0:*:*:*:*:*:*:*",
                    f"cpe:/a:fictional:{MARKER}",
                ),
                vendor_products=(
                    ("Example Vendor", " Example Widget "),
                    ("Fictional Vendor", "Fictional Tool"),
                ),
                resolved_packages=("Fictional-Direct",),
            )

        assert names == [
            "Fictional-Direct",
            "fictional-gadget",
            "fictional-pkg-a",
            "fictional-pkg-b",
            "fictional-pkg-c",
            "fictional_tool",
        ]
        assert logs == [
            {
                "event": "cpe_parse_failed",
                "log_level": "warning",
                "reason": "missing_cpe23_prefix",
            }
        ]
        assert MARKER not in repr(logs)

    def test_non_concrete_values_and_malformed_cpes_yield_no_name(self) -> None:
        with capture_logs() as logs:
            names = _candidates(
                cpe_matches=(_vm("cpe:2.3:a:example:*:*:*:*:*:*:*:*:*"),),
                affected_cpes=("cpe:2.3:a:example", "not-a-cpe"),
                vendor_products=(("example", "*"), ("-", "-"), ("example", " ")),
            )

        assert names == []
        assert [(entry["event"], entry["reason"]) for entry in logs] == [
            ("cpe_parse_failed", "wrong_component_count"),
            ("cpe_parse_failed", "missing_cpe23_prefix"),
        ]
