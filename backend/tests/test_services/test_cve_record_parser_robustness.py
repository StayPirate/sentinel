"""Robustness, External String Admissibility, and module-boundary tests for
the CVE Record Format 5.x parser (backend/app/services/cve_record_parser.py).

Contract under test: docs/features/platform/cve-record-parser.md (Design
Principles: pure and fail-safe; Module-Level Defaults: no exception, no
I/O, no logging; Input Validation; External String Admissibility; Schema
Version Handling: no `dataVersion` branching) and
docs/features/platform/testing-strategy.md (External String
Admissibility). Behavior of each function is covered by
`test_cve_record_parser.py`.

The mutation tests are deterministic property tests: every consumed member
of every sanitized fixture (`tests/support/cve_record.py`), at every nesting
level, is replaced by each value of a fixed malformed set, deleted, and
swapped between array and object; a seeded `random.Random` then combines
several mutations per variant. Each variant goes through all ten functions,
which must not raise and must return their documented types and invariants.
No database, network, or log is involved.
"""

from __future__ import annotations

import ast
import copy
import inspect
import itertools
import random
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime
from typing import Any, Final

import pytest
from pydantic import ValidationError

from app.core.enums import CveState
from app.services import cve_record_parser
from app.services.cve_ingest import (
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVEIngestPayload,
    CVSSAssessmentEntry,
    CWEEntry,
    KEVEntry,
    SSVCEntry,
    affected_version_key,
)
from app.services.cve_record_parser import (
    TITLE_MAX_LENGTH,
    extract_cve_state,
    extract_dates,
    parse_affected_versions,
    parse_cvss_assessments,
    parse_cwe_classifications,
    parse_description,
    parse_kev_data,
    parse_ssvc_assessment,
    parse_title,
    validate_cve_id,
)
from app.services.cvss import validate_cvss_vector
from tests.support.cve_record import ALL_FIXTURES, load_fixture
from tests.support.module_imports import (
    APP_ROOT,
    forbidden_imports,
    imported_modules,
)

pytestmark = pytest.mark.unit

CVE_ID: Final = "CVE-2026-0001"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40: Final = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
VENDOR: Final = "Example Vendor"
PRODUCT: Final = "example-product"
SIBLING: Final[dict[str, Any]] = {
    "vendor": VENDOR,
    "product": "example-sibling",
    "versions": [{"version": "1.0", "status": "affected"}],
}
SIBLING_ENTRY: Final = AffectedVersionEntry(
    vendor=VENDOR, product="example-sibling", version="1.0", status="affected"
)
SSVC_TIMESTAMP: Final = "2024-04-02T04:00:23.138684Z"
KEV_REFERENCE: Final = "https://kev.example.invalid/catalog?cve=CVE-2026-0001"

_MODULE: Final = APP_ROOT / "services" / "cve_record_parser.py"
_PUBLIC_FUNCTIONS: Final = (
    "parse_affected_versions",
    "parse_cvss_assessments",
    "parse_cwe_classifications",
    "parse_description",
    "parse_title",
    "validate_cve_id",
    "parse_ssvc_assessment",
    "parse_kev_data",
    "extract_cve_state",
    "extract_dates",
)

_CONSUMED_MEMBERS: Final = (
    "affected",
    "metrics",
    "problemTypes",
    "descriptions",
    "title",
    "providerMetadata",
)
"""Container members read by the parser or by its Caller Pattern."""

_REPLACEMENTS: Final[tuple[Any, ...]] = (
    None,
    0,
    1.5,
    True,
    [],
    {},
    "x" * 5000,
    "\x00",
    "a\x00",
    [[None, {"k": "\x00"}], "x"],
    {"k": {"k": [1, None, "\x00"]}},
)
"""Malformed values substituted for every consumed member."""

_ARGUMENTS: Final[tuple[Any, ...]] = (
    None,
    0,
    -1,
    1.5,
    True,
    False,
    "",
    "x",
    "\x00",
    b"x",
    [],
    {},
    [None, 0, "x", [], {}],
    {"0": {"vendor": VENDOR}},
    load_fixture("cvelistv5_kev_ssvc_offset_n_a"),
)
"""Wrong-typed arguments for every function, including a whole record (the
wrong level of the record, carrying every consumed member below it)."""

type Path = tuple[str | int, ...]


# ---------------------------------------------------------------------------
# Invariant checks
# ---------------------------------------------------------------------------


def _check_affected(entries: object) -> None:
    assert isinstance(entries, list)
    assert all(isinstance(entry, AffectedVersionEntry) for entry in entries)
    assert all(entry.ecosystem is None for entry in entries)
    keys = [affected_version_key(entry) for entry in entries]
    assert len(keys) == len(set(keys))
    operation = AffectedVersionScopeOperation(
        source_container="cna",
        operation=AffectedVersionOperation.REPLACE,
        entries=entries,
    )
    CVEIngestPayload(affected_version_operations=[operation])


def _check_cvss(entries: object, provider: object) -> None:
    assert isinstance(entries, list)
    assert len(entries) <= 4
    versions = set()
    for entry in entries:
        assert isinstance(entry, CVSSAssessmentEntry)
        assert isinstance(provider, str)
        assert entry.provider_name == provider.strip()
        assert isinstance(entry.vector_string, str)
        parsed = validate_cvss_vector(entry.vector_string)
        assert parsed.canonical_vector == entry.vector_string
        versions.add(parsed.version)
    assert len(versions) == len(entries)


def _check_cwe(entries: object, source: str) -> None:
    assert isinstance(entries, list)
    assert all(isinstance(entry, CWEEntry) for entry in entries)
    assert {entry.source for entry in entries} <= {source}
    ids = [entry.cwe_id for entry in entries]
    assert len(ids) == len(set(ids))


def _check_utc(value: object) -> None:
    assert value is None or (isinstance(value, datetime) and value.tzinfo is UTC)


def _check_ssvc(entry: object) -> None:
    assert entry is None or isinstance(entry, SSVCEntry)
    if entry is not None:
        _check_utc(entry.assessed_at)


def _check_kev(entry: object) -> None:
    assert entry is None or isinstance(entry, KEVEntry)
    if entry is not None:
        assert isinstance(entry.date_added, date)


def _check_optional_str(value: object) -> None:
    assert value is None or isinstance(value, str)


def _check_title(value: object) -> None:
    """Truncated to the bound unless it contains U+0000 (then untruncated,
    for the caller's payload to reject)."""
    assert value is None or (
        isinstance(value, str) and (len(value) <= TITLE_MAX_LENGTH or "\x00" in value)
    )


def _check_dates(dates: object) -> None:
    assert isinstance(dates, tuple)
    assert len(dates) == 3
    for value in dates:
        _check_utc(value)


def _check_state(state: object) -> None:
    assert state is None or isinstance(state, CveState)


# ---------------------------------------------------------------------------
# Exercising a (mutated) record
# ---------------------------------------------------------------------------


def _member(value: Any, key: str) -> Any:
    """`value[key]` of an object; a non-object value is passed through so
    that the function under test receives it as a wrong-typed argument."""
    return value.get(key) if isinstance(value, dict) else value


def _exercise_metadata(metadata: Any) -> None:
    _check_state(extract_cve_state(metadata))
    _check_dates(extract_dates(metadata))
    assert validate_cve_id(CVE_ID, metadata) == CVE_ID


def _exercise_container(container: Any) -> None:
    short_name = _member(_member(container, "providerMetadata"), "shortName")
    provider = "Linux" if short_name is None else short_name
    metrics = _member(container, "metrics")
    source = "cna:Example CNA"

    _check_affected(parse_affected_versions(_member(container, "affected")))
    entries = parse_cvss_assessments(metrics, provider)
    if isinstance(provider, str):
        _check_cvss(entries, provider)
    else:
        assert entries == []
    _check_cwe(
        parse_cwe_classifications(_member(container, "problemTypes"), source), source
    )
    _check_optional_str(parse_description(_member(container, "descriptions")))
    _check_title(parse_title(container))
    _check_ssvc(parse_ssvc_assessment(metrics))
    _check_kev(parse_kev_data(metrics))


def _containers(record: Any) -> list[Any]:
    containers = _member(record, "containers")
    adp = _member(containers, "adp")
    adps = adp if isinstance(adp, list) else [] if adp is None else [adp]
    return [_member(containers, "cna"), *adps]


def _exercise_record(record: Any) -> None:
    _exercise_metadata(_member(record, "cveMetadata"))
    for container in _containers(record):
        _exercise_container(container)


def _exercise_scope(record: Any, path: Path) -> None:
    """Exercise only the part of `record` a mutation at `path` can affect."""
    if path[0] == "cveMetadata":
        _exercise_metadata(_member(record, "cveMetadata"))
    elif path[:2] == ("containers", "cna") and len(path) > 2:
        _exercise_container(record["containers"]["cna"])
    elif path[:2] == ("containers", "adp") and len(path) > 3:
        index = path[2]
        assert isinstance(index, int)
        _exercise_container(record["containers"]["adp"][index])
    else:
        _exercise_record(record)


def _children(value: Any) -> Iterator[tuple[str | int, Any]]:
    if isinstance(value, dict):
        yield from value.items()
    elif isinstance(value, list):
        yield from enumerate(value)


def _subtree_paths(value: Any, path: Path) -> Iterator[Path]:
    yield path
    for key, child in _children(value):
        yield from _subtree_paths(child, (*path, key))


def _consumed_paths(record: dict[str, Any]) -> list[Path]:
    """Every path of a consumed member, at every nesting level, in a fixed
    order, including the containers themselves."""
    paths: list[Path] = [*_subtree_paths(record["cveMetadata"], ("cveMetadata",))]
    containers = record["containers"]
    paths.append(("containers",))
    scopes: list[tuple[Path, dict[str, Any]]] = [
        (("containers", "cna"), containers["cna"])
    ]
    if "adp" in containers:
        paths.append(("containers", "adp"))
        scopes += [
            (("containers", "adp", index), adp)
            for index, adp in enumerate(containers["adp"])
        ]
    for scope, container in scopes:
        paths.append(scope)
        for member in _CONSUMED_MEMBERS:
            if member in container:
                paths += _subtree_paths(container[member], (*scope, member))
    return paths


def _swaps(value: Any) -> list[Any]:
    """Array ↔ object replacements of `value`."""
    if isinstance(value, list):
        return [{str(index): item for index, item in enumerate(value)}]
    if isinstance(value, dict):
        return [[value], list(value.values())]
    return []


def _parent(record: Any, path: Path) -> Any:
    target = record
    for key in path[:-1]:
        target = target[key]
    return target


def _mutations(record: dict[str, Any]) -> Iterator[tuple[Path, Callable[[], None]]]:
    """(path, undo) per in-place mutation; the record is mutated while the
    caller handles one item and restored by calling `undo`."""
    for path in _consumed_paths(record):
        parent = _parent(record, path)
        key = path[-1]
        original = parent[key]

        def undo(
            parent: Any = parent, key: Any = key, original: Any = original
        ) -> None:
            parent[key] = original

        for replacement in (*_REPLACEMENTS, *_swaps(original)):
            parent[key] = replacement
            yield path, undo
        if isinstance(parent, dict):
            del parent[key]
            yield path, undo


_ABSENT_MARKER: Final = object()


def _random_variant(
    pristine: dict[str, Any], paths: list[Path], rng: random.Random
) -> dict[str, Any]:
    """A copy of `pristine` with three to six random mutations; a path made
    unreachable by an earlier mutation is ignored."""
    record = copy.deepcopy(pristine)
    for path in rng.sample(paths, k=min(len(paths), rng.randint(3, 6))):
        try:
            parent = _parent(record, path)
        except KeyError, IndexError, TypeError:
            continue
        key = path[-1]
        reachable = (isinstance(parent, dict) and key in parent) or (
            isinstance(parent, list) and isinstance(key, int) and key < len(parent)
        )
        if not reachable:
            continue
        current = parent[key]
        choices = [*_REPLACEMENTS, *_swaps(current), _ABSENT_MARKER]
        replacement = rng.choice(choices)
        if replacement is _ABSENT_MARKER:
            if isinstance(parent, dict):
                del parent[key]
        else:
            parent[key] = copy.deepcopy(replacement)
    return record


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestFixtureMutations:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_every_single_mutation_yields_documented_types(self, name: str) -> None:
        record = load_fixture(name)
        count = 0

        for path, undo in _mutations(record):
            _exercise_scope(record, path)
            undo()
            count += 1

        assert count > 100
        assert record == load_fixture(name)

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_seeded_combined_mutations_yield_documented_types(self, name: str) -> None:
        pristine = load_fixture(name)
        paths = _consumed_paths(pristine)
        rng = random.Random(f"cve-record-parser:{name}")

        for _ in range(40):
            _exercise_record(_random_variant(pristine, paths, rng))

    def test_mutation_paths_reach_every_consumed_nesting_level(self) -> None:
        """Guards the harness: the paths include a version field, a vector,
        an SSVC option value, a KEV field, a CWE id, and a date."""
        paths = {
            path
            for name in ("cvelistv5_kev_ssvc_offset_n_a", "vulns_published_5_1_1")
            for path in _consumed_paths(load_fixture(name))
        }

        assert ("cveMetadata", "state") in paths
        assert ("containers", "cna", "affected", 0, "versions", 0, "lessThan") in paths
        assert ("containers", "cna", "affected", 0, "programFiles", 1) in paths
        assert ("containers", "cna", "metrics", 0, "cvssV3_1", "vectorString") in paths
        adp_paths = {p for p in paths if p[:2] == ("containers", "adp")}
        assert any(p[-1] == "Exploitation" for p in adp_paths)
        assert any(p[-1] == "dateAdded" for p in adp_paths)
        assert any(p[-1] == "cweId" for p in adp_paths)


class TestPurity:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_fixture_input_after_parsing_is_unchanged(self, name: str) -> None:
        record = load_fixture(name)

        _exercise_record(record)

        assert record == load_fixture(name)

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_repeated_calls_after_other_input_yield_equal_results(
        self, name: str
    ) -> None:
        def outputs() -> list[Any]:
            record = load_fixture(name)
            metadata = record["cveMetadata"]
            found: list[Any] = [
                extract_cve_state(metadata),
                extract_dates(metadata),
                validate_cve_id(CVE_ID, metadata),
            ]
            for container in _containers(record):
                metrics = container.get("metrics")
                found += [
                    parse_affected_versions(container.get("affected")),
                    parse_cvss_assessments(metrics, "Example CNA"),
                    parse_cwe_classifications(container.get("problemTypes"), "cna:x"),
                    parse_description(container.get("descriptions")),
                    parse_title(container),
                    parse_ssvc_assessment(metrics),
                    parse_kev_data(metrics),
                ]
            return found

        first = outputs()
        _exercise_record(load_fixture("cvelistv5_all_cvss_keys_non_base"))

        assert outputs() == first

    def test_returned_list_after_mutation_leaves_next_result_unchanged(self) -> None:
        affected = [SIBLING]

        first = parse_affected_versions(affected)
        first.clear()

        assert parse_affected_versions(affected) == [SIBLING_ENTRY]


class TestWrongTypedArguments:
    @pytest.mark.parametrize("argument", _ARGUMENTS)
    def test_wrong_typed_array_argument_yields_empty_list(self, argument: Any) -> None:
        assert parse_affected_versions(argument) == []
        assert parse_cvss_assessments(argument, "Example CNA") == []
        assert parse_cwe_classifications(argument, "cna:x") == []

    @pytest.mark.parametrize("argument", _ARGUMENTS)
    def test_wrong_typed_context_argument_yields_empty_or_stamped(
        self, argument: Any
    ) -> None:
        """A non-string provider or source yields `[]`; a string one is
        stamped (the provider trimmed) or rejected with the candidate."""
        cvss = parse_cvss_assessments([{"cvssV3_1": {"vectorString": V31}}], argument)
        problem = {"descriptions": [{"type": "CWE", "cweId": "CWE-79"}]}
        cwe = parse_cwe_classifications([problem], argument)

        if isinstance(argument, bytes):
            # Not a JSON type: Pydantic's lax mode decodes a bytes `source`,
            # so only the absence of an exception is asserted.
            assert cvss == []
            assert all(isinstance(e, CWEEntry) for e in cwe)
        elif isinstance(argument, str):
            assert [e.provider_name for e in cvss] == [argument.strip()]
            assert cwe == (
                []
                if "\x00" in argument
                else [CWEEntry(cwe_id="CWE-79", source=argument)]
            )
        else:
            assert cvss == []
            assert cwe == []
        assert validate_cve_id(argument, {"cveId": CVE_ID}) is argument

    @pytest.mark.parametrize("argument", _ARGUMENTS)
    def test_wrong_typed_object_argument_yields_none(self, argument: Any) -> None:
        assert parse_description(argument) is None
        assert parse_title(argument) is None
        assert parse_ssvc_assessment(argument) is None
        assert parse_kev_data(argument) is None
        assert extract_cve_state(argument) is None
        assert extract_dates(argument) == (None, None, None)
        assert validate_cve_id(CVE_ID, argument) == CVE_ID

    @pytest.mark.parametrize(
        ("call", "expected"),
        [
            pytest.param(lambda: parse_affected_versions(SIBLING), [], id="affected"),
            pytest.param(
                lambda: parse_cvss_assessments(
                    {"cvssV3_1": {"vectorString": V31}}, "Example CNA"
                ),
                [],
                id="cvss",
            ),
            pytest.param(
                lambda: parse_cwe_classifications(
                    {"descriptions": [{"type": "CWE", "cweId": "CWE-79"}]}, "cna:x"
                ),
                [],
                id="cwe",
            ),
            pytest.param(
                lambda: parse_description({"lang": "en", "value": "Fictional."}),
                None,
                id="description",
            ),
            pytest.param(
                lambda: parse_title([{"title": "Fictional title"}]), None, id="title"
            ),
            pytest.param(
                lambda: parse_ssvc_assessment(_ssvc_metrics()[0]), None, id="ssvc"
            ),
            pytest.param(lambda: parse_kev_data(_kev_metrics()[0]), None, id="kev"),
            pytest.param(
                lambda: extract_cve_state([{"state": "PUBLISHED"}]),
                None,
                id="state-array",
            ),
            pytest.param(
                lambda: extract_cve_state("PUBLISHED"), None, id="state-value"
            ),
            pytest.param(
                lambda: extract_dates([{"datePublished": "2024-01-01T00:00:00Z"}]),
                (None, None, None),
                id="dates-array",
            ),
            pytest.param(
                lambda: extract_dates("2024-01-01T00:00:00Z"),
                (None, None, None),
                id="dates-value",
            ),
        ],
    )
    def test_single_valid_element_instead_of_container_yields_empty_result(
        self, call: Callable[[], object], expected: object
    ) -> None:
        """A valid element, object, or value passed where its array or
        object is expected is not unwrapped."""
        assert call() == expected

    def test_container_instead_of_array_yields_empty_result(self) -> None:
        (container,) = [
            adp
            for adp in load_fixture("cvelistv5_kev_ssvc_offset_n_a")["containers"][
                "adp"
            ]
            if adp["providerMetadata"]["shortName"] == "CISA-ADP"
        ]

        assert parse_affected_versions(container) == []
        assert parse_cvss_assessments(container, "Example CNA") == []
        assert parse_cwe_classifications(container, "cna:x") == []
        assert parse_description(container) is None
        assert parse_ssvc_assessment(container) is None
        assert parse_kev_data(container) is None

    def test_deeply_nested_input_yields_documented_types(self) -> None:
        nested: Any = "x"
        for _ in range(200):
            nested = [nested, {"k": nested}]
        record = {
            "cveMetadata": nested,
            "containers": {"cna": dict.fromkeys(_CONSUMED_MEMBERS, nested)},
        }

        _exercise_record(record)


# ---------------------------------------------------------------------------
# External String Admissibility
# ---------------------------------------------------------------------------

_POSITIONS: Final = ("start", "middle", "end", "whole")


def _with_nul(base: str, position: str) -> str:
    middle = len(base) // 2
    return {
        "start": "\x00" + base,
        "middle": base[:middle] + "\x00" + base[middle:],
        "end": base + "\x00",
        "whole": "\x00",
    }[position]


def _versions() -> list[dict[str, Any]]:
    return [
        {"version": "1.0", "status": "affected"},
        {"version": "2.0", "status": "affected"},
    ]


def _element_with(key: str, value: Any) -> dict[str, Any]:
    return {"vendor": VENDOR, "product": PRODUCT, "versions": _versions(), key: value}


def _assert_element_skipped(element: dict[str, Any]) -> None:
    """Every entry of the element is skipped; the sibling survives."""
    assert parse_affected_versions([element, SIBLING]) == [SIBLING_ENTRY]


def _affected_element_field(key: str) -> Callable[[str], None]:
    def check(value: str) -> None:
        _assert_element_skipped(_element_with(key, value))

    return check


def _cpe(value: str) -> None:
    _assert_element_skipped(_element_with("cpes", [value, "cpe:/a:example:other"]))


def _program_file(value: str) -> None:
    _assert_element_skipped(_element_with("programFiles", ["src/example.c", value]))


def _version_field(key: str) -> Callable[[str], None]:
    def check(value: str) -> None:
        versions = _versions()
        versions[1][key] = value
        element = {"vendor": VENDOR, "product": PRODUCT, "versions": versions}

        entries = parse_affected_versions([element, SIBLING])

        assert entries == [
            AffectedVersionEntry(
                vendor=VENDOR, product=PRODUCT, version="1.0", status="affected"
            ),
            SIBLING_ENTRY,
        ]

    return check


def _vector(value: str) -> None:
    metrics = [
        {"cvssV3_1": {"vectorString": value}},
        {"cvssV4_0": {"vectorString": V40}},
    ]

    entries = parse_cvss_assessments(metrics, "Example CNA")

    assert [entry.vector_string for entry in entries] == [V40]


def _provider(value: str) -> None:
    entries = parse_cvss_assessments([{"cvssV3_1": {"vectorString": V31}}], value)

    assert entries == [CVSSAssessmentEntry(provider_name=value, vector_string=V31)]


def _cwe_id(value: str) -> None:
    problem = {
        "descriptions": [
            {"type": "CWE", "cweId": value},
            {"type": "CWE", "cweId": "CWE-89"},
        ]
    }

    entries = parse_cwe_classifications([problem], "cna:Example CNA")

    assert [entry.cwe_id for entry in entries] == ["CWE-89"]


def _cwe_source(value: str) -> None:
    problem = {"descriptions": [{"type": "CWE", "cweId": "CWE-79"}]}

    assert parse_cwe_classifications([problem], value) == []


def _ssvc_metrics(**overrides: Any) -> list[dict[str, Any]]:
    options = {
        "Exploitation": "active",
        "Automatable": "no",
        "Technical Impact": "total",
    }
    content: dict[str, Any] = {
        "version": "2.0.3",
        "timestamp": SSVC_TIMESTAMP,
        **{k: v for k, v in overrides.items() if k in {"version", "timestamp"}},
    }
    options.update({k: v for k, v in overrides.items() if k in options})
    content["options"] = [{key: value} for key, value in options.items()]
    return [{"other": {"type": "ssvc", "content": content}}]


def _ssvc_field(key: str) -> Callable[[str], None]:
    def check(value: str) -> None:
        assert parse_ssvc_assessment(_ssvc_metrics()) is not None

        assert parse_ssvc_assessment(_ssvc_metrics(**{key: value})) is None

    return check


def _kev_metrics(**content: Any) -> list[dict[str, Any]]:
    values = {"dateAdded": "2024-01-15", "reference": KEV_REFERENCE, **content}
    return [{"other": {"type": "kev", "content": values}}]


def _kev_field(key: str) -> Callable[[str], None]:
    def check(value: str) -> None:
        assert parse_kev_data(_kev_metrics()) is not None

        assert parse_kev_data(_kev_metrics(**{key: value})) is None

    return check


def _state(value: str) -> None:
    assert extract_cve_state({"state": value}) is None


def _date_field(index: int) -> Callable[[str], None]:
    keys = ("datePublished", "dateUpdated", "dateRejected")

    def check(value: str) -> None:
        metadata = dict.fromkeys(keys, "2024-01-01T00:00:00.000Z")
        metadata[keys[index]] = value

        dates = extract_dates(metadata)

        assert dates[index] is None
        assert [d for i, d in enumerate(dates) if i != index] == [
            datetime(2024, 1, 1, tzinfo=UTC)
        ] * 2

    return check


def _description(value: str) -> None:
    descriptions = [{"lang": "en", "value": value}]

    assert parse_description(descriptions) == value
    with pytest.raises(ValidationError):
        CVEIngestPayload(description=parse_description(descriptions))


def _title(value: str) -> None:
    """Returned untruncated, so the caller's payload rejects it."""
    assert parse_title({"title": value}) == value
    with pytest.raises(ValidationError):
        CVEIngestPayload(title=parse_title({"title": value}))


_ADMISSIBILITY: Final[dict[str, tuple[str, Callable[[str], None]]]] = {
    **{
        f"affected.{key}": ("example-value", _affected_element_field(key))
        for key in (
            "vendor",
            "product",
            "repo",
            "packageURL",
            "collectionURL",
            "packageName",
            "defaultStatus",
        )
    },
    "affected.cpes[0]": ("cpe:/a:example:product", _cpe),
    "affected.programFiles[]": ("src/example.c", _program_file),
    **{
        f"versions.{key}": ("example-value", _version_field(key))
        for key in ("version", "versionType", "lessThan", "lessThanOrEqual", "status")
    },
    "metrics.vectorString": (V31, _vector),
    "provider_name": ("Example CNA", _provider),
    "problemTypes.cweId": ("CWE-79", _cwe_id),
    "cwe source": ("cna:Example CNA", _cwe_source),
    "ssvc Exploitation": ("active", _ssvc_field("Exploitation")),
    "ssvc Automatable": ("no", _ssvc_field("Automatable")),
    "ssvc Technical Impact": ("total", _ssvc_field("Technical Impact")),
    "ssvc version": ("2.0.3", _ssvc_field("version")),
    "ssvc timestamp": (SSVC_TIMESTAMP, _ssvc_field("timestamp")),
    "kev dateAdded": ("2024-01-15", _kev_field("dateAdded")),
    "kev dateAdded date-time": ("2024-01-15T00:00:00Z", _kev_field("dateAdded")),
    "kev reference": (KEV_REFERENCE, _kev_field("reference")),
    "cveMetadata.state": ("PUBLISHED", _state),
    "cveMetadata.datePublished": ("2024-01-01T00:00:00.000Z", _date_field(0)),
    "cveMetadata.dateUpdated": ("2024-01-01T00:00:00.000Z", _date_field(1)),
    "cveMetadata.dateRejected": ("2024-01-01T00:00:00.000Z", _date_field(2)),
    "descriptions.value": ("Fictional description.", _description),
    "title": ("t" * 300, _title),
}
"""Consumed string → (valid base value, check of the named outcome for a
value containing U+0000) per the spec table (External String
Admissibility)."""

_PASSED_THROUGH: Final = frozenset({"provider_name", "descriptions.value"})
"""Values returned unchanged: the caller or `upsert_cve()` rejects them. A
`title` is also returned unvalidated, but its 300-character base value is
truncated, so it stays in the guard below."""


class TestExternalStringAdmissibility:
    @pytest.mark.parametrize("position", _POSITIONS)
    @pytest.mark.parametrize("field", list(_ADMISSIBILITY))
    def test_nul_in_consumed_string_yields_documented_outcome(
        self, field: str, position: str
    ) -> None:
        base, check = _ADMISSIBILITY[field]

        check(_with_nul(base, position))

    @pytest.mark.parametrize(
        "field", [f for f in _ADMISSIBILITY if f not in _PASSED_THROUGH]
    )
    def test_base_value_without_nul_avoids_the_outcome(self, field: str) -> None:
        """Guards the matrix: without U+0000 the base value does not take the
        rejection outcome, so each outcome above is caused by the
        character."""
        base, check = _ADMISSIBILITY[field]

        with pytest.raises(AssertionError):
            check(base)

    def test_n_a_vendor_with_nul_skips_the_element(self) -> None:
        element = {"vendor": "n/a\x00", "product": "n/a", "versions": _versions()}

        _assert_element_skipped(element)

    def test_less_than_or_equal_with_nul_beside_less_than_is_ignored(self) -> None:
        """Only an entry carrying the value is rejected: `lessThan` wins."""
        element = {
            "vendor": VENDOR,
            "product": PRODUCT,
            "versions": [
                {"version": "1.0", "lessThan": "2.0", "lessThanOrEqual": "\x00"}
            ],
        }

        (entry,) = parse_affected_versions([element])

        assert (entry.version_end, entry.version_end_inclusive) == ("2.0", False)


class TestComparedOnlyValues:
    """Values the parser only compares are not checked; a value containing
    U+0000 simply does not match."""

    @pytest.mark.parametrize("lang", ["\x00en", "e\x00n", "\x00"])
    def test_description_lang_with_leading_or_inner_nul_is_not_english(
        self, lang: str
    ) -> None:
        descriptions = [
            {"lang": "de", "value": "Fiktive Beschreibung."},
            {"lang": lang, "value": "Fictional description."},
        ]

        assert parse_description(descriptions) == "Fiktive Beschreibung."

    def test_description_lang_with_trailing_nul_is_english(self) -> None:
        """The prefix rule compares only the start of `lang`; the value is
        never persisted, so a trailing U+0000 is irrelevant."""
        descriptions = [
            {"lang": "de", "value": "Fiktive Beschreibung."},
            {"lang": "en\x00", "value": "Fictional description."},
        ]

        assert parse_description(descriptions) == "Fictional description."

    def test_problem_type_type_with_nul_does_not_select(self) -> None:
        problem = {
            "descriptions": [{"type": "CWE\x00"}, {"type": "\x00", "cweId": "CWE-79"}]
        }

        entries = parse_cwe_classifications([problem], "cna:x")

        assert [entry.cwe_id for entry in entries] == ["CWE-79"]

    def test_ssvc_option_key_with_nul_yields_none(self) -> None:
        metrics = _ssvc_metrics()
        options = metrics[0]["other"]["content"]["options"]
        options[0] = {"Exploitation\x00": "active"}

        assert parse_ssvc_assessment(metrics) is None

    @pytest.mark.parametrize("type_", ["ssvc\x00", "kev\x00", "\x00"])
    def test_other_type_with_nul_yields_none(self, type_: str) -> None:
        ssvc = _ssvc_metrics()
        kev = _kev_metrics()
        ssvc[0]["other"]["type"] = type_
        kev[0]["other"]["type"] = type_

        assert parse_ssvc_assessment(ssvc) is None
        assert parse_kev_data(kev) is None

    @pytest.mark.parametrize("key", ["cveId", "cveID"])
    def test_json_cve_id_with_nul_yields_the_filename_id(self, key: str) -> None:
        assert validate_cve_id(CVE_ID, {key: CVE_ID + "\x00"}) == CVE_ID


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------

_FORBIDDEN_PREFIXES: Final = (
    "logging",
    "structlog",
    "app.core.logging",
    "sqlalchemy",
    "alembic",
    "asyncpg",
    "app.models",
    "app.db",
    "app.database",
    "app.config",
    "app.api",
    "app.schemas",
    "app.tasks",
    "app.cli",
    "app.celery_app",
    "httpx",
    "requests",
    "aiohttp",
    "urllib",
    "http",
    "socket",
    "ssl",
    "subprocess",
    "os",
    "sys",
    "pathlib",
    "io",
    "shutil",
    "tempfile",
    "asyncio",
    "celery",
    "redis",
)
"""Logging, database/ORM, settings, I/O, network, and broker modules."""


def _docstring_nodes(tree: ast.Module) -> set[ast.AST]:
    found: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                found.add(body[0].value)
    return found


def _attribute_docstrings(tree: ast.Module) -> set[ast.AST]:
    """String expressions directly following an assignment (attribute
    docstrings such as the one of `TITLE_MAX_LENGTH`)."""
    found: set[ast.AST] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            continue
        for previous, statement in itertools.pairwise(body):
            if (
                isinstance(previous, ast.Assign | ast.AnnAssign)
                and isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                found.add(statement.value)
    return found


class TestModuleBoundary:
    def test_imports_include_no_logging_database_settings_or_io(self) -> None:
        modules = imported_modules(_MODULE, "app.services")

        assert forbidden_imports(modules) == set()
        assert {
            m
            for m in modules
            if any(m == p or m.startswith(f"{p}.") for p in _FORBIDDEN_PREFIXES)
        } == set()

    def test_application_imports_are_the_payload_cvss_and_core(self) -> None:
        modules = imported_modules(_MODULE, "app.services")

        assert {m for m in modules if m.startswith("app.")} == {
            "app.core.enums",
            "app.core.external_strings",
            "app.services.cve_ingest",
            "app.services.cvss",
            "app.services.ticket_mutations_errors",
        }

    def test_code_outside_docstrings_has_no_data_version_reference(self) -> None:
        """Schema Version Handling: no `dataVersion` branching. Only
        documentation strings may mention the key."""
        tree = ast.parse(_MODULE.read_text(encoding="utf-8"))
        documentation = _docstring_nodes(tree) | _attribute_docstrings(tree)

        references = [
            node
            for node in ast.walk(tree)
            if node not in documentation
            and (
                (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and "dataversion" in node.value.casefold()
                )
                or (isinstance(node, ast.Name) and "dataversion" in node.id.casefold())
                or (
                    isinstance(node, ast.Attribute)
                    and "dataversion" in node.attr.casefold()
                )
            )
        ]

        assert references == []

    def test_code_calls_include_no_io_builtin(self) -> None:
        tree = ast.parse(_MODULE.read_text(encoding="utf-8"))

        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

        assert called.isdisjoint(
            {"open", "print", "input", "exec", "eval", "compile", "__import__"}
        )

    def test_public_functions_are_synchronous(self) -> None:
        for name in _PUBLIC_FUNCTIONS:
            function = getattr(cve_record_parser, name)
            assert inspect.isfunction(function), name
            assert not inspect.iscoroutinefunction(function), name
