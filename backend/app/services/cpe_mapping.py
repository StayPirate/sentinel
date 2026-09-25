"""Static CPE-to-package mapping: parser, loader, and resolvers.

Implements `docs/features/packages/cpe-package-mapping.md`: CPE 2.3
formatted-string decoding, the canonical `vendor:product` mapping-key
serialization, the lazily loaded and validated mapping in
`app/data/cpe-package-mapping.json`, and the two synchronous resolvers
consumed by the post-ingest package-resolution workflow.

The resolvers create no audit event, touch no database, and call no
external service. The only I/O is the first read of the package-relative
mapping resource, performed when a lookup first has concrete vendor and
product values. Importing this module never reads or validates the file,
and generic worker startup does not import it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Final, NoReturn, cast

import structlog

logger = structlog.get_logger(__name__)

_CPE23_PREFIX: Final = "cpe:2.3:"
_CPE23_COMPONENT_COUNT: Final = 11
_VENDOR_INDEX: Final = 1
_PRODUCT_INDEX: Final = 2
_ESCAPE: Final = "\\"
_SEPARATOR: Final = ":"
_ANY_OR_NA: Final = frozenset({"*", "-"})
"""Encoded single-character components with ANY/NA meaning."""

_FREE_TEXT_NON_CONCRETE: Final = frozenset({"", "*", "-"})
"""Normalized free-text values that cannot form a lookup component."""

_MAPPING_RESOURCE: Final = ("data", "cpe-package-mapping.json")
"""Mapping location relative to the installed `app` package."""

_JSON_WHITESPACE: Final = b" \t\n\r"


class CPEMappingLoadError(RuntimeError):
    """The mapping file exists but cannot be read or is structurally invalid.

    `reason` names the failed validation rule and, for structural
    failures, the offending key or zero-based array index. It never
    contains file contents or package values.
    """

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"CPE mapping load failed at {path}: {reason}")


@dataclass(frozen=True, slots=True)
class _Component:
    """One formatted-string component: raw encoded text and decoded value."""

    encoded: str
    value: str


class _UnpairedEscapeError(ValueError):
    """A trailing `\\` escapes no character."""


class _CPEParseError(ValueError):
    """A CPE string violates the supported CPE 2.3 formatted-string grammar."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class _JSONObject(tuple[tuple[str, object], ...]):
    """A decoded JSON object preserving every key/value pair in file order.

    A plain `dict` silently keeps only the last duplicate key, so the
    loader decodes objects into this pair sequence to enforce rule 4. It
    is deliberately not a `list`, so an object value is never mistaken
    for a JSON array.
    """


def _split_components(text: str) -> list[_Component]:
    """Split on unescaped `:` and decode each escaped character.

    `\\` escapes the following character, which becomes part of the
    semantic value while the escape marker is removed. Raises
    `_UnpairedEscapeError` for a trailing unpaired `\\`.
    """
    components: list[_Component] = []
    encoded_start = 0
    value: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == _ESCAPE:
            if index + 1 == len(text):
                raise _UnpairedEscapeError
            value.append(text[index + 1])
            index += 2
            continue
        if char == _SEPARATOR:
            components.append(_Component(text[encoded_start:index], "".join(value)))
            encoded_start = index + 1
            value = []
        else:
            value.append(char)
        index += 1
    components.append(_Component(text[encoded_start:], "".join(value)))
    return components


def _serialize_component(value: str) -> str:
    """Escape a literal `\\` as `\\\\` and a literal `:` as `\\:`."""
    return value.replace(_ESCAPE, _ESCAPE * 2).replace(_SEPARATOR, _ESCAPE + _SEPARATOR)


def _canonical_key(vendor: str, product: str) -> str:
    """Canonical mapping key of a normalized semantic vendor/product pair."""
    return f"{_serialize_component(vendor)}{_SEPARATOR}{_serialize_component(product)}"


def _concrete_value(component: _Component) -> str | None:
    """Normalized semantic value, or `None` for ANY, NA, or empty.

    `*` and `-` are special only when the encoded component is that single
    unescaped character; an escaped literal is a normal value.
    """
    if component.encoded in _ANY_OR_NA:
        return None
    value = component.value.strip().lower()
    return value or None


def _parse_cpe(cpe_criteria: str) -> tuple[str | None, str | None]:
    """Decode a CPE 2.3 string into concrete vendor and product values.

    Returns `(vendor, product)` where either element is `None` when the
    component is ANY, NA, or empty. Raises `_CPEParseError` for a missing
    `cpe:2.3:` prefix (including every CPE 2.2 URI), an unpaired escape,
    or a component count other than 11.
    """
    if not cpe_criteria.startswith(_CPE23_PREFIX):
        raise _CPEParseError("missing_cpe23_prefix")
    try:
        components = _split_components(cpe_criteria[len(_CPE23_PREFIX) :])
    except _UnpairedEscapeError:
        raise _CPEParseError("unpaired_escape") from None
    if len(components) != _CPE23_COMPONENT_COUNT:
        raise _CPEParseError("wrong_component_count")
    return (
        _concrete_value(components[_VENDOR_INDEX]),
        _concrete_value(components[_PRODUCT_INDEX]),
    )


def _mapping_resource() -> Traversable:
    """The mapping resource resolved relative to the installed `app` package."""
    return files("app").joinpath(*_MAPPING_RESOURCE)


def _reject_non_json_constant(constant: str) -> NoReturn:
    """Reject `NaN`, `Infinity`, and `-Infinity`, which are not JSON."""
    raise ValueError(f"non-JSON constant {constant}")


def _json_type_name(value: object) -> str:
    """JSON type name of a decoded value, for content-free error reasons."""
    if isinstance(value, _JSONObject):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if value is None:
        return "null"
    return "number"


def _key_rule_violation(key: str) -> str | None:
    """Rule 5 detail for a non-canonical key, or `None` when canonical."""
    try:
        components = _split_components(key)
    except _UnpairedEscapeError:
        return "unpaired escape"
    if len(components) != 2:
        return "expected exactly one unescaped ':' separator"
    vendor, product = (component.value for component in components)
    if not vendor or not product:
        return "empty vendor or product"
    if vendor != vendor.strip().lower() or product != product.strip().lower():
        return "vendor or product is not lowercase and trimmed"
    if _canonical_key(vendor, product) != key:
        return "key is not in canonical serialization"
    return None


def _package_rule_violation(value: object) -> str | None:
    """Rule 6 detail for an invalid package list, or `None` when valid."""
    if not isinstance(value, list):
        return f"value is a JSON {_json_type_name(value)}, not an array"
    if not value:
        return "array is empty"
    for index, package in enumerate(value):
        if not isinstance(package, str):
            return f"element {index} is a JSON {_json_type_name(package)}"
        if not package.strip():
            return f"element {index} is empty"
        if package != package.strip():
            return f"element {index} has leading or trailing whitespace"
    return None


def _validated_mapping(path: str, entries: _JSONObject) -> dict[str, tuple[str, ...]]:
    """Apply rules 4-6 in order to a non-empty root object.

    Semantic key uniqueness needs no separate check: rule 5 makes each key
    the injective canonical serialization of its decoded pair, so two keys
    with the same pair are textually identical and fail rule 4.
    """
    seen: set[str] = set()
    for key, _ in entries:
        if key in seen:
            raise CPEMappingLoadError(path, f"rule 4 (duplicate key): {key!r}")
        seen.add(key)
    for key, _ in entries:
        violation = _key_rule_violation(key)
        if violation is not None:
            raise CPEMappingLoadError(
                path, f"rule 5 (canonical key) failed for key {key!r}: {violation}"
            )
    mapping: dict[str, tuple[str, ...]] = {}
    for key, value in entries:
        violation = _package_rule_violation(value)
        if violation is not None:
            raise CPEMappingLoadError(
                path, f"rule 6 (package list) failed for key {key!r}: {violation}"
            )
        mapping[key] = tuple(cast("list[str]", value))
    return mapping


@lru_cache(maxsize=1)
def _load_mapping() -> dict[str, tuple[str, ...]]:
    """Read, validate, and cache the package-relative mapping file.

    Absent, zero-byte, or whitespace-only files log `cpe_mapping_absent`
    and an empty root object logs `cpe_mapping_empty`; both return an
    empty dict. Populated and empty results are cached for the process
    lifetime. `CPEMappingLoadError` (unreadable, invalid UTF-8, invalid
    JSON, non-object root, or a failed structural rule) stores no cache
    entry, so the next call retries. Non-`OSError` exceptions propagate
    unchanged.
    """
    resource = _mapping_resource()
    path = str(resource)
    try:
        raw = resource.read_bytes()
    except FileNotFoundError, NotADirectoryError:
        logger.warning("cpe_mapping_absent", path=path)
        return {}
    except OSError as exc:
        raise CPEMappingLoadError(
            path, f"rule 1 (readable): {type(exc).__name__}: {exc}"
        ) from exc
    if not raw.strip(_JSON_WHITESPACE):
        logger.warning("cpe_mapping_absent", path=path)
        return {}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Chaining would render the offending byte in tracebacks.
        raise CPEMappingLoadError(
            path, f"rule 1 (valid UTF-8): invalid byte at offset {exc.start}"
        ) from None
    try:
        root = json.loads(
            text,
            object_pairs_hook=_JSONObject,
            parse_constant=_reject_non_json_constant,
        )
    except ValueError as exc:
        position = (
            f" at line {exc.lineno} column {exc.colno}"
            if isinstance(exc, json.JSONDecodeError)
            else ""
        )
        raise CPEMappingLoadError(
            path, f"rule 2 (valid JSON): syntax error{position}"
        ) from exc
    if not isinstance(root, _JSONObject):
        raise CPEMappingLoadError(
            path, f"rule 3 (object root): root is a JSON {_json_type_name(root)}"
        )
    if not root:
        logger.warning("cpe_mapping_empty", path=path)
        return {}
    return _validated_mapping(path, root)


def _resolve(vendor: str | None, product: str | None) -> set[str]:
    """Shared lookup and raw-product fallback of both public resolvers."""
    if product is None:
        return set()
    if vendor is None:
        return {product}
    packages = _load_mapping().get(_canonical_key(vendor, product))
    if packages is None:
        return {product}
    return set(packages)


def resolve_cpe_packages(cpe_criteria: str) -> set[str]:
    """Resolve one CPE 2.3 string to SUSE source package names.

    A parse error logs WARNING `cpe_parse_failed` (without the untrusted
    CPE string) and returns an empty set, as does a non-concrete product.
    A non-concrete vendor returns the normalized product without loading
    the mapping. Otherwise a mapped key returns a new set of its packages
    and an unmapped key returns the decoded, lowercased product. Propagates
    `CPEMappingLoadError` and unexpected loader exceptions unchanged.
    """
    try:
        vendor, product = _parse_cpe(cpe_criteria)
    except _CPEParseError as exc:
        logger.warning("cpe_parse_failed", reason=exc.reason)
        return set()
    return _resolve(vendor, product)


def _normalize_free_text(value: str) -> str | None:
    """Trim, lowercase, and replace internal spaces with `_`.

    Returns `None` for an empty, `*`, or `-` normalized value.
    """
    normalized = value.strip().lower().replace(" ", "_")
    if normalized in _FREE_TEXT_NON_CONCRETE:
        return None
    return normalized


def resolve_vendor_product(vendor: str, product: str) -> set[str]:
    """Resolve a free-text CNA/ADP vendor/product pair to SUSE package names.

    Uses the same normalization outcome, mapping, and fallback as
    `resolve_cpe_packages()`, bypassing CPE string parsing. An empty, `*`,
    or `-` product returns an empty set; such a vendor returns the
    normalized product without loading the mapping. Propagates
    `CPEMappingLoadError` and unexpected loader exceptions unchanged.
    """
    return _resolve(_normalize_free_text(vendor), _normalize_free_text(product))
