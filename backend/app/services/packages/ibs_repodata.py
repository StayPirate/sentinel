"""IBS Product repository names, paths, and `repomd.xml` validation.

Pure functions of the IBS Product repository download boundary
(docs/features/packages/ibs-product-release-detection.md):

- Download Origin and Repository Paths > Repository qualification and URL
  construction: which retained `ProductRepository.repo_name` values are
  requested, and the URL built from their validated segments;
- Repository Traversal: the deterministic order within one tier;
- Download Origin and Repository Paths > Artifact location: validation of
  the updateinfo `location/@href`;
- Repomd Contract (with Checksums) and the `repomd.xml` rows of Resource
  and XML Safety: the updateinfo identity tuple of a complete document.

`RepositoryDataError` carries the bounded failure category shared by the
whole boundary (Irreversibility, Audit, and Observability:
`reason_category`). No function performs I/O.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

from app.services.xml_safety import (
    NAMESPACE_SEPARATOR,
    SafeXMLParser,
    XMLLimits,
    XMLSafetyError,
)

RepositoryFailureCategory = Literal[
    "transport",
    "timeout",
    "http_status",
    "redirect",
    "unsafe_path",
    "content_type",
    "size",
    "checksum",
    "gzip",
    "xml_structure",
    "resource_limit",
    "snapshot_changed",
]
"""Why one repository examination did not complete."""


class RepositoryDataError(Exception):
    """A repository examination failed with a bounded category.

    The message never contains upstream content, a URL, or configuration.
    """

    def __init__(
        self, category: RepositoryFailureCategory, *, http_status: int | None = None
    ) -> None:
        super().__init__(f"IBS Product repository failure: {category}")
        self.category: RepositoryFailureCategory = category
        self.http_status = http_status


# --- Resource limits (fixed engineering constants) -------------------------

REPOMD_MAX_BYTES: Final = 64 * 1024
REPOMD_MAX_DEPTH: Final = 16
REPOMD_MAX_ELEMENTS: Final = 10_000
UPDATEINFO_MAX_COMPRESSED_BYTES: Final = 32 * 1024 * 1024
UPDATEINFO_MAX_OPEN_BYTES: Final = 256 * 1024 * 1024
UPDATEINFO_MAX_RATIO: Final = 100

# --- Repository names --------------------------------------------------------

_REPOSITORY_PREFIX: Final = "SUSE:Updates:"
_SEGMENT: Final = re.compile(r"[A-Za-z0-9._+-]+")
_EXCLUDED_TERMINAL_SEGMENTS: Final = frozenset({"debug", "src"})
_NON_RPM_TARGETS: Final = ("Debian", "Ubuntu")

RECOGNIZED_ARCHITECTURES: Final = frozenset(
    {"aarch64", "i586", "i686", "ia64", "ppc64", "ppc64le", "s390x", "x86_64"}
)


def qualify_repository_name(repo_name: str) -> tuple[str, ...] | None:
    """Return the validated colon-separated segments, or `None`.

    `None` means the name is not a candidate and is never requested: it
    does not start with `SUSE:Updates:`, a segment is empty or outside
    `[A-Za-z0-9._+-]+`, the terminal segment is `debug` or `src`, or a
    segment identifies a Debian or Ubuntu target (exactly `Debian` or
    `Ubuntu`, or beginning with `Debian-` or `Ubuntu-`).
    """
    if not repo_name.startswith(_REPOSITORY_PREFIX):
        return None
    segments = tuple(repo_name.split(":"))
    if not all(_SEGMENT.fullmatch(segment) for segment in segments):
        return None
    if segments[-1] in _EXCLUDED_TERMINAL_SEGMENTS:
        return None
    for segment in segments:
        for target in _NON_RPM_TARGETS:
            if segment == target or segment.startswith(f"{target}-"):
                return None
    return segments


def repository_root_url(base_url: str, segments: tuple[str, ...]) -> str:
    """The repository root: validated base, `/`-joined segments, `/update`.

    `base_url` is the validated, canonicalized `IBS_DOWNLOAD_BASE_URL`
    (no trailing slash); `segments` come from `qualify_repository_name()`.
    """
    return f"{base_url}/{'/'.join(segments)}/update"


def order_tier(repo_names: Iterable[str]) -> list[str]:
    """Qualified, distinct repository names of one tier in traversal order.

    Names without a recognized terminal architecture come first in lexical
    order, then terminal `x86_64` names in lexical order, then the other
    recognized architectures in lexical architecture order with the name
    as final tiebreaker. Unqualified names are dropped.
    """

    def key(name: str) -> tuple[int, str, str]:
        architecture = name.rsplit(":", 1)[-1]
        if architecture not in RECOGNIZED_ARCHITECTURES:
            return (0, "", name)
        if architecture == "x86_64":
            return (1, "", name)
        return (2, architecture, name)

    qualified = {name for name in repo_names if qualify_repository_name(name)}
    return sorted(qualified, key=key)


# --- Artifact location -------------------------------------------------------

_LOCATION_PREFIX: Final = "repodata/"


def validate_artifact_location(href: str) -> str:
    """Return `href` unchanged if it is a safe relative repodata path.

    It must begin with `repodata/` followed by at least one segment, every
    segment must be non-empty, neither `.` nor `..`, and match
    `[A-Za-z0-9._+-]+`. This excludes a scheme, authority, leading slash,
    backslash, percent escape, query, fragment, control character, and
    duplicate separator, so resolving it against the repository root stays
    below that root. Anything else raises `RepositoryDataError`
    (`unsafe_path`); alternatives are rejected rather than repaired.
    """
    segments = href.split("/")
    if (
        not href.startswith(_LOCATION_PREFIX)
        or len(segments) < 2
        or any(
            segment in (".", "..") or not _SEGMENT.fullmatch(segment)
            for segment in segments
        )
    ):
        raise RepositoryDataError("unsafe_path")
    return href


# --- Repomd ------------------------------------------------------------------

REPOMD_NAMESPACE: Final = "http://linux.duke.edu/metadata/repo"

_ROOT: Final = f"{REPOMD_NAMESPACE}{NAMESPACE_SEPARATOR}repomd"
_DATA: Final = f"{REPOMD_NAMESPACE}{NAMESPACE_SEPARATOR}data"
_FIELDS: Final = (
    "location",
    "checksum",
    "open-checksum",
    "size",
    "open-size",
    "timestamp",
)
_FIELD_NAMES: Final = {
    f"{REPOMD_NAMESPACE}{NAMESPACE_SEPARATOR}{field}": field for field in _FIELDS
}
_TEXT_FIELDS: Final = frozenset(_FIELDS) - {"location"}
_MAX_FIELD_TEXT: Final = 128

CHECKSUM_ALGORITHMS: Final = {"sha256": ("sha256", 64), "sha": ("sha1", 40)}
"""Accepted repomd checksum names: hashlib name and hexadecimal length."""

_HEX: Final = re.compile(r"[0-9A-Fa-f]+")
CANONICAL_UNSIGNED: Final = re.compile(r"0|[1-9][0-9]*")
"""Canonical unsigned decimal: no sign, fraction, whitespace, or leading
zero."""


@dataclass(frozen=True, slots=True)
class UpdateinfoIdentity:
    """The updateinfo identity tuple of one `repomd.xml` snapshot.

    Checksum values are lowercase; two snapshots are consistent when their
    identities are equal (Snapshot Consistency, step 4).
    """

    location: str
    checksum_type: str
    checksum: str
    open_checksum_type: str
    open_checksum: str
    size: int
    open_size: int
    timestamp: int


class _RepomdHandler:
    def __init__(self) -> None:
        self.entries: list[dict[str, list[tuple[dict[str, str], str]]]] = []
        self._stack: list[str] = []
        self._entry: dict[str, list[tuple[dict[str, str], str]]] | None = None
        self._field: str | None = None
        self._field_attributes: dict[str, str] = {}
        self._text: list[str] = []
        self._text_length = 0
        self._field_has_child = False

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        depth = len(self._stack)
        if depth == 0 and name != _ROOT:
            raise RepositoryDataError("xml_structure")
        if depth == 1 and name == _DATA and attributes.get("type") == "updateinfo":
            self._entry = {}
            self.entries.append(self._entry)
        elif depth == 2 and self._entry is not None and name in _FIELD_NAMES:
            self._field = _FIELD_NAMES[name]
            self._field_attributes = attributes
            self._text = []
            self._text_length = 0
            self._field_has_child = False
        elif depth >= 3 and self._field is not None:
            self._field_has_child = True
        self._stack.append(name)

    def end_element(self, name: str) -> None:
        self._stack.pop()
        depth = len(self._stack)
        if depth == 2 and self._field is not None and self._entry is not None:
            if self._field_has_child and self._field in _TEXT_FIELDS:
                raise RepositoryDataError("xml_structure")
            text = "".join(self._text)
            self._entry.setdefault(self._field, []).append(
                (self._field_attributes, text)
            )
            self._field = None
        elif depth == 1:
            self._entry = None

    def character_data(self, data: str) -> None:
        if self._field is not None and len(self._stack) == 3:
            self._text_length += len(data)
            if self._text_length > _MAX_FIELD_TEXT:
                raise RepositoryDataError("xml_structure")
            self._text.append(data)


def _single(
    entry: dict[str, list[tuple[dict[str, str], str]]], field: str
) -> tuple[dict[str, str], str]:
    values = entry.get(field, [])
    if len(values) != 1:
        raise RepositoryDataError("xml_structure")
    return values[0]


def _unsigned(entry: dict[str, list[tuple[dict[str, str], str]]], field: str) -> int:
    _, text = _single(entry, field)
    if not CANONICAL_UNSIGNED.fullmatch(text):
        raise RepositoryDataError("xml_structure")
    return int(text)


def _checksum(
    entry: dict[str, list[tuple[dict[str, str], str]]], field: str
) -> tuple[str, str]:
    attributes, text = _single(entry, field)
    algorithm = CHECKSUM_ALGORITHMS.get(attributes.get("type", ""))
    if algorithm is None:
        raise RepositoryDataError("checksum")
    if len(text) != algorithm[1] or not _HEX.fullmatch(text):
        raise RepositoryDataError("checksum")
    return attributes["type"], text.lower()


def parse_repomd(content: bytes) -> UpdateinfoIdentity | None:
    """Validate a complete `repomd.xml` and return its updateinfo identity.

    Returns `None` when the document has no `data` child of type
    `updateinfo` in the repomd namespace (a successful non-match). Raises
    `RepositoryDataError` for a document that is not complete, safe XML
    within the repomd limits (`xml_structure`, `resource_limit`), for a
    root other than `repomd` in the exact namespace or more than one
    updateinfo entry (`xml_structure`), and for a missing, duplicate,
    empty, or malformed consumed field: location (`unsafe_path`),
    checksums (`checksum`), sizes and timestamp (`xml_structure`), or sizes
    outside the fixed limits (`size` for a zero compressed size,
    `resource_limit` otherwise). Unknown non-consumed elements and
    attributes are ignored.
    """
    handler = _RepomdHandler()
    parser = SafeXMLParser(
        handler,
        limits=XMLLimits(max_depth=REPOMD_MAX_DEPTH, max_elements=REPOMD_MAX_ELEMENTS),
    )
    try:
        parser.feed(content)
        parser.close()
    except XMLSafetyError as exc:
        category: RepositoryFailureCategory = (
            "resource_limit" if exc.reason == "resource_limit" else "xml_structure"
        )
        raise RepositoryDataError(category) from None
    if not handler.entries:
        return None
    if len(handler.entries) > 1:
        raise RepositoryDataError("xml_structure")
    entry = handler.entries[0]

    location_attributes, _ = _single(entry, "location")
    location = validate_artifact_location(location_attributes.get("href", ""))
    checksum_type, checksum = _checksum(entry, "checksum")
    open_checksum_type, open_checksum = _checksum(entry, "open-checksum")
    size = _unsigned(entry, "size")
    open_size = _unsigned(entry, "open-size")
    timestamp = _unsigned(entry, "timestamp")

    if size == 0:
        raise RepositoryDataError("size")
    if (
        size > UPDATEINFO_MAX_COMPRESSED_BYTES
        or open_size > UPDATEINFO_MAX_OPEN_BYTES
        or open_size > size * UPDATEINFO_MAX_RATIO
    ):
        raise RepositoryDataError("resource_limit")
    return UpdateinfoIdentity(
        location=location,
        checksum_type=checksum_type,
        checksum=checksum,
        open_checksum_type=open_checksum_type,
        open_checksum=open_checksum,
        size=size,
        open_size=open_size,
        timestamp=timestamp,
    )
