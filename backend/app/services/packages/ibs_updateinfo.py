"""Incremental validation of IBS Product repository `updateinfo.xml`.

Implements docs/features/packages/ibs-product-release-detection.md:

- Source Authority conditions 2-6;
- Updateinfo and Advisory Validation (with Issued time);
- Exact Source-Package Match;
- the updateinfo rows of Resource and XML Safety (depth, total elements,
  `update` and `package` element counts).

The parser receives the decompressed document in chunks and keeps only
compact validated advisories, never the document. A document-level
failure (not complete safe XML, a root other than the no-namespace
`updates`, or a limit) raises `RepositoryDataError` and fails the
repository. A malformed advisory is ignored as a whole and counted.

The advisory contract applies to the advisories considered for a mutation:
the direct `update` children of the root with exact `type="security"` and
`status="stable"`. Every other advisory is never authoritative, so its
structure is not reported as malformed; its consumed content still takes
part in the duplicate-ID comparison, so a conflicting variant of a
security advisory's ID invalidates every variant.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final

from app.services.packages.ibs_repodata import (
    CANONICAL_UNSIGNED,
    RepositoryDataError,
)
from app.services.xml_safety import SafeXMLParser, XMLLimits, XMLSafetyError

UPDATEINFO_MAX_DEPTH: Final = 32
UPDATEINFO_MAX_ELEMENTS: Final = 1_000_000
UPDATEINFO_MAX_UPDATES: Final = 50_000
UPDATEINFO_MAX_PACKAGES: Final = 500_000

UPDATEINFO_LIMITS: Final = XMLLimits(
    max_depth=UPDATEINFO_MAX_DEPTH,
    max_elements=UPDATEINFO_MAX_ELEMENTS,
    max_element_counts={
        "update": UPDATEINFO_MAX_UPDATES,
        "package": UPDATEINFO_MAX_PACKAGES,
    },
)

_ADVISORY_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,254}")
_SOURCE_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
_UNSAFE_IDENTITY_CHARACTERS: Final = frozenset("/\\%?#")
_SOURCE_ARCHITECTURES: Final = frozenset({"src", "nosrc"})
_PACKAGE_ATTRIBUTES: Final = ("name", "epoch", "version", "release", "arch", "src")
_MAX_ID_TEXT: Final = 255

MAX_UTC_SECONDS: Final = 253_402_300_799
"""9999-12-31T23:59:59Z, the largest second a UTC `datetime` represents."""

_PackageEntry = tuple[
    str | None, str | None, str | None, str | None, str | None, str | None
]


@dataclass(frozen=True, slots=True)
class SecurityAdvisory:
    """One valid authoritative stable security advisory.

    `cve_ids` are the `id` values of exact `type="cve"` references;
    `source_names` are the validated `src`/`nosrc` package names.
    """

    advisory_id: str
    issued: int
    cve_ids: frozenset[str]
    source_names: frozenset[str]

    @property
    def issued_at(self) -> datetime:
        """The issued time as a UTC datetime."""
        return datetime.fromtimestamp(self.issued, UTC)


class UpdateinfoSnapshot:
    """The validated authoritative advisories of one updateinfo document.

    `malformed_advisory_count` counts the distinct stable security advisory
    IDs ignored as malformed (including IDs whose variants conflict) plus
    stable security advisories without a valid ID.
    """

    def __init__(
        self, advisories: Collection[SecurityAdvisory], *, malformed_advisory_count: int
    ) -> None:
        self.advisories: tuple[SecurityAdvisory, ...] = tuple(advisories)
        self.malformed_advisory_count = malformed_advisory_count
        by_cve: dict[str, list[SecurityAdvisory]] = {}
        for advisory in self.advisories:
            for cve_id in advisory.cve_ids:
                by_cve.setdefault(cve_id, []).append(advisory)
        self._by_cve = by_cve

    def match(self, cve_id: str, package_name: str) -> SecurityAdvisory | None:
        """The matching advisory with the earliest issued time, or `None`.

        Matching requires the exact CVE and an exact, case-sensitive
        source-package name. Equal issued times are resolved by the
        lexically smallest advisory ID.
        """
        matches = [
            advisory
            for advisory in self._by_cve.get(cve_id, ())
            if package_name in advisory.source_names
        ]
        if not matches:
            return None
        return min(matches, key=lambda item: (item.issued, item.advisory_id))


@dataclass(slots=True)
class _Update:
    """Consumed content of one `update` element while it is parsed."""

    status: str | None
    type: str | None
    ids: list[str] = field(default_factory=list)
    id_valid: bool = True
    issued: list[str | None] = field(default_factory=list)
    references_elements: int = 0
    pkglist_elements: int = 0
    references: set[tuple[str | None, str | None]] = field(default_factory=set)
    collections: int = 0
    packages: set[_PackageEntry] = field(default_factory=set)

    @property
    def considered(self) -> bool:
        return self.type == "security" and self.status == "stable"

    def fingerprint(self) -> bytes:
        """A digest of the consumed content, exact duplicates collapsed."""
        canonical = repr(
            (
                self.status,
                self.type,
                self.ids,
                self.id_valid,
                self.issued,
                self.references_elements,
                self.pkglist_elements,
                sorted(self.references, key=repr),
                self.collections,
                sorted(self.packages, key=repr),
            )
        )
        return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).digest()


@dataclass(slots=True)
class _Variants:
    """Every variant seen for one advisory ID."""

    fingerprint: bytes
    considered: bool
    malformed: bool
    advisory: SecurityAdvisory | None
    conflicting: bool = False


class _UpdateinfoHandler:
    # Depths: 1 `updates`, 2 `update`, 3 update children, 4 `reference` or
    # `collection`, 5 `package`. Names in a namespace never match.

    def __init__(
        self, *, metadata_timestamp: int, cve_filter: frozenset[str] | None
    ) -> None:
        self._metadata_timestamp = metadata_timestamp
        self._cve_filter = cve_filter
        self._depth = 0
        self._update: _Update | None = None
        self._section: str | None = None
        self._in_id = False
        self._id_text: list[str] = []
        self._id_length = 0
        self.variants: dict[str, _Variants] = {}
        self.unidentified_malformed = 0

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        self._depth += 1
        depth = self._depth
        if depth == 1:
            if name != "updates":
                raise RepositoryDataError("xml_structure")
            return
        update = self._update
        if self._in_id:
            assert update is not None
            update.id_valid = False
            return
        if depth == 2:
            if name == "update":
                self._update = _Update(
                    status=attributes.get("status"), type=attributes.get("type")
                )
            return
        if update is None:
            return
        if depth == 3:
            self._section = None
            if name == "id":
                self._in_id = True
                self._id_text = []
                self._id_length = 0
            elif name == "issued":
                update.issued.append(attributes.get("date"))
            elif name == "references":
                update.references_elements += 1
                self._section = "references"
            elif name == "pkglist":
                update.pkglist_elements += 1
                self._section = "pkglist"
        elif depth == 4:
            if self._section == "references" and name == "reference":
                update.references.add((attributes.get("type"), attributes.get("id")))
            elif self._section == "pkglist" and name == "collection":
                update.collections += 1
                self._section = "collection"
        elif depth == 5 and self._section == "collection" and name == "package":
            name_, epoch, version, release, arch, src = (
                attributes.get(key) for key in _PACKAGE_ATTRIBUTES
            )
            update.packages.add((name_, epoch, version, release, arch, src))

    def end_element(self, name: str) -> None:
        depth = self._depth
        self._depth -= 1
        update = self._update
        if self._in_id:
            if depth == 3:
                assert update is not None
                self._in_id = False
                if self._id_length > _MAX_ID_TEXT:
                    update.id_valid = False
                update.ids.append("".join(self._id_text))
            return
        if depth == 4 and self._section == "collection":
            self._section = "pkglist"
        elif depth == 3:
            self._section = None
        elif depth == 2 and update is not None:
            self._finish(update)
            self._update = None

    def character_data(self, data: str) -> None:
        if self._in_id and self._depth == 3:
            self._id_length += len(data)
            if self._id_length <= _MAX_ID_TEXT:
                self._id_text.append(data)

    def _finish(self, update: _Update) -> None:
        considered = update.considered
        advisory_id = (
            update.ids[0]
            if update.id_valid
            and len(update.ids) == 1
            and _ADVISORY_ID.fullmatch(update.ids[0])
            else None
        )
        if advisory_id is None:
            if considered:
                self.unidentified_malformed += 1
            return
        fingerprint = update.fingerprint()
        existing = self.variants.get(advisory_id)
        if existing is not None:
            # Identical consumed content yields an identical fingerprint and
            # therefore the same validity; only a difference matters.
            if existing.fingerprint != fingerprint:
                existing.conflicting = True
                existing.considered = existing.considered or considered
            return
        advisory = _validate(update, advisory_id, self._metadata_timestamp)
        if advisory is not None and self._cve_filter is not None:
            relevant = not advisory.cve_ids.isdisjoint(self._cve_filter)
        else:
            relevant = advisory is not None
        self.variants[advisory_id] = _Variants(
            fingerprint=fingerprint,
            considered=considered,
            malformed=considered and advisory is None,
            advisory=advisory if relevant else None,
        )


def _validate(
    update: _Update, advisory_id: str, metadata_timestamp: int
) -> SecurityAdvisory | None:
    """The authoritative advisory, or `None` if not considered or invalid."""
    if (
        not update.considered
        or len(update.issued) != 1
        or update.references_elements != 1
        or update.pkglist_elements != 1
        or not update.references
        or update.collections == 0
        or not update.packages
    ):
        return None
    issued = _issued_seconds(update.issued[0], metadata_timestamp)
    if issued is None:
        return None
    cve_ids: set[str] = set()
    for reference_type, reference_id in update.references:
        if not reference_type or not reference_id:
            return None
        if reference_type == "cve":
            cve_ids.add(reference_id)
    source_names: set[str] = set()
    for package in update.packages:
        if package[4] not in _SOURCE_ARCHITECTURES:
            continue
        name = _source_name(package)
        if name is None:
            return None
        source_names.add(name)
    return SecurityAdvisory(
        advisory_id=advisory_id,
        issued=issued,
        cve_ids=frozenset(cve_ids),
        source_names=frozenset(source_names),
    )


def _issued_seconds(value: str | None, metadata_timestamp: int) -> int | None:
    if not value or not CANONICAL_UNSIGNED.fullmatch(value):
        return None
    seconds = int(value)
    if seconds > MAX_UTC_SECONDS or seconds > metadata_timestamp:
        return None
    return seconds


def _is_safe_identity(value: str) -> bool:
    return value.isascii() and not any(
        character.isspace()
        or ord(character) < 0x20
        or ord(character) == 0x7F
        or character in _UNSAFE_IDENTITY_CHARACTERS
        for character in value
    )


def _source_name(package: _PackageEntry) -> str | None:
    """The validated source name of a `src`/`nosrc` entry, or `None`."""
    name, epoch, version, release, arch, src = package
    if not (name and epoch and version and release and arch and src):
        return None
    if not CANONICAL_UNSIGNED.fullmatch(epoch):
        return None
    if not all(_is_safe_identity(value) for value in (name, version, release, arch)):
        return None
    if not _SOURCE_NAME.fullmatch(name):
        return None
    if src != f"{arch}/{name}-{version}-{release}.{arch}.rpm":
        return None
    return name


class UpdateinfoParser:
    """Incremental parser of one decompressed `updateinfo.xml` document.

    `metadata_timestamp` is the updateinfo `timestamp` of the accepted
    repomd snapshot; an issued time after it invalidates the advisory.
    `cve_filter`, when given, limits the retained advisories to those
    referencing at least one of these CVEs; validation and the malformed
    count are unaffected.
    """

    def __init__(
        self, *, metadata_timestamp: int, cve_filter: Collection[str] | None = None
    ) -> None:
        self._handler = _UpdateinfoHandler(
            metadata_timestamp=metadata_timestamp,
            cve_filter=frozenset(cve_filter) if cve_filter is not None else None,
        )
        self._parser = SafeXMLParser(self._handler, limits=UPDATEINFO_LIMITS)

    def feed(self, data: bytes) -> None:
        """Parse the next decompressed chunk."""
        try:
            self._parser.feed(data)
        except XMLSafetyError as exc:
            raise _document_error(exc) from None

    def close(self) -> UpdateinfoSnapshot:
        """Finalize the document and return the validated snapshot."""
        try:
            self._parser.close()
        except XMLSafetyError as exc:
            raise _document_error(exc) from None
        handler = self._handler
        advisories: list[SecurityAdvisory] = []
        malformed = handler.unidentified_malformed
        for variants in handler.variants.values():
            if variants.conflicting or variants.malformed:
                if variants.considered:
                    malformed += 1
            elif variants.advisory is not None:
                advisories.append(variants.advisory)
        return UpdateinfoSnapshot(advisories, malformed_advisory_count=malformed)


def _document_error(exc: XMLSafetyError) -> RepositoryDataError:
    if exc.reason == "resource_limit":
        return RepositoryDataError("resource_limit")
    return RepositoryDataError("xml_structure")
