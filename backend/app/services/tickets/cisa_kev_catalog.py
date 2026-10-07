"""Pure parsing of the CISA KEV catalog.

Implements docs/features/tickets/cve-sync-kev.md (Algorithm steps 2, 3a,
and 3d; Field Mapping) for the decoded body of one catalog download. The
module performs no HTTP, database, or logging work; `SyncCisaKev`
(`sync_cisa_kev.py`) owns the download, the per-entry boundary, and the
ingestion.

- `parse_catalog()` validates the catalog structure only: a JSON object
  whose `vulnerabilities` is a list. Entries stay raw so that each is
  validated inside its own per-entry boundary.
- `entry_cve_id()` returns an entry's raw `cveID`, or `None` when the
  entry is not an object; the caller applies the canonical CVE-ID check.
- `extract()` converts one entry of an existing CVE into its `KEVEntry`
  and collapsed `CWEEntry` list. No received string reaches PostgreSQL
  unvalidated: `dateAdded` must be a `YYYY-MM-DD` string naming a
  calendar date, and each CWE must match the `CWEEntry` contract, which
  rejects U+0000 (docs/conventions.md, External String Admissibility).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Final

from pydantic import ValidationError

from app.services.cve_ingest import CWEEntry, KEVEntry

CWE_SOURCE: Final = "CISA KEV"
"""The `CWEEntry.source` of every KEV CWE classification."""

_DATE_ADDED_PATTERN: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
"""`YYYY-MM-DD`, matched in full; the calendar check is `date`'s."""


class KevCatalogStructureError(ValueError):
    """The catalog is not an object with a `vulnerabilities` list."""

    def __init__(self) -> None:
        super().__init__("CISA KEV catalog has unexpected structure")


class InvalidDateAddedError(ValueError):
    """An entry's `dateAdded` is missing or not a `YYYY-MM-DD` calendar date."""

    def __init__(self) -> None:
        super().__init__("CISA KEV entry has an invalid dateAdded")


class InvalidCwesError(ValueError):
    """An entry's `cwes` is present but neither `null` nor a list."""

    def __init__(self) -> None:
        super().__init__("CISA KEV entry has a non-list cwes")


@dataclass(frozen=True, slots=True)
class KevCatalog:
    """The validated catalog structure.

    `count` is the `count` member when it is an integer, else `None`;
    `entries` are the raw `vulnerabilities` items in catalog order.
    """

    count: int | None
    entries: list[object]


@dataclass(frozen=True, slots=True)
class KevEnrichment:
    """The ingestible data of one entry.

    `cwe_classifications` holds the accepted CWEs in first-occurrence
    order with identical IDs collapsed; `skipped_cwes` counts the rejected
    `cwes` items, each of which the caller logs once.
    """

    kev_entry: KEVEntry
    cwe_classifications: list[CWEEntry]
    skipped_cwes: int


def parse_catalog(document: object) -> KevCatalog:
    """Validate the catalog structure (Algorithm step 2).

    Raises `KevCatalogStructureError` when `document` is not an object or
    its `vulnerabilities` is missing or not a list. An absent or
    non-integer `count` (including a boolean) yields `count = None` and
    never raises.
    """
    if not isinstance(document, dict):
        raise KevCatalogStructureError()
    entries = document.get("vulnerabilities")
    if not isinstance(entries, list):
        raise KevCatalogStructureError()
    count = document.get("count")
    if not isinstance(count, int) or isinstance(count, bool):
        count = None
    return KevCatalog(count=count, entries=entries)


def entry_cve_id(entry: object) -> object:
    """The raw `cveID` of an entry, or `None` when `entry` is not an object.

    The value is untrusted; the caller validates it with the canonical
    CVE-ID check before any database work (Algorithm step 3a).
    """
    if not isinstance(entry, dict):
        return None
    return entry.get("cveID")


def extract(entry: dict[str, object], *, reference_url: str) -> KevEnrichment:
    """Convert one entry of an existing CVE (Algorithm step 3d).

    `entry` is the catalog object whose `cveID` already passed the
    canonical check; `reference_url` is the constructed per-CVE URL.

    Raises `InvalidDateAddedError` for a missing, non-string, mis-encoded,
    or non-calendar `dateAdded`, and `InvalidCwesError` for a `cwes` that
    is present but neither `null` nor a list. A non-string or
    non-canonical `cwes` item is skipped and counted.
    """
    kev_entry = KEVEntry(
        date_added=_date_added(entry.get("dateAdded")),
        reference_url=reference_url,
    )
    cwes = entry.get("cwes")
    if cwes is None:
        return KevEnrichment(kev_entry, [], 0)
    if not isinstance(cwes, list):
        raise InvalidCwesError()
    accepted: dict[str, CWEEntry] = {}
    skipped = 0
    for value in cwes:
        cwe = _cwe_entry(value)
        if cwe is None:
            skipped += 1
        else:
            accepted.setdefault(cwe.cwe_id, cwe)
    return KevEnrichment(kev_entry, list(accepted.values()), skipped)


def _date_added(value: object) -> date:
    if not isinstance(value, str) or not _DATE_ADDED_PATTERN.fullmatch(value):
        raise InvalidDateAddedError()
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise InvalidDateAddedError() from None


def _cwe_entry(value: object) -> CWEEntry | None:
    if not isinstance(value, str):
        return None
    try:
        return CWEEntry(cwe_id=value, source=CWE_SOURCE)
    except ValidationError:
        return None
