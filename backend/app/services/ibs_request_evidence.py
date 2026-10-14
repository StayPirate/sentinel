"""Typed records, field contracts, and parsers of the IBS request evidence.

Implements the parsing and form contracts of
docs/features/integrations/ibs-integration.md (Request ID Search, Request
Point Detail, Request Action Diff, Package Source History, Service Layer >
IBSClient) used by `IBSClient.search_request_ids()`, `get_request()`,
`get_request_action_diff()`, and `get_source_history()`. The records and
predicates are re-exported by `app.services.ibs_client`; the handlers and
the diff-form derivation are internal to `IBSClient`.

Each handler receives the events of `app.services.xml_safety.SafeXMLParser`.
It raises `IncompleteEvidenceError` with one bounded reason as soon as the
document can no longer be complete evidence, and otherwise returns its typed
value from `result()` once the complete document has parsed. Handlers
retain only consumed values: actors, free text, and unconsumed elements are
never stored, and no exception carries response content. Project values
outside the `SUSE:` namespace never leave the point-detail parser: they are
replaced by `REDACTED_PROJECT` after validation, before semantic identities
are built. Numbers are parsed only after an ASCII pattern check and never
raise from a handler.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final, Literal, Protocol

from app.core.enums import IBSRequestActionType, IBSRequestState

__all__ = [
    "REDACTED_PROJECT",
    "AcceptInfo",
    "IBSRequestActionDetail",
    "IBSRequestDetail",
    "IncompleteReason",
    "RequestActionDiff",
    "RequestActionIssue",
    "RequestEvidenceResult",
    "RequestIdSearchResult",
    "SourceHistory",
    "SourceHistoryEntry",
    "is_valid_ibs_name",
    "is_valid_request_revision",
]

IncompleteReason = Literal[
    "malformed_xml",
    "interrupted_response",
    "invalid_document",
    "not_found",
    "rejected",
    "count_mismatch",
    "duplicate_identity",
    "invalid_entry",
    "invalid_state",
    "unknown_action_type",
    "invalid_action",
    "invalid_issue",
    "missing_diff_input",
    "outside_suse_namespace",
    "history_unavailable",
]
"""Why request evidence is incomplete (one bounded value per result)."""

REDACTED_PROJECT: Final = "_redacted_"
"""Stored form of every consumed project outside the `SUSE:` namespace."""

SUSE_NAMESPACE: Final = "SUSE:"

_IBS_NAME: Final = re.compile(r"[A-Za-z0-9_.:+\-]{1,255}")
_DOT_SEGMENTS: Final = frozenset({".", ".."})
_DECIMAL: Final = re.compile(r"[1-9][0-9]*")
_NON_NEGATIVE: Final = re.compile(r"0|[1-9][0-9]*")
_CHECKSUM: Final = re.compile(r"[0-9a-f]{32}")
_TIMESTAMP: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2})?"
)
_MAX_FIELD_TEXT: Final = 64
"""Characters retained from a history child; longer text is never valid."""

_SUPPORTED_TYPES: Final = frozenset(member.value for member in IBSRequestActionType)
_IGNORED_TYPES: Final = frozenset(
    {"submit", "delete", "add_role", "set_bugowner", "change_devel", "release"}
)
_STATES: Final = frozenset(member.value for member in IBSRequestState)
_ACCEPTINFO_CHECKSUMS: Final = ("srcmd5", "xsrcmd5", "osrcmd5", "oxsrcmd5")


class IncompleteEvidenceError(Exception):
    """Internal signal: the response is not complete request evidence.

    Carries one bounded `reason` and never response content. Converted to
    an incomplete `RequestEvidenceResult` by `IBSClient`; it never escapes
    an operation.
    """

    def __init__(self, reason: IncompleteReason) -> None:
        super().__init__(f"IBS request evidence incomplete: {reason}")
        self.reason: IncompleteReason = reason


# ---------------------------------------------------------------------------
# Field contracts
# ---------------------------------------------------------------------------


def is_valid_ibs_name(value: object) -> bool:
    """Whether `value` is an IBS name (ibs-integration.md, Request Point
    Detail): 1 to 255 ASCII letters, digits, `_`, `.`, `:`, `+`, or `-`,
    and neither `.` nor `..`. Pure predicate."""
    return (
        isinstance(value, str)
        and _IBS_NAME.fullmatch(value) is not None
        and value not in _DOT_SEGMENTS
    )


def is_valid_request_revision(value: object) -> bool:
    """Whether `value` is a positive decimal revision number without leading
    zeros or a lowercase 32-character hexadecimal checksum. Pure
    predicate."""
    return isinstance(value, str) and (
        _DECIMAL.fullmatch(value) is not None or _CHECKSUM.fullmatch(value) is not None
    )


def is_lowercase_checksum(value: object) -> bool:
    """Whether `value` is a lowercase 32-character hexadecimal checksum."""
    return isinstance(value, str) and _CHECKSUM.fullmatch(value) is not None


def positive_int(value: str | None) -> int | None:
    """`value` as a positive integer, or `None` when it is absent or not a
    canonical positive decimal number."""
    if value is None or _DECIMAL.fullmatch(value) is None:
        return None
    try:
        return int(value)
    except ValueError:  # beyond the interpreter's integer-string limit
        return None


def _non_negative_int(value: str | None) -> int | None:
    if value is None or _NON_NEGATIVE.fullmatch(value) is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _request_timestamp(value: str | None) -> datetime | None:
    """An IBS request timestamp as an aware UTC datetime: offset-less values
    are UTC, an explicit offset is normalized; anything else is `None`."""
    if value is None or _TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError, OverflowError:  # an invalid date or an offset beyond range
        return None


def _unix_time(value: str | None) -> datetime | None:
    seconds = _non_negative_int(value)
    if seconds is None:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except OverflowError, OSError, ValueError:
        return None


def _stored_project(value: str) -> str:
    return value if value.startswith(SUSE_NAMESPACE) else REDACTED_PROJECT


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RequestEvidenceResult[T]:
    """Exactly one of a complete typed `value` or a bounded
    `incomplete_reason`. An incomplete result is not an exception and is
    not a successful negative observation."""

    value: T | None = None
    incomplete_reason: IncompleteReason | None = None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.incomplete_reason is None):
            msg = (
                "RequestEvidenceResult needs exactly one of value and incomplete_reason"
            )
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RequestIdSearchResult:
    """A complete ID search: distinct request numbers in ascending order
    (upstream order is not numeric) and the reported match count."""

    request_numbers: tuple[int, ...]
    matches: int


@dataclass(frozen=True, slots=True)
class AcceptInfo:
    """The consumed `acceptinfo` attributes of one action.

    `rev` and `srcmd5` are provenance; the others are diff inputs only.
    Absent attributes are `None`. `oproject` is already in the stored form.
    """

    rev: str | None = None
    srcmd5: str | None = None
    xsrcmd5: str | None = None
    osrcmd5: str | None = None
    oxsrcmd5: str | None = None
    oproject: str | None = None
    opackage: str | None = None


@dataclass(frozen=True, slots=True)
class IBSRequestActionDetail:
    """One supported action of a complete request detail.

    Projects are in the stored form (`REDACTED_PROJECT` outside `SUSE:`);
    absent optional values are `None`, never `""`. `acceptinfo` is present
    exactly when the action has an `<acceptinfo>` element, which selects the
    accepted form of the request action diff.
    """

    request_number: int
    action_type: IBSRequestActionType
    source_project: str
    source_package: str
    source_revision: str | None = None
    target_project: str | None = None
    target_package: str | None = None
    target_release_project: str | None = None
    acceptinfo: AcceptInfo | None = None


@dataclass(frozen=True, slots=True)
class IBSRequestDetail:
    """One complete request detail with every supported action, in
    document order. Timestamps are aware UTC datetimes."""

    request_number: int
    state: IBSRequestState
    upstream_created_at: datetime
    upstream_updated_at: datetime
    superseded_by_request_number: int | None
    actions: tuple[IBSRequestActionDetail, ...]


@dataclass(frozen=True, slots=True)
class RequestActionIssue:
    """One issue reference of a request action diff, as served: `tracker`
    and `state` are non-empty; `name` and `label` may be absent. Nothing is
    filtered or reinterpreted."""

    tracker: str
    state: str
    name: str | None
    label: str | None


@dataclass(frozen=True, slots=True)
class RequestActionDiff:
    """The issues of one complete request action diff, in document order,
    duplicates included."""

    issues: tuple[RequestActionIssue, ...]


@dataclass(frozen=True, slots=True)
class SourceHistoryEntry:
    """One source-history revision; `request_number` is `None` when the
    revision has no `requestid`."""

    revision: int
    srcmd5: str
    time: datetime
    request_number: int | None


@dataclass(frozen=True, slots=True)
class SourceHistory:
    """The entries of one complete history or exact lookup, ascending."""

    entries: tuple[SourceHistoryEntry, ...]


class EvidenceHandler[T](Protocol):
    """A `SafeXMLParser` content handler that yields a typed value."""

    def start_element(self, name: str, attributes: dict[str, str]) -> None: ...

    def end_element(self, name: str) -> None: ...

    def character_data(self, data: str) -> None: ...

    def result(self) -> T: ...


# ---------------------------------------------------------------------------
# Request ID search
# ---------------------------------------------------------------------------


@dataclass
class SearchHandler:
    """Parses a `<collection matches>` of `<request id>` entries."""

    _depth: int = 0
    _matches: int | None = None
    _ids: list[int] = field(default_factory=list)

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        self._depth += 1
        if self._depth == 1:
            if name != "collection":
                raise IncompleteEvidenceError("invalid_document")
            self._matches = _non_negative_int(attributes.get("matches"))
            if self._matches is None:
                raise IncompleteEvidenceError("invalid_document")
        elif self._depth == 2:
            request_number = positive_int(attributes.get("id"))
            if name != "request" or request_number is None:
                raise IncompleteEvidenceError("invalid_entry")
            self._ids.append(request_number)

    def end_element(self, name: str) -> None:
        self._depth -= 1

    def character_data(self, data: str) -> None:
        return None

    def result(self) -> RequestIdSearchResult:
        if self._matches is None:
            raise IncompleteEvidenceError("invalid_document")
        if len(set(self._ids)) != len(self._ids):
            raise IncompleteEvidenceError("duplicate_identity")
        if len(self._ids) != self._matches:
            raise IncompleteEvidenceError("count_mismatch")
        return RequestIdSearchResult(tuple(sorted(self._ids)), self._matches)


# ---------------------------------------------------------------------------
# Request point detail
# ---------------------------------------------------------------------------

_ACTION_ELEMENTS: Final = {
    "source": ("project", "package", "rev"),
    "target": ("project", "package", "releaseproject"),
    "acceptinfo": ("rev", *_ACCEPTINFO_CHECKSUMS, "oproject", "opackage"),
}
_REQUIRED_FIELDS: Final = {
    IBSRequestActionType.MAINTENANCE_INCIDENT: (
        ("source", "project"),
        ("source", "package"),
        ("target", "releaseproject"),
    ),
    IBSRequestActionType.MAINTENANCE_RELEASE: (
        ("source", "project"),
        ("source", "package"),
        ("target", "project"),
        ("target", "package"),
    ),
}


@dataclass
class _ActionFields:
    action_type: IBSRequestActionType
    elements: dict[str, dict[str, str]] = field(default_factory=dict)


def _build_action(request_number: int, fields: _ActionFields) -> IBSRequestActionDetail:
    """Validate one supported action and return it in the stored form."""
    elements = fields.elements
    for element, attribute in _REQUIRED_FIELDS[fields.action_type]:
        if attribute not in elements.get(element, {}):
            raise IncompleteEvidenceError("invalid_action")
    source = elements.get("source", {})
    target = elements.get("target", {})
    for values, attributes in (
        (source, ("project", "package")),
        (target, ("project", "package", "releaseproject")),
        (elements.get("acceptinfo", {}), ("oproject", "opackage")),
    ):
        for attribute in attributes:
            if attribute in values and not is_valid_ibs_name(values[attribute]):
                raise IncompleteEvidenceError("invalid_action")
    source_revision = source.get("rev")
    if source_revision is not None and not is_valid_request_revision(source_revision):
        raise IncompleteEvidenceError("invalid_action")
    acceptinfo: AcceptInfo | None = None
    if "acceptinfo" in elements:
        accepted = elements["acceptinfo"]
        if "rev" in accepted and positive_int(accepted["rev"]) is None:
            raise IncompleteEvidenceError("invalid_action")
        for attribute in _ACCEPTINFO_CHECKSUMS:
            if attribute in accepted and not is_lowercase_checksum(accepted[attribute]):
                raise IncompleteEvidenceError("invalid_action")
        oproject = accepted.get("oproject")
        acceptinfo = AcceptInfo(
            rev=accepted.get("rev"),
            srcmd5=accepted.get("srcmd5"),
            xsrcmd5=accepted.get("xsrcmd5"),
            osrcmd5=accepted.get("osrcmd5"),
            oxsrcmd5=accepted.get("oxsrcmd5"),
            oproject=None if oproject is None else _stored_project(oproject),
            opackage=accepted.get("opackage"),
        )
    target_project = target.get("project")
    release_project = target.get("releaseproject")
    return IBSRequestActionDetail(
        request_number=request_number,
        action_type=fields.action_type,
        source_project=_stored_project(source["project"]),
        source_package=source["package"],
        source_revision=source_revision,
        target_project=None
        if target_project is None
        else _stored_project(target_project),
        target_package=target.get("package"),
        target_release_project=(
            None if release_project is None else _stored_project(release_project)
        ),
        acceptinfo=acceptinfo,
    )


def semantic_identity(action: IBSRequestActionDetail) -> tuple[object, ...]:
    """The durable semantic identity of ibs-integration.md (Request Point
    Detail), over the stored form."""
    if action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT:
        return (
            action.request_number,
            action.action_type,
            action.source_project,
            action.source_package,
            action.target_release_project,
        )
    return (
        action.request_number,
        action.action_type,
        action.target_project,
        action.target_package,
    )


@dataclass
class RequestDetailHandler:
    """Parses one `<request>` point detail for `request_number`."""

    request_number: int
    _depth: int = 0
    _states: int = 0
    _state: IBSRequestState | None = None
    _created: datetime | None = None
    _updated: datetime | None = None
    _superseded_by: int | None = None
    _actions: list[IBSRequestActionDetail] = field(default_factory=list)
    _action: _ActionFields | None = None

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        self._depth += 1
        if self._depth == 1:
            if (
                name != "request"
                or positive_int(attributes.get("id")) != self.request_number
            ):
                raise IncompleteEvidenceError("invalid_document")
        elif self._depth == 2:
            if name == "state":
                self._states += 1
                if self._states > 1:
                    raise IncompleteEvidenceError("invalid_document")
                self._read_state(attributes)
            elif name == "action":
                action_type = attributes.get("type")
                if action_type is not None and action_type in _SUPPORTED_TYPES:
                    self._action = _ActionFields(IBSRequestActionType(action_type))
                elif action_type not in _IGNORED_TYPES:
                    raise IncompleteEvidenceError("unknown_action_type")
        elif self._depth == 3 and self._action is not None:
            consumed = _ACTION_ELEMENTS.get(name)
            if consumed is not None:
                if name in self._action.elements:
                    raise IncompleteEvidenceError("invalid_action")
                self._action.elements[name] = {
                    key: attributes[key] for key in consumed if key in attributes
                }

    def end_element(self, name: str) -> None:
        if self._depth == 2 and self._action is not None:
            self._actions.append(_build_action(self.request_number, self._action))
            self._action = None
        self._depth -= 1

    def character_data(self, data: str) -> None:
        return None

    def _read_state(self, attributes: Mapping[str, str]) -> None:
        name = attributes.get("name")
        if name not in _STATES:
            raise IncompleteEvidenceError("invalid_state")
        self._state = IBSRequestState(name)
        self._created = _request_timestamp(attributes.get("created"))
        self._updated = _request_timestamp(attributes.get("when"))
        if self._created is None or self._updated is None:
            raise IncompleteEvidenceError("invalid_state")
        raw_successor = attributes.get("superseded_by")
        if self._state is IBSRequestState.SUPERSEDED:
            self._superseded_by = positive_int(raw_successor)
            if (
                self._superseded_by is None
                or self._superseded_by == self.request_number
            ):
                raise IncompleteEvidenceError("invalid_state")
        elif raw_successor is not None:
            raise IncompleteEvidenceError("invalid_state")

    def result(self) -> IBSRequestDetail:
        if (
            self._states != 1
            or self._state is None
            or self._created is None
            or self._updated is None
        ):
            raise IncompleteEvidenceError("invalid_document")
        identities = [semantic_identity(action) for action in self._actions]
        if len(set(identities)) != len(identities):
            raise IncompleteEvidenceError("duplicate_identity")
        return IBSRequestDetail(
            request_number=self.request_number,
            state=self._state,
            upstream_created_at=self._created,
            upstream_updated_at=self._updated,
            superseded_by_request_number=self._superseded_by,
            actions=tuple(self._actions),
        )


# ---------------------------------------------------------------------------
# Request action diff form
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DiffForm:
    """The path package and the form parameters of one request action diff."""

    project: str
    package: str
    params: tuple[tuple[str, str], ...]


def request_action_diff_form(
    action: IBSRequestActionDetail, codestream_package: str
) -> DiffForm:
    """Derive the form of ibs-integration.md (Request Action Diff).

    Accepted (acceptinfo present): the target package, `rev` = `xsrcmd5`
    or `srcmd5`, `orev` = `oxsrcmd5`, `osrcmd5`, or `0`, plus `oproject`
    and `opackage` when present, without `expand`. Not accepted: the source
    package with `expand=1`, `rev` = `source/@rev`, `oproject` = the
    codestream, and `opackage` = `codestream_package`. Raises
    `IncompleteEvidenceError` with `missing_diff_input` for an absent form input
    and `outside_suse_namespace` for a path project or `oproject` outside
    `SUSE:`, so that no request is made.
    """
    acceptinfo = action.acceptinfo
    if acceptinfo is not None:
        rev = acceptinfo.xsrcmd5 or acceptinfo.srcmd5
        if action.target_project is None or action.target_package is None or not rev:
            raise IncompleteEvidenceError("missing_diff_input")
        orev = acceptinfo.oxsrcmd5 or acceptinfo.osrcmd5 or "0"
        params: list[tuple[str, str]] = [("rev", rev), ("orev", orev)]
        if acceptinfo.oproject is not None:
            params.append(("oproject", acceptinfo.oproject))
        if acceptinfo.opackage is not None:
            params.append(("opackage", acceptinfo.opackage))
        project, package = action.target_project, action.target_package
    else:
        codestream = (
            action.target_release_project
            if action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT
            else action.target_project
        )
        if action.source_revision is None or codestream is None:
            raise IncompleteEvidenceError("missing_diff_input")
        params = [
            ("expand", "1"),
            ("rev", action.source_revision),
            ("oproject", codestream),
            ("opackage", codestream_package),
        ]
        project, package = action.source_project, action.source_package
    projects = [project, *(value for key, value in params if key == "oproject")]
    if not all(value.startswith(SUSE_NAMESPACE) for value in projects):
        raise IncompleteEvidenceError("outside_suse_namespace")
    return DiffForm(project=project, package=package, params=tuple(params))


# ---------------------------------------------------------------------------
# Package source history
# ---------------------------------------------------------------------------

_HISTORY_FIELDS: Final = frozenset({"srcmd5", "time", "requestid"})


@dataclass
class SourceHistoryHandler:
    """Parses a `<revisionlist>` and applies the completeness rule of an
    unpaged history (`revision` is `None`) or of an exact lookup."""

    revision: str | None
    _depth: int = 0
    _entries: list[SourceHistoryEntry] = field(default_factory=list)
    _rev: int | None = None
    _fields: dict[str, str] = field(default_factory=dict)
    _field: str | None = None
    _ignored_depth: int | None = None
    _text: list[str] = field(default_factory=list)
    _length: int = 0

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        self._depth += 1
        if self._depth == 1:
            if name != "revisionlist":
                raise IncompleteEvidenceError("invalid_document")
        elif self._depth == 2:
            self._rev = positive_int(attributes.get("rev"))
            if name != "revision" or self._rev is None:
                raise IncompleteEvidenceError("invalid_entry")
            self._fields = {}
        elif self._depth == 3:
            if name in _HISTORY_FIELDS:
                if name in self._fields:
                    raise IncompleteEvidenceError("invalid_entry")
                self._field, self._text, self._length = name, [], 0
        elif self._field is not None:
            raise IncompleteEvidenceError("invalid_entry")

    def end_element(self, name: str) -> None:
        if self._depth == 3 and self._field is not None:
            self._fields[self._field] = "".join(self._text)
            self._field = None
        elif self._depth == 2:
            self._entries.append(self._entry())
        self._depth -= 1

    def character_data(self, data: str) -> None:
        if self._field is None or self._depth != 3:
            return
        if self._length + len(data) > _MAX_FIELD_TEXT:
            raise IncompleteEvidenceError("invalid_entry")
        self._text.append(data)
        self._length += len(data)

    def _entry(self) -> SourceHistoryEntry:
        srcmd5 = self._fields.get("srcmd5")
        time = _unix_time(self._fields.get("time"))
        raw_request = self._fields.get("requestid")
        request_number = None if raw_request is None else positive_int(raw_request)
        if (
            self._rev is None
            or srcmd5 is None
            or not is_lowercase_checksum(srcmd5)
            or time is None
            or (raw_request is not None and request_number is None)
        ):
            raise IncompleteEvidenceError("invalid_entry")
        return SourceHistoryEntry(
            revision=self._rev,
            srcmd5=srcmd5,
            time=time,
            request_number=request_number,
        )

    def result(self) -> SourceHistory:
        revisions = [entry.revision for entry in self._entries]
        if len(set(revisions)) != len(revisions):
            raise IncompleteEvidenceError("duplicate_identity")
        if revisions != sorted(revisions):
            raise IncompleteEvidenceError("invalid_entry")
        if self.revision is None:
            if not revisions or revisions != list(range(1, len(revisions) + 1)):
                raise IncompleteEvidenceError("history_unavailable")
        elif not revisions:
            raise IncompleteEvidenceError("history_unavailable")
        elif _DECIMAL.fullmatch(self.revision):
            if revisions != [int(self.revision)]:
                raise IncompleteEvidenceError("invalid_entry")
        elif any(entry.srcmd5 != self.revision for entry in self._entries):
            raise IncompleteEvidenceError("invalid_entry")
        return SourceHistory(entries=tuple(self._entries))
