"""Package, codestream, and incident identity of IBS request actions.

Implements docs/features/packages/ibs-submission-tracking.md (Package and
Codestream Identity) for the shared IBS request reconciliation. Every
function is pure: it reads only its arguments and performs no I/O.

- `logical_package()` derives the logical package of a
  `maintenance_incident` physical package: the part before its first
  `.SUSE_`, `.openSUSE_`, or `.RES_` that is followed by at least one
  character, otherwise the whole name.
- `incident_number()` reads `n` from an exact `SUSE:Maintenance:{n}`.
- `action_identity()` derives an action's logical package, codestream,
  and incident number from its validated point-detail fields, and
  `classify_action()` classifies it for one scope as matching,
  unresolved, or non-matching. Comparisons are exact and case-sensitive.
- `action_key()` is the durable semantic identity used to compare current
  and retained actions in the stored project form (`_redacted_` outside
  `SUSE:`).
- `is_valid_scope_identity()` tells whether a scope's logical package and
  codestream can be sent to the IBS request operations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from app.core.enums import IBSRequestActionType
from app.services.ibs_client import IBSRequestActionDetail, is_valid_ibs_name

ORIGIN_SEPARATORS: Final = (".SUSE_", ".openSUSE_", ".RES_")
"""Separators between a logical package and the origin of its maintenance
package name."""

_INCIDENT_PROJECT: Final = re.compile(r"SUSE:Maintenance:([1-9][0-9]*)")

ActionKey = tuple[object, ...]
"""`(request_number, action_type, ...)`: the type-specific semantic
identity of ibs-integration.md (Request Point Detail)."""


class ActionMatch(StrEnum):
    """How one action relates to one scope's logical package and
    codestream."""

    MATCHING = "matching"
    UNRESOLVED = "unresolved"
    NON_MATCHING = "non_matching"


@dataclass(frozen=True, slots=True)
class ActionIdentity:
    """The derived identity of one action.

    `logical_package` is `None` only for a `maintenance_release` action
    whose name cannot be resolved; `incident_number` is `None` when no
    exact incident project establishes it.
    """

    logical_package: str | None
    codestream: str | None
    incident_number: int | None


def logical_package(physical_package: str) -> str:
    """The logical package of a `maintenance_incident` physical package.

    The part before the first origin separator that is followed by at least
    one character; the whole name when there is none. May be empty when a
    separator starts the name; an empty logical package matches no scope.
    """
    first: int | None = None
    for separator in ORIGIN_SEPARATORS:
        index = physical_package.find(separator)
        while index >= 0 and len(physical_package) <= index + len(separator):
            index = physical_package.find(separator, index + 1)
        if index >= 0 and (first is None or index < first):
            first = index
    return physical_package if first is None else physical_package[:first]


def incident_number(project: str | None) -> int | None:
    """`n` of an exact `SUSE:Maintenance:{n}` (positive, no leading zeros);
    `None` for every other project, including
    `SUSE:Maintenance:REQUEST:{n}` staging projects."""
    if project is None:
        return None
    match = _INCIDENT_PROJECT.fullmatch(project)
    return None if match is None else int(match[1])


def action_identity(
    action: IBSRequestActionDetail, *, accepted: bool
) -> ActionIdentity:
    """The logical package, codestream, and incident of `action`.

    `accepted` is whether the action's request is `accepted`: only an
    accepted submission action establishes its incident from
    `target/@project`.
    """
    if action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT:
        physical = action.target_package or action.source_package
        return ActionIdentity(
            logical_package=logical_package(physical),
            codestream=action.target_release_project,
            incident_number=incident_number(action.target_project)
            if accepted
            else None,
        )
    incident = incident_number(action.source_project)
    target = action.target_package or ""
    suffix = f".{incident}"
    resolved = (
        target[: -len(suffix)]
        if incident is not None
        and target.endswith(suffix)
        and len(target) > len(suffix)
        else None
    )
    return ActionIdentity(
        logical_package=resolved,
        codestream=action.target_project,
        incident_number=incident,
    )


def classify_action(
    action: IBSRequestActionDetail,
    identity: ActionIdentity,
    *,
    package_name: str,
    codestream: str,
) -> ActionMatch:
    """Classify `action` for the scope `(package_name, codestream)`.

    Matching when its logical package and codestream equal the scope's;
    unresolved for a `maintenance_release` action that targets the
    codestream with a package starting with `{package_name}.` but whose
    logical package cannot be resolved; non-matching otherwise.
    """
    if identity.logical_package is not None:
        if (
            identity.logical_package == package_name
            and identity.codestream == codestream
        ):
            return ActionMatch.MATCHING
        return ActionMatch.NON_MATCHING
    if action.target_project == codestream and (action.target_package or "").startswith(
        f"{package_name}."
    ):
        return ActionMatch.UNRESOLVED
    return ActionMatch.NON_MATCHING


def action_key(
    request_number: int,
    action_type: IBSRequestActionType,
    *,
    source_project: str | None,
    source_package: str | None,
    target_project: str | None,
    target_package: str | None,
    target_release_project: str | None,
) -> ActionKey:
    """The semantic identity of one action over stored-form values."""
    if action_type is IBSRequestActionType.MAINTENANCE_INCIDENT:
        return (
            request_number,
            action_type,
            source_project,
            source_package,
            target_release_project,
        )
    return (request_number, action_type, target_project, target_package)


def detail_action_key(action: IBSRequestActionDetail) -> ActionKey:
    """`action_key()` of a point-detail action."""
    return action_key(
        action.request_number,
        action.action_type,
        source_project=action.source_project,
        source_package=action.source_package,
        target_project=action.target_project,
        target_package=action.target_package,
        target_release_project=action.target_release_project,
    )


def is_valid_scope_identity(package_name: str, codestream: str) -> bool:
    """Whether the scope's logical package, its search prefix
    `{package_name}.`, and its codestream are IBS names."""
    return (
        is_valid_ibs_name(package_name)
        and is_valid_ibs_name(f"{package_name}.")
        and is_valid_ibs_name(codestream)
    )
