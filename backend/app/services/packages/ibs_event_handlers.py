"""Application handling of IBS RabbitMQ deliveries.

Implements docs/features/integrations/ibs-rabbitmq-integration.md
(Ownership Boundaries; Consumed Events > Package Commit, Request Create and
State Change; Per-Delivery Processing > Correlation Scope (log identity),
One-Attempt Rule, Settlement Policy outcomes; Fatal and Transient Failures,
delivery exception boundary),
docs/features/packages/ibs-track-release-detection.md (RabbitMQ
Package-Commit Acceleration), and
docs/features/packages/ibs-submission-tracking.md (Accelerators > RabbitMQ
Request Wake-Ups):

- `handle_delivery()` decodes one delivery
  (`app.services.ibs_event_decoding`), dispatches it by routing key, and
  returns its bounded `DeliveryResult`, with the heartbeat `last_error`
  category of its routing key on a failure (`FAILURE_CATEGORIES`). It never
  settles, logs the delivery events, counts, or binds the correlation ID;
  the consumer lifecycle owns those.
- `parse_package_commit()` consumes only `project` and `package`: each a
  non-empty JSON string, not whitespace-only, without an inadmissible
  character (docs/conventions.md, External String Admissibility), and not
  repeated in the root object. Every other member is ignored without
  validation; values are never trimmed.
- `handle_package_commit()` selects the existing tracks of the detector's
  Scope whose IBS project and logical package equal the event identity
  exactly, in a read-only session closed before any IBS request. An empty
  selection is irrelevant and makes no IBS request. Otherwise it invokes
  `reconcile_ibs_track_releases()` in consumer mode with the process-wide
  client, no hook, no delay, and no fetcher name; the delivery is processed
  only when every outcome is `updated` or `no_op`. There is no
  reverse-link fan-out.
- `parse_request_number()` consumes only `number` of a request create or
  state-change event: a JSON integer from 1 to 2,147,483,647, not repeated
  in the root object. Every other member, including the event `id`, state,
  actors, and actions, is ignored without validation.
- `handle_request_event()` point-fetches the current request detail with
  the process-wide client (an incomplete or failed lookup fails the
  delivery with the bounded category of the request operation), then
  selects, in a read-only session closed before the reconciliation, every
  active-Ticket IBS track whose package and codestream equal the identity
  of a validated current action or of a retained action of that request
  number. An empty selection is irrelevant. Otherwise it invokes
  `reconcile_ibs_requests()` inline with no hook, no delay, and no fetcher
  name; the delivery is processed only when every outcome is `created`,
  `updated`, or `no_op`. Event state and actions are never consulted.

One application attempt: no retry beyond the shared HTTP transport's.
Every non-cancellation exception other than `MemoryError` raised by the
point lookup, the selection, the boundary, or the dispatch ends the
delivery as a `failed` result with a bounded category (the boundary has
already rolled back and closed its unit); `MemoryError`, cancellation, and
other `BaseException` propagate to the lifecycle. Units committed before a
failure remain committed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Final

from app.core.enums import IBSConsumerErrorCategory, IBSRequestState
from app.core.external_strings import contains_inadmissible_character
from app.database import async_session_factory
from app.services.ibs_client import IBSClient, IBSRequestDetail, is_valid_ibs_name
from app.services.ibs_event_decoding import (
    PACKAGE_COMMIT_ROUTING_KEY,
    REQUEST_CREATE_ROUTING_KEY,
    REQUEST_STATE_CHANGE_ROUTING_KEY,
    DeliveryOutcome,
    DeliveryResult,
    EventObject,
    MalformedDeliveryError,
    MalformedReason,
    decode_delivery,
)
from app.services.packages.ibs_request_identity import action_identity
from app.services.packages.ibs_request_observation import (
    INTEGER_MAX,
    EvidenceCache,
    UnusableObservation,
)
from app.services.packages.ibs_request_reconciliation import (
    load_ibs_request_scopes,
    read_retained_identities,
    reconcile_ibs_requests,
)
from app.services.packages.ibs_track_release import (
    load_track_release_candidates,
    reconcile_ibs_track_releases,
)

TRACK_FAILED_CATEGORY: Final = "track_failed"
"""At least one selected track (or request scope) had a `failed`
outcome."""

SELECTION_FAILED_CATEGORY: Final = "selection_failed"
"""The read-only track or scope selection raised."""

RECONCILIATION_FAILED_CATEGORY: Final = "reconciliation_failed"
"""The shared reconciliation boundary propagated an exception."""

UNEXPECTED_ERROR_CATEGORY: Final = "unexpected_error"
"""Decoding or dispatch raised an exception it does not classify."""

_SANITIZED_PROJECT_PREFIX: Final = "SUSE:"

Handler = Callable[[EventObject, IBSClient], Awaitable[DeliveryResult]]


@dataclass(frozen=True, slots=True)
class PackageCommit:
    """The consumed wake-up identity of one package commit."""

    project: str
    package: str


def parse_package_commit(event: EventObject) -> PackageCommit:
    """The validated `project` and `package` of a package-commit event.

    Pure validation. Raises `MalformedDeliveryError` with
    `invalid_project` (checked first) or `invalid_package`.
    """
    project = _identity_member(event, "project", MalformedReason.INVALID_PROJECT)
    package = _identity_member(event, "package", MalformedReason.INVALID_PACKAGE)
    return PackageCommit(project=project, package=package)


def _identity_member(event: EventObject, name: str, reason: MalformedReason) -> str:
    value = event.members.get(name)
    if (
        name in event.duplicated
        or not isinstance(value, str)
        or not value.strip()
        or contains_inadmissible_character(value)
    ):
        raise MalformedDeliveryError(reason)
    return value


def log_identity(commit: PackageCommit) -> dict[str, str | int]:
    """The identity allowed in delivery logs: `project` and `package` only
    for a `SUSE:` project whose names are both IBS names; nothing for a
    personal (`home:`) or any other project (Correlation Scope)."""
    if (
        commit.project.startswith(_SANITIZED_PROJECT_PREFIX)
        and is_valid_ibs_name(commit.project)
        and is_valid_ibs_name(commit.package)
    ):
        return {"project": commit.project, "package": commit.package}
    return {}


async def handle_package_commit(
    event: EventObject, client: IBSClient
) -> DeliveryResult:
    """Accelerate the release reconciliation of the exactly represented
    tracks of one package commit.

    Category A workflow: owns one read-only selection session and delegates
    every write to the boundary's own per-track transactions. Raises
    `MalformedDeliveryError` for an invalid identity; converts every other
    `Exception` except `MemoryError` into a `failed` result.
    """
    commit = parse_package_commit(event)
    identity = log_identity(commit)
    try:
        async with async_session_factory() as session:
            candidates = await load_track_release_candidates(
                session, project=commit.project, package_name=commit.package
            )
    except MemoryError:
        raise
    except Exception:
        return DeliveryResult(
            DeliveryOutcome.FAILED, SELECTION_FAILED_CATEGORY, identity
        )
    if not candidates:
        return DeliveryResult(DeliveryOutcome.IRRELEVANT, fields=identity)

    selected = {**identity, "track_count": len(candidates)}
    try:
        outcomes = await reconcile_ibs_track_releases(
            candidates, client=client, forbid_convergence_effects=True
        )
    except MemoryError:
        raise
    except Exception:
        return DeliveryResult(
            DeliveryOutcome.FAILED, RECONCILIATION_FAILED_CATEGORY, selected
        )
    failed = sum(1 for outcome in outcomes if outcome.kind == "failed")
    if failed:
        return DeliveryResult(
            DeliveryOutcome.FAILED,
            TRACK_FAILED_CATEGORY,
            {**selected, "failed_track_count": failed},
        )
    return DeliveryResult(DeliveryOutcome.PROCESSED, fields=selected)


def parse_request_number(event: EventObject) -> int:
    """The validated `number` of a request create or state-change event.

    Pure validation. `number` must be an `int` decoded from a JSON integer
    token (never a `bool`; a fraction or exponent decodes to `float`) from
    1 to 2,147,483,647, the largest `IBSRequest.request_number`, and must
    occur once in the root object. Raises `MalformedDeliveryError` with
    `invalid_number` otherwise; no other member is read.
    """
    value = event.members.get("number")
    if (
        "number" in event.duplicated
        or isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= INTEGER_MAX
    ):
        raise MalformedDeliveryError(MalformedReason.INVALID_NUMBER)
    return value


def request_identities(detail: IBSRequestDetail) -> set[tuple[str, str]]:
    """The `(logical package, codestream)` of every validated current action
    of `detail` (ibs-submission-tracking.md, Package and Codestream
    Identity).

    Pure. A track of exactly this package and codestream is the scope for
    which the action is matching; an unresolved release action (no logical
    package) and an empty logical package contribute nothing, so they
    select no scope.
    """
    accepted = detail.state is IBSRequestState.ACCEPTED
    identities: set[tuple[str, str]] = set()
    for action in detail.actions:
        identity = action_identity(action, accepted=accepted)
        if identity.logical_package and identity.codestream:
            identities.add((identity.logical_package, identity.codestream))
    return identities


async def handle_request_event(event: EventObject, client: IBSClient) -> DeliveryResult:
    """Accelerate the delivery reconciliation of the represented scopes of
    one request create or state-change event.

    Category A workflow: owns one read-only selection session, closed
    before the reconciliation, and delegates every write to the boundary's
    own per-scope transactions. Raises `MalformedDeliveryError` for an
    invalid `number`; converts every other `Exception` except `MemoryError`
    into a `failed` result. The point detail only selects scopes; the
    reconciliation obtains its own evidence.
    """
    number = parse_request_number(event)
    fields: dict[str, str | int] = {"request_number": number}
    try:
        detail = await EvidenceCache(client).detail(number)
    except UnusableObservation as unusable:
        if unusable.http_status is not None:
            fields["http_status"] = unusable.http_status
        return DeliveryResult(DeliveryOutcome.FAILED, unusable.reason_category, fields)
    except MemoryError:
        raise
    except Exception:
        return DeliveryResult(DeliveryOutcome.FAILED, UNEXPECTED_ERROR_CATEGORY, fields)
    try:
        async with async_session_factory() as session:
            retained = await read_retained_identities(session, request_number=number)
            scopes = await load_ibs_request_scopes(
                session, identities=request_identities(detail) | retained
            )
    except MemoryError:
        raise
    except Exception:
        return DeliveryResult(DeliveryOutcome.FAILED, SELECTION_FAILED_CATEGORY, fields)
    if not scopes:
        return DeliveryResult(DeliveryOutcome.IRRELEVANT, fields=fields)

    selected = {**fields, "track_count": len(scopes)}
    try:
        outcomes = await reconcile_ibs_requests(scopes, client=client)
    except MemoryError:
        raise
    except Exception:
        return DeliveryResult(
            DeliveryOutcome.FAILED, RECONCILIATION_FAILED_CATEGORY, selected
        )
    failed = sum(1 for outcome in outcomes if outcome.kind == "failed")
    if failed:
        return DeliveryResult(
            DeliveryOutcome.FAILED,
            TRACK_FAILED_CATEGORY,
            {**selected, "failed_track_count": failed},
        )
    return DeliveryResult(DeliveryOutcome.PROCESSED, fields=selected)


HANDLERS: Final[dict[str, Handler]] = {
    PACKAGE_COMMIT_ROUTING_KEY: handle_package_commit,
    REQUEST_CREATE_ROUTING_KEY: handle_request_event,
    REQUEST_STATE_CHANGE_ROUTING_KEY: handle_request_event,
}
"""The application handler of every bound routing key."""

FAILURE_CATEGORIES: Final[dict[str, IBSConsumerErrorCategory]] = {
    PACKAGE_COMMIT_ROUTING_KEY: IBSConsumerErrorCategory.PACKAGE_RECONCILIATION_FAILED,
    REQUEST_CREATE_ROUTING_KEY: IBSConsumerErrorCategory.REQUEST_RECONCILIATION_FAILED,
    REQUEST_STATE_CHANGE_ROUTING_KEY: (
        IBSConsumerErrorCategory.REQUEST_RECONCILIATION_FAILED
    ),
}
"""The heartbeat `last_error` category of a failed delivery of every bound
routing key (Heartbeat Storage)."""


async def handle_delivery(
    routing_key: str | None,
    content_type: str | None,
    body: bytes,
    *,
    client: IBSClient,
) -> DeliveryResult:
    """Decode, validate, and handle one delivery in one application attempt.

    Returns `malformed` with its reason for an unbound routing key or an
    encoding or schema violation (no database or IBS work), otherwise the
    handler's result; an unclassified `Exception` other than `MemoryError`
    becomes `failed` with `unexpected_error`. Every `failed` result carries
    the `last_error` category of its routing key (`FAILURE_CATEGORIES`).
    `MemoryError`, cancellation, and other `BaseException` propagate.
    """
    if routing_key is None or routing_key not in HANDLERS:
        return DeliveryResult(
            DeliveryOutcome.MALFORMED, MalformedReason.UNSUPPORTED_ROUTING_KEY.value
        )
    try:
        event = decode_delivery(routing_key, content_type, body)
        result = await HANDLERS[routing_key](event, client)
    except MalformedDeliveryError as malformed:
        return DeliveryResult(DeliveryOutcome.MALFORMED, malformed.reason.value)
    except MemoryError:
        raise
    except Exception:
        result = DeliveryResult(DeliveryOutcome.FAILED, UNEXPECTED_ERROR_CATEGORY)
    if result.outcome is DeliveryOutcome.FAILED:
        return replace(result, error_category=FAILURE_CATEGORIES[routing_key])
    return result
