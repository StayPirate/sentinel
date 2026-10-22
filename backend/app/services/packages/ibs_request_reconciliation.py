"""The shared authoritative IBS request reconciliation boundary.

Implements docs/features/packages/ibs-submission-tracking.md (Data Model
behaviour over the existing schema; Retention and Deletion; Observation
Outcomes; Delivery Derivation; Shared Authoritative Reconciliation > Scope
Identity, Algorithm, and Structured Logs; Recovery Guarantees, preservation
of the last proven state) for the daily fetcher, its per-Ticket catch-up,
the package-add catch-up, and the RabbitMQ request wake-ups:

- `load_ibs_request_scopes()` is the read-only scope selection: every IBS
  track of an active Ticket, in every affectedness, delivery, exclusion,
  actionability, eligibility, and lifecycle state, including CVE-less
  Tickets; Git tracks are never selected. A request wake-up restricts it to
  exact `(logical package, codestream)` identities, which include those
  `read_retained_identities()` reads for one request number.
- `reconcile_ibs_requests()` is the orchestration and never takes a lock.
  It reads the step-1 snapshot of every scope in one read-only session that
  is closed before the first IBS request, observes each scope through
  `app.services.packages.ibs_request_observation` over the caller's open
  `IBSClient`, and applies each complete observation as one independent
  transaction, so no IBS request is made while a Ticket lock is held.
- `_reconcile_scope()` is the only function that takes the Ticket row
  lock: it revalidates the scope, compares the reloaded evidence with the
  snapshot (the stale-negative guard), writes requests in ascending request
  number (`FOR NO KEY UPDATE` or `INSERT ... ON CONFLICT`), then actions in
  identity order, then correlations, and applies the derived delivery
  through `package_service.set_track_delivery_status()`.
- `apply_ibs_request_observation()` (Trusted Observation Application)
  applies one complete observation that its caller supplies, without IBS,
  through the same step-1 snapshot and locked unit in the caller's
  transaction. Its only caller is the example dataset loader
  (docs/features/platform/example-dataset.md).

The per-outcome hook (periodic metrics) runs once for every terminal
outcome: immediately for an incomplete or failed observation, and after the
commit or rollback of a local unit, before its session is closed. A commit
that the database definitely rejects is a failed scope; a commit with an
unknown outcome propagates without an outcome and ends the invocation.
`TicketNotMutableError` is a stale no-op; `InvalidDeliveryStatusTransition`
and `SQLAlchemyError` before finalization are failed scopes; every other
exception, including `SoftTimeLimitExceeded`, `MemoryError`, and
cancellation, propagates. Nothing creates a `TicketAuditEvent`, reads audit
history, or changes affectedness, eligibility, `released_at`, a track
release checkpoint, or an exclusion marker. A delivery change never
registers a Ticket convergence effect, so no drain exists.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

import structlog
from sqlalchemy import select, tuple_, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    ACTIVE_TICKET_STATUSES,
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    WorkflowType,
)
from app.core.exceptions import ServiceError, TicketNotMutableError
from app.database import async_session_factory
from app.models.cve import CVE
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service
from app.services.ibs_client import IBSClient, IBSRequestActionDetail
from app.services.packages.ibs_request_identity import (
    ActionKey,
    ActionMatch,
    action_identity,
    action_key,
    classify_action,
)
from app.services.packages.ibs_request_observation import (
    SUSE_NAMESPACE,
    ActionWrite,
    EvidenceCache,
    IBSRequestScope,
    Observation,
    RequestWrite,
    RetainedAction,
    RetainedRequest,
    ScopeSnapshot,
    UnusableObservation,
    observe_scope,
    order,
)
from app.services.ticket_mutations import ensure_ticket_operable

__all__ = [
    "IBSObservationRejectedError",
    "IBSRequestOutcome",
    "IBSRequestOutcomeHook",
    "IBSRequestOutcomeKind",
    "IBSRequestScope",
    "ObservationApplication",
    "apply_ibs_request_observation",
    "load_ibs_request_scopes",
    "read_retained_actions",
    "read_retained_identities",
    "reconcile_ibs_requests",
]

logger = structlog.get_logger(__name__)

SCOPE_FAILED_EVENT: Final = "ibs_request_scope_failed"
SCOPE_STALE_EVENT: Final = "ibs_request_scope_stale"

TICKET_NOT_OPERABLE_CATEGORY: Final = "ticket_not_operable"
SCOPE_CHANGED_CATEGORY: Final = "scope_changed"
STALE_REQUEST_CATEGORY: Final = "stale_request_observation"
CONFLICTING_OBSERVATION_CATEGORY: Final = "conflicting_observation"
CONFLICTING_PROVENANCE_CATEGORY: Final = "conflicting_provenance"
INVALID_TRANSITION_CATEGORY: Final = "invalid_delivery_transition"
DATABASE_CATEGORY: Final = "database"

SNAPSHOT_BATCH_SIZE: Final = 1000
"""Most tracks read by one step-1 statement."""

_CONNECTION_EXCEPTION_CLASS: Final = "08"

IBSRequestOutcomeKind = Literal["created", "updated", "no_op", "failed"]

_IMMUTABLE_FIELDS: Final = (
    "source_project",
    "source_package",
    "target_release_project",
    "logical_package",
    "codestream_name",
    "incident_number",
    "accepted_revision",
    "accepted_srcmd5",
)
_RELEASE_TARGET_FIELDS: Final = ("target_project", "target_package")
"""Identity of a release action; for a submission action they may change
at acceptance and take the latest observed value."""


@dataclass(frozen=True, slots=True)
class IBSRequestOutcome:
    """The terminal outcome of one selected scope: `created` or `updated`
    for a committed effect, `no_op` for a success without effect (including
    a stale or inapplicable scope), `failed` for an incomplete or failed
    one."""

    track_id: uuid.UUID
    kind: IBSRequestOutcomeKind


IBSRequestOutcomeHook = Callable[[IBSRequestOutcome], None]


# ---------------------------------------------------------------------------
# Scope selection
# ---------------------------------------------------------------------------


async def load_ibs_request_scopes(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID | None = None,
    identities: Collection[tuple[str, str]] | None = None,
) -> list[IBSRequestScope]:
    """The IBS track scopes of active Tickets, ordered by track ID.

    Category B (read-only; no lock, write, commit, or rollback). Selects
    every `TicketPackageTrack` with `workflow_type = ibs` below a Ticket in
    `New`, `Analysis`, or `Analyzed`, whatever its affectedness, delivery,
    exclusion, actionability, eligibility, or lifecycle, including tracks of
    CVE-less Tickets (`cve_id = None`). With `ticket_id`, only that Ticket's
    tracks (none for a missing or inactive Ticket). With `identities`
    (`(logical package, codestream)` pairs; the request wake-up selection),
    only tracks whose `TicketPackage.package_name` and
    `TicketPackageTrack.reference` equal one pair exactly; an empty
    collection selects nothing without a query. Database exceptions
    propagate.
    """
    if identities is not None and not identities:
        return []
    statement = (
        select(
            Ticket.id,
            CVE.cve_id,
            TicketPackage.id,
            TicketPackage.package_name,
            TicketPackageTrack.id,
            TicketPackageTrack.reference,
        )
        .select_from(TicketPackageTrack)
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(Ticket, Ticket.id == TicketPackage.ticket_id)
        .outerjoin(CVE, CVE.id == Ticket.cve_id)
        .where(
            TicketPackageTrack.workflow_type == WorkflowType.IBS.value,
            Ticket.status.in_(ACTIVE_TICKET_STATUSES),
        )
        .order_by(TicketPackageTrack.id)
    )
    if ticket_id is not None:
        statement = statement.where(Ticket.id == ticket_id)
    if identities is not None:
        pairs = sorted(set(identities))
        # The package-name predicate serves `ix_ticket_package_package_name`;
        # the row-value predicate keeps only the exact pairs.
        statement = statement.where(
            TicketPackage.package_name.in_(sorted({name for name, _ in pairs})),
            tuple_(TicketPackage.package_name, TicketPackageTrack.reference).in_(pairs),
        )
    rows = (await db.execute(statement)).all()
    return [
        IBSRequestScope(
            ticket_id=scope_ticket_id,
            cve_id=cve_id,
            package_id=package_id,
            package_name=package_name,
            track_id=track_id,
            codestream=codestream,
        )
        for (
            scope_ticket_id,
            cve_id,
            package_id,
            package_name,
            track_id,
            codestream,
        ) in rows
    ]


# ---------------------------------------------------------------------------
# Retained evidence readers (step 1 and the locked reload)
# ---------------------------------------------------------------------------

_ACTION_COLUMNS: Final = (
    IBSRequestAction.id,
    IBSRequestAction.action_type,
    IBSRequestAction.source_project,
    IBSRequestAction.source_package,
    IBSRequestAction.target_project,
    IBSRequestAction.target_package,
    IBSRequestAction.target_release_project,
    IBSRequestAction.logical_package,
    IBSRequestAction.codestream_name,
    IBSRequestAction.incident_number,
    IBSRequestAction.accepted_revision,
    IBSRequestAction.accepted_srcmd5,
    IBSRequestAction.created_at,
    IBSRequestAction.updated_at,
    IBSRequest.id.label("request_id"),
    IBSRequest.request_number,
    IBSRequest.state,
    IBSRequest.superseded_by_request_number,
    IBSRequest.upstream_created_at,
    IBSRequest.upstream_updated_at,
    IBSRequest.created_at.label("request_created_at"),
    IBSRequest.updated_at.label("request_updated_at"),
)


def _retained(row: Any) -> RetainedAction:
    request = RetainedRequest(
        id=row.request_id,
        request_number=row.request_number,
        state=IBSRequestState(row.state),
        superseded_by_request_number=row.superseded_by_request_number,
        upstream_created_at=row.upstream_created_at,
        upstream_updated_at=row.upstream_updated_at,
        created_at=row.request_created_at,
        updated_at=row.request_updated_at,
    )
    return RetainedAction(
        id=row.id,
        request=request,
        action_type=IBSRequestActionType(row.action_type),
        source_project=row.source_project,
        source_package=row.source_package,
        target_project=row.target_project,
        target_package=row.target_package,
        target_release_project=row.target_release_project,
        logical_package=row.logical_package,
        codestream_name=row.codestream_name,
        incident_number=row.incident_number,
        accepted_revision=row.accepted_revision,
        accepted_srcmd5=row.accepted_srcmd5,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def read_retained_actions(
    db: AsyncSession, *, package_name: str, codestream: str
) -> list[RetainedAction]:
    """Every retained action of one logical package and codestream with
    its parent request (the retained-root reader, served by
    `ix_ibs_request_action_logical_package_codestream_name`), ordered by
    request number and action ID. Category B; database exceptions
    propagate."""
    rows = (
        await db.execute(
            select(*_ACTION_COLUMNS)
            .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
            .where(
                IBSRequestAction.logical_package == package_name,
                IBSRequestAction.codestream_name == codestream,
            )
            .order_by(IBSRequest.request_number, IBSRequestAction.id)
        )
    ).all()
    return [_retained(row) for row in rows]


async def read_retained_identities(
    db: AsyncSession, *, request_number: int
) -> set[tuple[str, str]]:
    """The distinct `(logical_package, codestream_name)` of the retained
    actions of one request number (its retained exact roots), served by
    the unique `request_number` and `ix_ibs_request_action_ibs_request_id`;
    empty when the request is not retained. Category B; database
    exceptions propagate."""
    rows = (
        await db.execute(
            select(IBSRequestAction.logical_package, IBSRequestAction.codestream_name)
            .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
            .where(IBSRequest.request_number == request_number)
            .distinct()
        )
    ).all()
    return {(package, codestream) for package, codestream in rows}


@dataclass(frozen=True, slots=True)
class _Correlation:
    id: uuid.UUID
    created_at: Any
    action: RetainedAction


async def _read_correlations(
    db: AsyncSession, track_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[_Correlation]]:
    """The correlations of the given tracks with their actions and
    requests."""
    correlations: dict[uuid.UUID, list[_Correlation]] = defaultdict(list)
    for start in range(0, len(track_ids), SNAPSHOT_BATCH_SIZE):
        batch = track_ids[start : start + SNAPSHOT_BATCH_SIZE]
        rows = (
            await db.execute(
                select(
                    IBSRequestActionTrack.id.label("correlation_id"),
                    IBSRequestActionTrack.created_at.label("correlation_created_at"),
                    IBSRequestActionTrack.ticket_package_track_id,
                    *_ACTION_COLUMNS,
                )
                .join(
                    IBSRequestAction,
                    IBSRequestAction.id == IBSRequestActionTrack.ibs_request_action_id,
                )
                .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
                .where(IBSRequestActionTrack.ticket_package_track_id.in_(batch))
                .order_by(IBSRequestActionTrack.id)
            )
        ).all()
        for row in rows:
            correlations[row.ticket_package_track_id].append(
                _Correlation(
                    id=row.correlation_id,
                    created_at=row.correlation_created_at,
                    action=_retained(row),
                )
            )
    return correlations


def _fingerprint(
    actions: Iterable[RetainedAction], correlations: Iterable[_Correlation]
) -> frozenset[tuple[object, ...]]:
    """The identities and row timestamps compared by the stale-negative
    guard: the actions of the scope's package and codestream, their
    requests, and the track's correlations with their actions."""
    stamps: set[tuple[object, ...]] = set()
    for correlation in correlations:
        stamps.add(("correlation", correlation.id, correlation.created_at))
    for action in (*actions, *(c.action for c in correlations)):
        stamps.add(("action", action.id, action.created_at, action.updated_at))
        request = action.request
        stamps.add(("request", request.id, request.created_at, request.updated_at))
    return frozenset(stamps)


def _snapshot(
    delivery_status: DeliveryStatus | None,
    actions: Sequence[RetainedAction],
    correlations: Sequence[_Correlation],
) -> ScopeSnapshot:
    correlated = tuple(correlation.action for correlation in correlations)
    correlated_ids = {action.id for action in correlated}
    released_incidents = {
        action.incident_number
        for action in actions
        if action.action_type is IBSRequestActionType.MAINTENANCE_RELEASE
        and action.request.state is IBSRequestState.ACCEPTED
    }
    in_flight = tuple(
        action
        for action in actions
        if action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT
        and action.request.state is IBSRequestState.ACCEPTED
        and action.id not in correlated_ids
        and (
            action.incident_number is None
            or action.incident_number not in released_incidents
        )
    )
    return ScopeSnapshot(
        delivery_status=delivery_status,
        correlated=correlated,
        in_flight=in_flight,
        fingerprint=_fingerprint(actions, correlations),
    )


async def _read_snapshots(
    scopes: Sequence[IBSRequestScope],
) -> dict[uuid.UUID, ScopeSnapshot]:
    """Step 1 of every scope in one read-only session, closed before any
    IBS request."""
    track_ids = [scope.track_id for scope in scopes]
    async with async_session_factory() as session:
        try:
            deliveries: dict[uuid.UUID, DeliveryStatus] = {}
            for start in range(0, len(track_ids), SNAPSHOT_BATCH_SIZE):
                batch = track_ids[start : start + SNAPSHOT_BATCH_SIZE]
                rows = (
                    await session.execute(
                        select(
                            TicketPackageTrack.id, TicketPackageTrack.delivery_status
                        ).where(TicketPackageTrack.id.in_(batch))
                    )
                ).all()
                deliveries.update(
                    (track_id, DeliveryStatus(value)) for track_id, value in rows
                )
            groups: dict[tuple[str, str], list[RetainedAction]] = {}
            for scope in scopes:
                group = (scope.package_name, scope.codestream)
                if group not in groups:
                    groups[group] = await read_retained_actions(
                        session, package_name=group[0], codestream=group[1]
                    )
            correlations = await _read_correlations(session, track_ids)
        finally:
            await session.rollback()
    return {
        scope.track_id: _snapshot(
            deliveries.get(scope.track_id),
            groups[(scope.package_name, scope.codestream)],
            correlations.get(scope.track_id, []),
        )
        for scope in scopes
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def reconcile_ibs_requests(
    scopes: Iterable[IBSRequestScope],
    *,
    client: IBSClient,
    on_outcome: IBSRequestOutcomeHook | None = None,
    request_delay: float = 0.0,
    fetcher_name: str | None = None,
) -> list[IBSRequestOutcome]:
    """Reconcile the selected scopes against current IBS request evidence.

    Category A workflow owning one independent transaction per complete
    scope (ibs-submission-tracking.md, Shared Authoritative
    Reconciliation).

    Q1: `scopes` come from `load_ibs_request_scopes()` (or an equivalent
    selection); duplicate track IDs are processed once, in track-ID order.
    `client` is the caller's open `IBSClient`; `on_outcome`, when given,
    receives each terminal outcome exactly once; `request_delay` is the
    seconds waited before every IBS request of the invocation except the
    first, never while a local transaction is open; `fetcher_name`, when
    given, is added to every `ibs_request_scope_failed` (the fetcher and
    its catch-up; Structured Logs).

    Q2: acquires no lock; reads the step-1 snapshot of every scope before
    the first IBS request, and each local unit serializes on the Ticket row
    lock in `_reconcile_scope()`.

    Q3: an empty selection performs no IBS or database work. Each scope is
    observed (Algorithm steps 2-3); an incomplete or failed observation is
    `failed` without a database mutation and emits one
    `ibs_request_scope_failed`. A complete observation runs in a fresh
    session (steps 4-10): a stale or inapplicable scope is a `no_op` with
    one `ibs_request_scope_stale`; a stale request observation, conflicting
    content or provenance, a rejected delivery transition, a database error
    before finalization, or a definitely rejected commit is `failed` with
    one `ibs_request_scope_failed`; otherwise the committed scope is
    `created`, `updated`, or `no_op`.

    Q4: returns one outcome per distinct selected scope. Creates no audit
    event.

    Q5: re-invocation re-reads IBS and PostgreSQL; unchanged evidence
    produces no write.

    Q6: a commit with an unknown outcome, a rollback failure, a step-1
    database failure, `SoftTimeLimitExceeded`, `MemoryError`, cancellation,
    and unexpected exceptions propagate; earlier committed scopes remain
    committed.
    """
    selected: dict[uuid.UUID, IBSRequestScope] = {}
    for scope in scopes:
        selected.setdefault(scope.track_id, scope)
    run = _Reconciliation(hook=on_outcome, fetcher_name=fetcher_name)
    if selected:
        ordered = [selected[key] for key in sorted(selected)]
        snapshots = await _read_snapshots(ordered)
        cache = EvidenceCache(client, request_delay=request_delay)
        for scope in ordered:
            await run.reconcile(scope, snapshots[scope.track_id], cache)
    return run.outcomes


class _LocalFailure(Exception):  # noqa: N818 — an outcome, not an error
    """A complete observation that the locked unit rejects."""

    def __init__(self, category: str, *, request_number: int | None = None) -> None:
        super().__init__(f"IBS request scope rejected: {category}")
        self.category = category
        self.request_number = request_number


@dataclass(frozen=True, slots=True)
class _LocalResult:
    kind: Literal["created", "updated", "no_op"] = "no_op"
    stale: str | None = None


@dataclass
class _Reconciliation:
    """The outcomes of one boundary invocation."""

    hook: IBSRequestOutcomeHook | None
    fetcher_name: str | None = None
    outcomes: list[IBSRequestOutcome] = field(default_factory=list)

    async def reconcile(
        self, scope: IBSRequestScope, snapshot: ScopeSnapshot, cache: EvidenceCache
    ) -> None:
        try:
            observation = await observe_scope(scope, snapshot, cache)
        except UnusableObservation as exc:
            self._log_failed(
                scope,
                exc.reason_category,
                request_number=exc.request_number,
                http_status=exc.http_status,
            )
            self._finish(scope, "failed")
            return
        await self._apply(scope, snapshot, observation)

    async def _apply(
        self, scope: IBSRequestScope, snapshot: ScopeSnapshot, observation: Observation
    ) -> None:
        """Run one scope's locked unit as its own transaction."""
        kind: IBSRequestOutcomeKind
        async with async_session_factory() as unit:
            try:
                result = await _reconcile_scope(unit, scope, snapshot, observation)
            except TicketNotMutableError:
                await unit.rollback()
                self._log_stale(scope, TICKET_NOT_OPERABLE_CATEGORY)
                kind = "no_op"
            except _LocalFailure as exc:
                await unit.rollback()
                self._log_failed(scope, exc.category, request_number=exc.request_number)
                kind = "failed"
            except package_service.InvalidDeliveryStatusTransition:
                await unit.rollback()
                self._log_failed(scope, INVALID_TRANSITION_CATEGORY)
                kind = "failed"
            except SQLAlchemyError:
                await unit.rollback()
                self._log_failed(scope, DATABASE_CATEGORY)
                kind = "failed"
            else:
                if result.stale is not None:
                    await unit.rollback()
                    self._log_stale(scope, result.stale)
                    kind = "no_op"
                elif result.kind == "no_op":
                    await unit.rollback()
                    kind = "no_op"
                else:
                    try:
                        await unit.commit()
                    except DBAPIError as exc:
                        if not _definitely_failed(exc):
                            raise
                        await unit.rollback()
                        self._log_failed(scope, DATABASE_CATEGORY)
                        kind = "failed"
                    else:
                        kind = result.kind
            # Terminal outcome after the commit, before the session close.
            self._finish(scope, kind)

    def _log_failed(
        self,
        scope: IBSRequestScope,
        category: str,
        *,
        request_number: int | None = None,
        http_status: int | None = None,
    ) -> None:
        fields = _scope_fields(scope)
        if request_number is not None:
            fields["request_number"] = request_number
        if http_status is not None:
            fields["http_status"] = http_status
        if self.fetcher_name is not None:
            fields["fetcher_name"] = self.fetcher_name
        logger.warning(SCOPE_FAILED_EVENT, reason_category=category, **fields)

    def _log_stale(self, scope: IBSRequestScope, category: str) -> None:
        logger.warning(
            SCOPE_STALE_EVENT, reason_category=category, **_scope_fields(scope)
        )

    def _finish(self, scope: IBSRequestScope, kind: IBSRequestOutcomeKind) -> None:
        outcome = IBSRequestOutcome(scope.track_id, kind)
        self.outcomes.append(outcome)
        if self.hook is not None:
            self.hook(outcome)


def _scope_fields(scope: IBSRequestScope) -> dict[str, object]:
    fields: dict[str, object] = {
        "ticket_id": str(scope.ticket_id),
        "track_id": str(scope.track_id),
        "package_name": scope.package_name,
    }
    if scope.codestream.startswith(SUSE_NAMESPACE):
        fields["codestream"] = scope.codestream
    return fields


def _definitely_failed(exc: DBAPIError) -> bool:
    """A server-reported error on a connection that is still valid: the
    commit did not happen. A connection-class error or an error without an
    SQLSTATE leaves the outcome unknown."""
    sqlstate = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
    return (
        not exc.connection_invalidated
        and isinstance(sqlstate, str)
        and not sqlstate.startswith(_CONNECTION_EXCEPTION_CLASS)
    )


# ---------------------------------------------------------------------------
# Trusted observation application
# ---------------------------------------------------------------------------

ObservationApplication = Literal["created", "updated", "no_op"]
"""The result of `apply_ibs_request_observation()`."""

_SRCMD5: Final = re.compile(r"[0-9a-f]{32}")


class IBSObservationRejectedError(ServiceError):
    """Locked revalidation or a conditional upsert rejected a supplied
    observation (ibs-submission-tracking.md, Trusted Observation
    Application).

    Inherits directly from `ServiceError`. `category` is one bounded
    category of Structured Logs (`scope_changed`,
    `stale_request_observation`, `conflicting_observation`, or
    `conflicting_provenance`), and the message names only that category.
    No API handler receives it.
    """

    def __init__(self, category: str) -> None:
        super().__init__(f"IBS request observation rejected: {category}")
        self.category = category


async def apply_ibs_request_observation(
    db: AsyncSession,
    *,
    track_id: uuid.UUID,
    observation: Observation,
) -> ObservationApplication:
    """Apply one complete observation that the caller supplies, without
    IBS, to one IBS track.

    Category A composable service function (ibs-submission-tracking.md,
    Trusted Observation Application). Its only caller is the example
    dataset loader (docs/features/platform/example-dataset.md).

    Q1: `track_id` is the `TicketPackageTrack.id` of the scope.
    `observation` has the form of Algorithm step 3: the derived delivery
    value and the request and action evidence in the stored form. The
    caller asserts that it is complete and that its delivery value is the
    one Delivery Derivation yields for its evidence; neither can be
    verified here.

    Q2: before any write, reads the scope of `track_id` and raises
    `ValueError` when the track does not exist, its workflow is not `ibs`,
    or its Ticket is not active, and when an action belongs to a request
    number the observation has no request for, does not satisfy the
    structural requirements of IBSRequestAction, has a semantic identity
    that differs from the identity of its own fields, or does not represent
    the scope's logical package and codestream.

    Q3: in the caller's transaction, reads the scope's step-1 snapshot with
    no lock, then runs Algorithm steps 4-9 through `_reconcile_scope()`:
    Ticket lock, locked revalidation, conditional request and action
    upserts, correlation of every action to the track, delivery derivation
    under the stale-negative guard, and delivery application through
    `package_service.set_track_delivery_status()`. Flushes; never commits
    or rolls back; performs no IBS, Redis, AMQP, or Celery I/O and
    registers no post-commit effect.

    Q4: returns `created`, `updated`, or `no_op`. Creates no audit event.

    Q5: idempotent; the same observation applied again returns `no_op`.

    Q6: `ValueError` for the guards; `TicketNotMutableError` for a Ticket
    that became `Ignored` or `Duplicated` before the lock;
    `IBSObservationRejectedError` when locked revalidation finds a stale
    scope (`scope_changed`) or a conditional upsert rejects the
    observation; `InvalidDeliveryStatusTransition`; database and flush
    exceptions. The caller rolls back on every exception.
    """
    scope, delivery = await _read_trusted_scope(db, track_id)
    _validate_trusted_observation(scope, observation)
    snapshot = _snapshot(
        delivery,
        await read_retained_actions(
            db, package_name=scope.package_name, codestream=scope.codestream
        ),
        (await _read_correlations(db, [scope.track_id])).get(scope.track_id, []),
    )
    try:
        result = await _reconcile_scope(db, scope, snapshot, observation)
    except _LocalFailure as exc:
        raise IBSObservationRejectedError(exc.category) from None
    if result.stale is not None:
        raise IBSObservationRejectedError(result.stale)
    return result.kind


async def _read_trusted_scope(
    db: AsyncSession, track_id: uuid.UUID
) -> tuple[IBSRequestScope, DeliveryStatus]:
    """The scope of `track_id` and its persisted delivery; raises
    `ValueError` for a missing track, a track that is not `ibs`, or an
    inactive Ticket. Takes no lock and never writes."""
    row = (
        await db.execute(
            select(
                Ticket.id.label("ticket_id"),
                Ticket.status,
                CVE.cve_id,
                TicketPackage.id.label("package_id"),
                TicketPackage.package_name,
                TicketPackageTrack.workflow_type,
                TicketPackageTrack.reference,
                TicketPackageTrack.delivery_status,
            )
            .select_from(TicketPackageTrack)
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .join(Ticket, Ticket.id == TicketPackage.ticket_id)
            .outerjoin(CVE, CVE.id == Ticket.cve_id)
            .where(TicketPackageTrack.id == track_id)
        )
    ).one_or_none()
    if row is None:
        raise ValueError("The track does not exist.")
    if row.workflow_type != WorkflowType.IBS.value:
        raise ValueError("The track is not an IBS track.")
    if row.status not in ACTIVE_TICKET_STATUSES:
        raise ValueError("The Ticket of the track is not active.")
    scope = IBSRequestScope(
        ticket_id=row.ticket_id,
        cve_id=row.cve_id,
        package_id=row.package_id,
        package_name=row.package_name,
        track_id=track_id,
        codestream=row.reference,
    )
    return scope, DeliveryStatus(row.delivery_status)


def _validate_trusted_observation(
    scope: IBSRequestScope, observation: Observation
) -> None:
    """The action guards of Trusted Observation Application."""
    states = {request.request_number: request.state for request in observation.requests}
    for action in observation.actions:
        state = states.get(action.request_number)
        if state is None:
            raise ValueError("An action belongs to a request the observation lacks.")
        if not _satisfies_action_structure(action):
            raise ValueError("An action does not satisfy the action structure.")
        if action.key != action_key(
            action.request_number,
            action.action_type,
            source_project=action.source_project,
            source_package=action.source_package,
            target_project=action.target_project,
            target_package=action.target_package,
            target_release_project=action.target_release_project,
        ):
            raise ValueError("An action identity differs from its own fields.")
        detail = IBSRequestActionDetail(
            request_number=action.request_number,
            action_type=action.action_type,
            source_project=action.source_project,
            source_package=action.source_package,
            target_project=action.target_project,
            target_package=action.target_package,
            target_release_project=action.target_release_project,
        )
        match = classify_action(
            detail,
            action_identity(detail, accepted=state is IBSRequestState.ACCEPTED),
            package_name=scope.package_name,
            codestream=scope.codestream,
        )
        if (
            match is not ActionMatch.MATCHING
            or action.logical_package != scope.package_name
            or action.codestream_name != scope.codestream
        ):
            raise ValueError("An action does not represent the scope's package.")


def _satisfies_action_structure(action: ActionWrite) -> bool:
    """The type-specific structural requirements and column constraints of
    IBSRequestAction (ibs-submission-tracking.md, Data Model)."""
    if action.incident_number is not None and action.incident_number <= 0:
        return False
    if action.accepted_srcmd5 is not None and not _SRCMD5.fullmatch(
        action.accepted_srcmd5
    ):
        return False
    if action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT:
        return (
            action.source_project is not None
            and action.source_package is not None
            and action.target_release_project is not None
            and action.codestream_name == action.target_release_project
        )
    return (
        action.source_project is not None
        and action.source_package is not None
        and action.target_project is not None
        and action.target_package is not None
        and action.incident_number is not None
        and action.codestream_name == action.target_project
    )


# ---------------------------------------------------------------------------
# The locked unit (Algorithm steps 4-10)
# ---------------------------------------------------------------------------


async def _reconcile_scope(
    db: AsyncSession,
    scope: IBSRequestScope,
    snapshot: ScopeSnapshot,
    observation: Observation,
) -> _LocalResult:
    """Lock the Ticket, revalidate the scope, and apply one complete
    observation.

    The only function of the reconciliation that takes the Ticket row
    lock. Performs no external I/O and never commits.

    Returns a stale result (`scope_changed`) when the Ticket is missing or
    inactive, or the track, its package, its IBS workflow, codestream,
    logical package, or the Ticket CVE no longer matches the scope.
    Otherwise writes the evidence, derives delivery under the
    stale-negative guard, flushes, and returns `created`, `updated`, or
    `no_op`. Raises `TicketNotMutableError` for an `Ignored`/`Duplicated`
    Ticket and `_LocalFailure` for a stale request observation or
    conflicting content or provenance; `InvalidDeliveryStatusTransition`
    and database exceptions propagate.
    """
    ticket = (
        await db.execute(
            select(Ticket)
            .where(Ticket.id == scope.ticket_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if ticket is None:
        return _LocalResult(stale=SCOPE_CHANGED_CATEGORY)
    ensure_ticket_operable(ticket)
    if ticket.status not in ACTIVE_TICKET_STATUSES:
        return _LocalResult(stale=SCOPE_CHANGED_CATEGORY)
    ticket_cve = (
        await db.scalar(select(CVE.cve_id).where(CVE.id == ticket.cve_id))
        if ticket.cve_id is not None
        else None
    )
    row = (
        await db.execute(
            select(
                TicketPackageTrack.workflow_type,
                TicketPackageTrack.reference,
                TicketPackageTrack.delivery_status,
                TicketPackage.package_name,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(
                TicketPackageTrack.id == scope.track_id,
                TicketPackage.id == scope.package_id,
                TicketPackage.ticket_id == ticket.id,
            )
        )
    ).one_or_none()
    if (
        row is None
        or row.workflow_type != WorkflowType.IBS.value
        or row.reference != scope.codestream
        or row.package_name != scope.package_name
        or ticket_cve != scope.cve_id
    ):
        return _LocalResult(stale=SCOPE_CHANGED_CATEGORY)
    current = DeliveryStatus(row.delivery_status)

    reloaded = _fingerprint(
        await read_retained_actions(
            db, package_name=scope.package_name, codestream=scope.codestream
        ),
        (await _read_correlations(db, [scope.track_id])).get(scope.track_id, []),
    )
    unchanged = reloaded == snapshot.fingerprint and current is snapshot.delivery_status

    created, updated = await _write_evidence(db, scope, observation)
    delivery_changed = await _apply_delivery(
        db, scope, observation.derived, current, unchanged=unchanged
    )
    await db.flush()
    if created:
        return _LocalResult(kind="created")
    if updated or delivery_changed:
        return _LocalResult(kind="updated")
    return _LocalResult()


async def _lock_request(db: AsyncSession, request_number: int) -> Any:
    return (
        await db.execute(
            select(
                IBSRequest.id,
                IBSRequest.state,
                IBSRequest.superseded_by_request_number,
                IBSRequest.upstream_created_at,
                IBSRequest.upstream_updated_at,
            )
            .where(IBSRequest.request_number == request_number)
            .with_for_update(key_share=True)
        )
    ).one_or_none()


async def _write_request(
    db: AsyncSession, write: RequestWrite
) -> tuple[uuid.UUID, bool, bool]:
    """Lock or insert one request and apply its observed state; returns
    `(id, created, updated)`."""
    number = write.request_number
    row = await _lock_request(db, number)
    if row is None:
        inserted = await db.scalar(
            insert(IBSRequest)
            .values(
                request_number=number,
                state=write.state.value,
                superseded_by_request_number=write.superseded_by_request_number,
                upstream_created_at=write.upstream_created_at,
                upstream_updated_at=write.upstream_updated_at,
            )
            .on_conflict_do_nothing(index_elements=[IBSRequest.request_number])
            .returning(IBSRequest.id)
        )
        if inserted is not None:
            return inserted, True, False
        row = await _lock_request(db, number)
        assert row is not None
    if write.upstream_updated_at < row.upstream_updated_at:
        raise _LocalFailure(STALE_REQUEST_CATEGORY, request_number=number)
    observed = (
        write.state.value,
        write.superseded_by_request_number,
        write.upstream_created_at,
    )
    stored = (row.state, row.superseded_by_request_number, row.upstream_created_at)
    if write.upstream_updated_at == row.upstream_updated_at:
        if observed != stored:
            raise _LocalFailure(CONFLICTING_OBSERVATION_CATEGORY, request_number=number)
        return row.id, False, False
    await db.execute(
        update(IBSRequest)
        .where(IBSRequest.id == row.id)
        .values(
            state=write.state.value,
            superseded_by_request_number=write.superseded_by_request_number,
            upstream_created_at=write.upstream_created_at,
            upstream_updated_at=write.upstream_updated_at,
        )
    )
    return row.id, False, True


async def _lock_actions(
    db: AsyncSession, request_ids: dict[int, uuid.UUID]
) -> dict[ActionKey, IBSRequestAction]:
    """Lock every action of the locked requests; keyed by semantic
    identity."""
    numbers = {request_id: number for number, request_id in request_ids.items()}
    rows = (
        await db.execute(
            select(IBSRequestAction)
            .where(IBSRequestAction.ibs_request_id.in_(list(numbers)))
            .order_by(IBSRequestAction.id)
            .with_for_update(key_share=True)
            .execution_options(populate_existing=True)
        )
    ).scalars()
    locked: dict[ActionKey, IBSRequestAction] = {}
    for action in rows:
        retained_key = _row_key(numbers[action.ibs_request_id], action)
        locked[retained_key] = action
    return locked


def _row_key(request_number: int, action: IBSRequestAction) -> ActionKey:
    return action_key(
        request_number,
        IBSRequestActionType(action.action_type),
        source_project=action.source_project,
        source_package=action.source_package,
        target_project=action.target_project,
        target_package=action.target_package,
        target_release_project=action.target_release_project,
    )


def _action_changes(action: IBSRequestAction, write: ActionWrite) -> dict[str, object]:
    """The provenance a retained action gains from `write`.

    A retained non-null value never changes except the target of a
    submission action, which takes the latest observed value; a different
    non-null value of any other field is conflicting provenance. Omission
    never erases a retained value."""
    changes: dict[str, object] = {}
    immutable: tuple[str, ...] = _IMMUTABLE_FIELDS
    mutable: tuple[str, ...] = _RELEASE_TARGET_FIELDS
    if write.action_type is IBSRequestActionType.MAINTENANCE_RELEASE:
        immutable, mutable = (*_IMMUTABLE_FIELDS, *_RELEASE_TARGET_FIELDS), ()
    for name in immutable:
        stored, observed = getattr(action, name), getattr(write, name)
        if observed is None:
            continue
        if stored is None:
            changes[name] = observed
        elif stored != observed:
            raise _LocalFailure(
                CONFLICTING_PROVENANCE_CATEGORY, request_number=write.request_number
            )
    for name in mutable:
        observed = getattr(write, name)
        if observed is not None and getattr(action, name) != observed:
            changes[name] = observed
    return changes


async def _write_evidence(
    db: AsyncSession, scope: IBSRequestScope, observation: Observation
) -> tuple[bool, bool]:
    """Algorithm steps 6-7: requests in ascending request number, then
    actions in identity order, then correlations. Returns `(created,
    updated)`."""
    created = updated = False
    request_ids: dict[int, uuid.UUID] = {}
    for request in sorted(observation.requests, key=lambda w: w.request_number):
        request_id, inserted, changed = await _write_request(db, request)
        request_ids[request.request_number] = request_id
        created |= inserted
        updated |= changed
    if not observation.actions:
        return created, updated
    locked = await _lock_actions(db, request_ids)
    action_ids: list[uuid.UUID] = []
    for write in sorted(observation.actions, key=lambda w: order(w.key)):
        action = locked.get(write.key)
        if action is None:
            inserted_id = await db.scalar(
                insert(IBSRequestAction)
                .values(
                    ibs_request_id=request_ids[write.request_number],
                    action_type=write.action_type.value,
                    source_project=write.source_project,
                    source_package=write.source_package,
                    target_project=write.target_project,
                    target_package=write.target_package,
                    target_release_project=write.target_release_project,
                    logical_package=write.logical_package,
                    codestream_name=write.codestream_name,
                    incident_number=write.incident_number,
                    accepted_revision=write.accepted_revision,
                    accepted_srcmd5=write.accepted_srcmd5,
                )
                .on_conflict_do_nothing()
                .returning(IBSRequestAction.id)
            )
            if inserted_id is not None:
                action_ids.append(inserted_id)
                created = True
                continue
            locked = await _lock_actions(db, request_ids)
            action = locked.get(write.key)
            if action is None:
                raise _LocalFailure(
                    CONFLICTING_PROVENANCE_CATEGORY, request_number=write.request_number
                )
        changes = _action_changes(action, write)
        if changes:
            await db.execute(
                update(IBSRequestAction)
                .where(IBSRequestAction.id == action.id)
                .values(**changes)
            )
            updated = True
        action_ids.append(action.id)
    for action_id in action_ids:
        correlation = await db.scalar(
            insert(IBSRequestActionTrack)
            .values(
                ibs_request_action_id=action_id,
                ticket_package_track_id=scope.track_id,
            )
            .on_conflict_do_nothing(
                constraint="uq_ibs_request_action_track_track_id_action_id"
            )
            .returning(IBSRequestActionTrack.id)
        )
        created |= correlation is not None
    return created, updated


async def _apply_delivery(
    db: AsyncSession,
    scope: IBSRequestScope,
    derived: DeliveryStatus,
    current: DeliveryStatus,
    *,
    unchanged: bool,
) -> bool:
    """Algorithm steps 8-9: apply the derived value from the locked-current
    one. `RELEASED` is never left; a proven release from `PENDING` takes
    two transitions; a negative regression requires the stale-negative
    guard (`unchanged`). Returns whether delivery changed."""
    steps: tuple[DeliveryStatus, ...] = ()
    if current is DeliveryStatus.RELEASED:
        steps = ()
    elif derived is DeliveryStatus.RELEASED:
        steps = (
            (DeliveryStatus.IN_PROGRESS, DeliveryStatus.RELEASED)
            if current is DeliveryStatus.PENDING
            else (DeliveryStatus.RELEASED,)
        )
    elif derived is DeliveryStatus.IN_PROGRESS:
        if current is DeliveryStatus.PENDING:
            steps = (DeliveryStatus.IN_PROGRESS,)
    elif current is DeliveryStatus.IN_PROGRESS and unchanged:
        steps = (DeliveryStatus.PENDING,)
    changed = False
    for target in steps:
        result = await package_service.set_track_delivery_status(
            db,
            ticket_id=scope.ticket_id,
            package_id=scope.package_id,
            track_id=scope.track_id,
            delivery_status=target,
        )
        changed |= result.outcome is package_service.MutationOutcome.CHANGED
    return changed
