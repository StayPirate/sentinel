"""The IBS track release reconciliation boundary.

Implements docs/features/packages/ibs-track-release-detection.md (Scope;
Shared Reconciliation Boundary; Scheduled Reconciliation Algorithm steps
1-8 with Source-Info Validation, Source-Diff Validation, Per-Track Local
Outcome, and Checkpoint Concurrency; First Observation and VA Correction;
Unavailable History Fallback; Error Handling and its Structured Logs) for
the periodic fetcher and the per-Ticket catch-up of
`detect_ibs_track_releases`:

- `load_track_release_candidates()` is the read-only candidate selection:
  IBS tracks in `ANALYSIS` or `AFFECTED` of an active Ticket with a CVE,
  each with its semantic locator and the snapshot used for external-work
  grouping (Ticket CVE, logical package, IBS project, checkpoint). VA
  exclusion, lifecycle, EOL, eligibility, delivery, and actionability never
  narrow the scope.
- `reconcile_ibs_track_releases()` is the I/O orchestration and never takes
  a lock. It requests targeted source info per IBS project (in partitions
  of at most `SOURCE_INFO_PARTITION_SIZE` packages), records unchanged-source
  no-ops without a transaction, then requests one expanded diff per unique
  `(project, package, baseline, current srcmd5)` group (checkpoint
  baselines first, then `orev=0` for first observations and the
  unavailable-history fallback). After each diff it applies the local
  outcome of every dependent track as one independent transaction, so no
  IBS request is made while a Ticket lock is held.
- `_reconcile_track()` is the only function that takes the Ticket row lock:
  it applies `ensure_ticket_operable()`, revalidates the selected scope,
  compares the checkpoint predecessor (the Ticket lock serializes every
  writer), delegates an effective `FIXED` to
  `package_service.set_track_status()` (the sole owner of the mutation, its
  `track_status_changed` event, and Ticket reconciliation), and creates or
  advances the checkpoint.

The per-outcome hook (periodic metrics) runs once for every terminal
outcome: immediately for an unchanged-source no-op or a request-level
failure, and after the commit or rollback of a local unit, before its
session is closed. Committed Ticket convergence effects are drained after
the close; a broker operational error is absorbed by the automatic policy
and any other drain exception propagates. A commit exception or ambiguous
commit outcome propagates without an outcome and terminates the
invocation. Known IBS request failures and `SQLAlchemyError` before
finalization become per-track failures; every other exception, including
`SoftTimeLimitExceeded`, `MemoryError`, and cancellation, propagates.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final, Literal

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ACTIVE_TICKET_STATUSES, PackageStatus, WorkflowType
from app.core.exceptions import TicketNotMutableError
from app.core.identifiers import is_valid_cve_id
from app.database import async_session_factory
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.models.track_release_checkpoint import TrackReleaseCheckpoint
from app.services import package_service
from app.services.ibs_client import (
    IBSAuthenticationError,
    IBSClient,
    IBSCredentialsNotConfiguredError,
    IBSHistoricalRevisionUnavailable,
    IBSResponseDataError,
    is_valid_checksum,
    is_valid_ibs_name,
)
from app.services.ticket_convergence_publication import drain_ticket_convergence
from app.services.ticket_mutations import ensure_ticket_operable

logger = structlog.get_logger(__name__)

SOURCE_INFO_FAILED_EVENT: Final = "ibs_track_release_source_info_failed"
PACKAGE_SOURCE_INVALID_EVENT: Final = "ibs_track_release_package_source_invalid"
DIFF_FAILED_EVENT: Final = "ibs_track_release_diff_failed"
ISSUE_IGNORED_EVENT: Final = "ibs_track_release_issue_ignored"
HISTORY_UNAVAILABLE_EVENT: Final = "ibs_track_release_history_unavailable"
TRACK_FAILED_EVENT: Final = "ibs_track_release_track_failed"
TRACK_STALE_EVENT: Final = "ibs_track_release_track_stale"

TRANSPORT_CATEGORY: Final = "transport"
HTTP_STATUS_CATEGORY: Final = "http_status"
CREDENTIALS_CATEGORY: Final = "credentials_not_configured"
INVALID_CVE_LABEL_CATEGORY: Final = "invalid_cve_label"
HISTORY_UNAVAILABLE_CATEGORY: Final = "history_unavailable"
SCOPE_CHANGED_CATEGORY: Final = "scope_changed"
TICKET_NOT_OPERABLE_CATEGORY: Final = "ticket_not_operable"
STALE_CHECKPOINT_CATEGORY: Final = "stale_checkpoint"
SYSTEM_TARGET_REJECTED_CATEGORY: Final = "system_target_rejected"
DATABASE_CATEGORY: Final = "database"
INVALID_IDENTITY_CATEGORY: Final = "invalid_identity"

SOURCE_INFO_PARTITION_SIZE: Final = 100
"""Most logical packages requested by one targeted source-info request."""

_EMPTY_SOURCE_TREE: Final = "0"
_EVIDENCE_STATES: Final = frozenset({"added", "changed"})
_RELEASABLE_STATUSES: Final = (PackageStatus.ANALYSIS, PackageStatus.AFFECTED)
_REQUEST_ERRORS: Final = (
    IBSCredentialsNotConfiguredError,
    IBSAuthenticationError,
    IBSResponseDataError,
    httpx.HTTPError,
)

TrackReleaseOutcomeKind = Literal["updated", "no_op", "failed"]
_LocalResult = Literal[
    "updated",
    "advanced",
    "already_complete",
    "scope_changed",
    "stale_checkpoint",
    "system_target_rejected",
]


@dataclass(frozen=True, slots=True)
class TrackReleaseCandidate:
    """One selected track and the snapshot used to examine it.

    `track_id`, `package_id`, and `ticket_id` form the semantic locator;
    `cve_id` is the Ticket CVE, `package_name` the logical package,
    `project` the IBS project (`TicketPackageTrack.reference`), and
    `checkpoint` the persisted checkpoint `srcmd5` (`None` before the first
    successful examination), which is also the predecessor revalidated
    under the Ticket lock.
    """

    track_id: uuid.UUID
    package_id: uuid.UUID
    ticket_id: uuid.UUID
    cve_id: str
    package_name: str
    project: str
    checkpoint: str | None


@dataclass(frozen=True, slots=True)
class TrackReleaseOutcome:
    """The terminal outcome of one selected track."""

    track_id: uuid.UUID
    kind: TrackReleaseOutcomeKind


TrackReleaseOutcomeHook = Callable[[TrackReleaseOutcome], None]

_DiffKey = tuple[str, str, str, str]
"""`(project, package, baseline, current srcmd5)` of one diff request."""


async def load_track_release_candidates(
    db: AsyncSession, *, ticket_id: uuid.UUID | None = None
) -> list[TrackReleaseCandidate]:
    """The tracks in the detector's Scope, ordered by track ID.

    Category B (read-only; no lock, write, commit, or rollback). Selects
    every `TicketPackageTrack` with `workflow_type = ibs` and status
    `ANALYSIS` or `AFFECTED` of an active Ticket that has a CVE, including
    excluded and EOL records, with its checkpoint when one exists; with
    `ticket_id`, only that Ticket's tracks (none for a missing, inactive,
    or CVE-less Ticket). Database exceptions propagate.
    """
    statement = (
        select(
            TicketPackageTrack.id,
            TicketPackage.id,
            Ticket.id,
            CVE.cve_id,
            TicketPackage.package_name,
            TicketPackageTrack.reference,
            TrackReleaseCheckpoint.srcmd5,
        )
        .select_from(TicketPackageTrack)
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(Ticket, Ticket.id == TicketPackage.ticket_id)
        .join(CVE, CVE.id == Ticket.cve_id)
        .outerjoin(
            TrackReleaseCheckpoint,
            TrackReleaseCheckpoint.ticket_package_track_id == TicketPackageTrack.id,
        )
        .where(
            TicketPackageTrack.workflow_type == WorkflowType.IBS.value,
            TicketPackageTrack.status.in_(_RELEASABLE_STATUSES),
            Ticket.status.in_(ACTIVE_TICKET_STATUSES),
        )
        .order_by(TicketPackageTrack.id)
    )
    if ticket_id is not None:
        statement = statement.where(Ticket.id == ticket_id)
    rows = (await db.execute(statement)).all()
    return [
        TrackReleaseCandidate(
            track_id=track_id,
            package_id=package_id,
            ticket_id=candidate_ticket_id,
            cve_id=cve_id,
            package_name=package_name,
            project=project,
            checkpoint=checkpoint,
        )
        for (
            track_id,
            package_id,
            candidate_ticket_id,
            cve_id,
            package_name,
            project,
            checkpoint,
        ) in rows
    ]


async def reconcile_ibs_track_releases(
    candidates: Iterable[TrackReleaseCandidate],
    *,
    client: IBSClient,
    fetcher_name: str,
    on_outcome: TrackReleaseOutcomeHook | None = None,
) -> list[TrackReleaseOutcome]:
    """Reconcile the selected tracks against their expanded IBS source state.

    Category A workflow owning one independent transaction per examined
    track (ibs-track-release-detection.md, Shared Reconciliation Boundary).

    Q1: `candidates` come from `load_track_release_candidates()` (or an
    equivalent selection); duplicate track IDs are processed once.
    `client` is the caller's open `IBSClient`; `fetcher_name` identifies
    the caller in per-track logs; `on_outcome`, when given, receives each
    terminal outcome exactly once.

    Q2: acquires no lock and performs IBS I/O only outside every local
    transaction; each local unit serializes on the Ticket row lock in
    `_reconcile_track()`.

    Q3: an empty selection performs no IBS or database work. A track whose
    persisted project, package, or checkpoint the client would reject fails
    alone (`invalid_identity`). Source info is requested once per selected
    logical package per project partition; a request failure fails every
    dependent track (one `ibs_track_release_source_info_failed`) and an
    unusable package fails its tracks (one
    `ibs_track_release_package_source_invalid`). A track whose checkpoint
    equals the current `srcmd5` is a `no_op` without diff or write. Each
    remaining group requests one diff from `0` (no checkpoint) or from the
    checkpoint to the current `srcmd5`; a diff failure fails every
    dependent track (one `ibs_track_release_diff_failed`), and a diff that
    raises `IBSHistoricalRevisionUnavailable` emits one
    `ibs_track_release_history_unavailable` per track and moves the track
    to the `orev=0` diff of the same current `srcmd5`. Invalid canonical
    CVE labels emit at most one `ibs_track_release_issue_ignored` per diff.
    Each examined track then runs in a fresh session: an effective `FIXED`
    is `updated`; a checkpoint-only examination is `no_op` and commits; an
    already-advanced checkpoint is a `no_op` without a write; an
    `Ignored`/`Duplicated` Ticket is a `no_op` with one
    `ibs_track_release_track_stale`; a changed scope, a changed predecessor,
    a rejected system target, or a `SQLAlchemyError` before commit is
    `failed`. Every failed track emits one `ibs_track_release_track_failed`.

    Q4: returns one outcome per distinct selected track (no ordering
    guarantee). Creates no audit event itself.

    Q5: re-invocation re-reads IBS and PostgreSQL and either advances from
    the retained predecessor or produces an idempotent no-op.

    Q6: a commit exception or ambiguous outcome, a rollback failure, a
    non-operational drain exception, `SoftTimeLimitExceeded`,
    `MemoryError`, cancellation, and unexpected exceptions propagate;
    earlier committed tracks remain committed.
    """
    selected: dict[uuid.UUID, TrackReleaseCandidate] = {}
    for candidate in candidates:
        selected.setdefault(candidate.track_id, candidate)
    run = _Reconciliation(client=client, fetcher_name=fetcher_name, hook=on_outcome)
    if selected:
        await run.execute([selected[key] for key in sorted(selected)])
    return run.outcomes


@dataclass
class _Reconciliation:
    """The state of one boundary invocation."""

    client: IBSClient
    fetcher_name: str
    hook: TrackReleaseOutcomeHook | None
    outcomes: list[TrackReleaseOutcome] = field(default_factory=list)

    async def execute(self, ordered: Sequence[TrackReleaseCandidate]) -> None:
        valid: list[TrackReleaseCandidate] = []
        for candidate in ordered:
            if _has_valid_identity(candidate):
                valid.append(candidate)
            else:
                self._fail(candidate, INVALID_IDENTITY_CATEGORY)

        current = await self._observe_sources(valid)

        incremental: dict[_DiffKey, list[TrackReleaseCandidate]] = defaultdict(list)
        initial: dict[_DiffKey, list[TrackReleaseCandidate]] = defaultdict(list)
        for candidate in valid:
            srcmd5 = current.get(candidate.track_id)
            if srcmd5 is None:
                continue
            if candidate.checkpoint == srcmd5:
                self._finish(candidate, "no_op")
                continue
            baseline = candidate.checkpoint or _EMPTY_SOURCE_TREE
            groups = initial if candidate.checkpoint is None else incremental
            groups[
                (candidate.project, candidate.package_name, baseline, srcmd5)
            ].append(candidate)

        for key in sorted(incremental):
            unavailable = await self._examine(key, incremental[key])
            if unavailable:
                project, package, _, srcmd5 = key
                initial[(project, package, _EMPTY_SOURCE_TREE, srcmd5)].extend(
                    unavailable
                )
        for key in sorted(initial):
            await self._examine(key, initial[key])

    async def _observe_sources(
        self, candidates: Sequence[TrackReleaseCandidate]
    ) -> dict[uuid.UUID, str]:
        """The current expanded `srcmd5` of every track whose package is
        usable; every other track has received its failed outcome."""
        by_project: dict[str, dict[str, list[TrackReleaseCandidate]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for candidate in candidates:
            by_project[candidate.project][candidate.package_name].append(candidate)

        current: dict[uuid.UUID, str] = {}
        for project in sorted(by_project):
            dependents_by_package = by_project[project]
            packages = sorted(dependents_by_package)
            for start in range(0, len(packages), SOURCE_INFO_PARTITION_SIZE):
                partition = packages[start : start + SOURCE_INFO_PARTITION_SIZE]
                dependents = [
                    track
                    for package in partition
                    for track in dependents_by_package[package]
                ]
                try:
                    results = await self.client.get_source_info(project, partition)
                except _REQUEST_ERRORS as exc:
                    category, status = _request_failure(exc)
                    logger.warning(
                        SOURCE_INFO_FAILED_EVENT,
                        codestream=project,
                        affected_track_count=len(dependents),
                        reason_category=category,
                        **_http_status(status),
                    )
                    for track in dependents:
                        self._fail(track, category)
                    continue
                for package in partition:
                    result = results[package]
                    tracks = dependents_by_package[package]
                    if result.source_info is None:
                        assert result.failure is not None
                        logger.warning(
                            PACKAGE_SOURCE_INVALID_EVENT,
                            codestream=project,
                            package_name=package,
                            affected_track_count=len(tracks),
                            reason_category=result.failure,
                        )
                        for track in tracks:
                            self._fail(track, result.failure)
                        continue
                    for track in tracks:
                        current[track.track_id] = result.source_info.srcmd5
        return current

    async def _examine(
        self, key: _DiffKey, tracks: Sequence[TrackReleaseCandidate]
    ) -> list[TrackReleaseCandidate]:
        """Request the diff of `key` and apply its tracks' local outcomes.

        Returns the tracks whose checkpoint IBS identified as unavailable;
        they have no outcome yet and continue with the `orev=0` diff.
        """
        project, package, baseline, srcmd5 = key
        try:
            issues = await self.client.get_diff_issues(
                project, package, baseline, srcmd5
            )
        except IBSHistoricalRevisionUnavailable:
            for track in tracks:
                logger.warning(
                    HISTORY_UNAVAILABLE_EVENT,
                    codestream=project,
                    package_name=package,
                    track_id=str(track.track_id),
                    reason_category=HISTORY_UNAVAILABLE_CATEGORY,
                    http_status=httpx.codes.BAD_REQUEST.value,
                )
            return list(tracks)
        except _REQUEST_ERRORS as exc:
            category, status = _request_failure(exc)
            logger.warning(
                DIFF_FAILED_EVENT,
                codestream=project,
                package_name=package,
                affected_track_count=len(tracks),
                reason_category=category,
                **_http_status(status),
            )
            for track in tracks:
                self._fail(track, category)
            return []

        relevant = {track.cve_id for track in tracks}
        evidence: set[str] = set()
        invalid_label = False
        for issue in issues:
            if issue.tracker != "cve" or issue.state not in _EVIDENCE_STATES:
                continue
            if not is_valid_cve_id(issue.label):
                invalid_label = True
            elif issue.label in relevant:
                evidence.add(issue.label)
        if invalid_label:
            logger.warning(
                ISSUE_IGNORED_EVENT,
                codestream=project,
                package_name=package,
                reason_category=INVALID_CVE_LABEL_CATEGORY,
            )
        for track in tracks:
            await self._apply(track, srcmd5=srcmd5, evidence=track.cve_id in evidence)
        return []

    async def _apply(
        self, track: TrackReleaseCandidate, *, srcmd5: str, evidence: bool
    ) -> None:
        """Run one track's local outcome as its own transaction."""
        committed = False
        kind: TrackReleaseOutcomeKind
        async with async_session_factory() as unit:
            try:
                result = await _reconcile_track(
                    unit, track, srcmd5=srcmd5, evidence=evidence
                )
            except TicketNotMutableError:
                await unit.rollback()
                logger.warning(
                    TRACK_STALE_EVENT,
                    codestream=track.project,
                    package_name=track.package_name,
                    track_id=str(track.track_id),
                    ticket_id=str(track.ticket_id),
                    reason_category=TICKET_NOT_OPERABLE_CATEGORY,
                )
                kind = "no_op"
            except SQLAlchemyError:
                await unit.rollback()
                self._log_failed(track, DATABASE_CATEGORY)
                kind = "failed"
            else:
                if result in ("updated", "advanced"):
                    # A commit exception propagates: never a per-track outcome.
                    await unit.commit()
                    committed = True
                    kind = "updated" if result == "updated" else "no_op"
                else:
                    await unit.rollback()
                    if result == "already_complete":
                        kind = "no_op"
                    else:
                        self._log_failed(track, result)
                        kind = "failed"
            # Terminal outcome before any awaitable post-commit action,
            # including the session close.
            self._finish(track, kind)
        if committed:
            await drain_ticket_convergence(unit)

    def _fail(self, track: TrackReleaseCandidate, category: str) -> None:
        self._log_failed(track, category)
        self._finish(track, "failed")

    def _log_failed(self, track: TrackReleaseCandidate, category: str) -> None:
        logger.warning(
            TRACK_FAILED_EVENT,
            codestream=track.project,
            package_name=track.package_name,
            track_id=str(track.track_id),
            ticket_id=str(track.ticket_id),
            fetcher_name=self.fetcher_name,
            reason_category=category,
        )

    def _finish(
        self, track: TrackReleaseCandidate, kind: TrackReleaseOutcomeKind
    ) -> None:
        outcome = TrackReleaseOutcome(track.track_id, kind)
        self.outcomes.append(outcome)
        if self.hook is not None:
            self.hook(outcome)


async def _reconcile_track(
    db: AsyncSession,
    track: TrackReleaseCandidate,
    *,
    srcmd5: str,
    evidence: bool,
) -> _LocalResult:
    """Lock the Ticket, revalidate the track, and apply its local outcome.

    The only function of the detector that takes the Ticket row lock
    (ibs-track-release-detection.md, Per-Track Local Outcome steps 1-6;
    Checkpoint Concurrency). Performs no external I/O and never commits.

    Returns `scope_changed` when the Ticket, track, package, IBS workflow,
    project, package name, or Ticket CVE no longer matches the selection;
    `already_complete` when another handler already accepted `srcmd5`;
    `stale_checkpoint` when the predecessor changed to another value;
    `system_target_rejected` for a `rejected` service result; otherwise it
    calls `set_track_status(..., FIXED)` when `evidence` holds and the
    status is still `ANALYSIS`/`AFFECTED`, creates or advances the
    checkpoint to `srcmd5`, flushes, and returns `updated` for an effective
    transition or `advanced` for a checkpoint-only examination.
    `TicketNotMutableError` and database exceptions propagate.
    """
    ticket = (
        await db.execute(
            select(Ticket)
            .where(Ticket.id == track.ticket_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if ticket is None:
        return "scope_changed"
    ensure_ticket_operable(ticket)

    ticket_cve = (
        await db.scalar(select(CVE.cve_id).where(CVE.id == ticket.cve_id))
        if ticket.cve_id is not None
        else None
    )
    row = (
        await db.execute(
            select(
                TicketPackageTrack.status,
                TicketPackageTrack.workflow_type,
                TicketPackageTrack.reference,
                TicketPackage.package_name,
                TrackReleaseCheckpoint,
            )
            .select_from(TicketPackageTrack)
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .outerjoin(
                TrackReleaseCheckpoint,
                TrackReleaseCheckpoint.ticket_package_track_id == TicketPackageTrack.id,
            )
            .where(
                TicketPackageTrack.id == track.track_id,
                TicketPackage.id == track.package_id,
                TicketPackage.ticket_id == ticket.id,
            )
            .execution_options(populate_existing=True)
        )
    ).one_or_none()
    if (
        row is None
        or row.workflow_type != WorkflowType.IBS.value
        or row.reference != track.project
        or row.package_name != track.package_name
        or ticket_cve != track.cve_id
    ):
        return "scope_changed"

    checkpoint: TrackReleaseCheckpoint | None = row.TrackReleaseCheckpoint
    predecessor = checkpoint.srcmd5 if checkpoint is not None else None
    if predecessor != track.checkpoint:
        return "already_complete" if predecessor == srcmd5 else "stale_checkpoint"

    updated = False
    if evidence and row.status in _RELEASABLE_STATUSES:
        result = await package_service.set_track_status(
            db,
            ticket_id=track.ticket_id,
            package_id=track.package_id,
            track_id=track.track_id,
            status=PackageStatus.FIXED,
            acting_user_id=None,
            caller=package_service.SYSTEM_INVOCATION,
        )
        if result.outcome is package_service.MutationOutcome.REJECTED:
            return "system_target_rejected"
        updated = result.outcome is package_service.MutationOutcome.CHANGED

    accepted_at = datetime.now(UTC)
    if checkpoint is None:
        db.add(
            TrackReleaseCheckpoint(
                ticket_package_track_id=track.track_id,
                srcmd5=srcmd5,
                last_seen_at=accepted_at,
            )
        )
    else:
        checkpoint.srcmd5 = srcmd5
        checkpoint.last_seen_at = accepted_at
    await db.flush()
    return "updated" if updated else "advanced"


def _has_valid_identity(track: TrackReleaseCandidate) -> bool:
    return (
        is_valid_ibs_name(track.project)
        and is_valid_ibs_name(track.package_name)
        and (track.checkpoint is None or is_valid_checksum(track.checkpoint))
    )


def _request_failure(exc: BaseException) -> tuple[str, int | None]:
    """The bounded `reason_category` and optional HTTP status of a failed
    IBS request."""
    if isinstance(exc, IBSCredentialsNotConfiguredError):
        return CREDENTIALS_CATEGORY, None
    if isinstance(exc, IBSAuthenticationError | IBSResponseDataError):
        return exc.reason, None
    if isinstance(exc, httpx.HTTPStatusError):
        return HTTP_STATUS_CATEGORY, exc.response.status_code
    return TRANSPORT_CATEGORY, None


def _http_status(status: int | None) -> dict[str, int]:
    return {} if status is None else {"http_status": status}
