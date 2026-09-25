"""Pure Ticket priority resolution.

Single database-free formula owner for Ticket priority. See
`docs/features/tickets/ticket-priority.md` (Exploitation Level, Decision
Table, Pure Resolution Functions) for the complete contract.

Both functions are Category B: they perform no database access, write,
audit, lock, or external call, and they raise no exception for any value
of their declared input types. Callers select the resolved severity
(`CVE.severity` for a Ticket with a CVE, otherwise
`Ticket.severity_manual`) and read the persisted exploitation evidence;
a Ticket without a CVE passes no evidence and therefore uses the
`unknown` row.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from app.core.enums import Severity, TicketPriority

EPSS_LIKELY_PERCENTILE_THRESHOLD: Final = 0.95
"""EPSS percentile (inclusive) at or above which exploitation is `likely`.

A specification constant, not a setting. It compares the persisted
percentile, never the EPSS probability score.
"""

_SSVC_ACTIVE: Final = "active"
_SSVC_POC: Final = "poc"


class ExploitationLevel(StrEnum):
    """Internal classification of the exploitation evidence of a CVE.

    Service-internal: neither persisted nor serialized. See
    `docs/features/tickets/ticket-priority.md` (Exploitation Level).
    """

    KEV = "kev"
    ACTIVE = "active"
    LIKELY = "likely"
    UNKNOWN = "unknown"


_P1, _P2, _P3, _P4 = (
    TicketPriority.P1,
    TicketPriority.P2,
    TicketPriority.P3,
    TicketPriority.P4,
)


def _row(
    critical: TicketPriority,
    high: TicketPriority,
    medium: TicketPriority,
    low_or_none: TicketPriority,
    unresolved: TicketPriority | None,
) -> Mapping[Severity | None, TicketPriority | None]:
    return MappingProxyType(
        {
            Severity.CRITICAL: critical,
            Severity.HIGH: high,
            Severity.MEDIUM: medium,
            Severity.LOW: low_or_none,
            Severity.NONE: low_or_none,
            None: unresolved,
        }
    )


# Decision Table: exploitation level -> resolved severity (Python `None`
# meaning SQL `NULL`, distinct from `Severity.NONE`) -> automatic priority.
_DECISION_TABLE: Final[
    Mapping[ExploitationLevel, Mapping[Severity | None, TicketPriority | None]]
] = MappingProxyType(
    {
        ExploitationLevel.KEV: _row(_P1, _P1, _P1, _P1, _P1),
        ExploitationLevel.ACTIVE: _row(_P1, _P1, _P2, _P3, _P2),
        ExploitationLevel.LIKELY: _row(_P2, _P2, _P3, _P4, _P3),
        ExploitationLevel.UNKNOWN: _row(_P2, _P3, _P4, _P4, None),
    }
)


def classify_exploitation(
    *,
    kev_listed: bool,
    ssvc_exploitation: str | None,
    epss_percentile: float | None,
) -> ExploitationLevel:
    """Classify the persisted exploitation evidence of one CVE.

    `kev_listed` states whether a `CVEKEVEntry` exists;
    `ssvc_exploitation` is the persisted `CVESSVCAssessment.exploitation`
    or `None` when no assessment exists; `epss_percentile` is the
    persisted `CVEEPSSScore.percentile` or `None` when no score exists.

    The first matching level wins: `kev` when KEV-listed; `active` when
    SSVC exploitation is `active`; `likely` when SSVC exploitation is
    `poc` or the EPSS percentile is at least
    `EPSS_LIKELY_PERCENTILE_THRESHOLD`; otherwise `unknown`. Any other
    SSVC value (including `none`) contributes no evidence. Infallible.
    """
    if kev_listed:
        return ExploitationLevel.KEV
    if ssvc_exploitation == _SSVC_ACTIVE:
        return ExploitationLevel.ACTIVE
    if ssvc_exploitation == _SSVC_POC or (
        epss_percentile is not None
        and epss_percentile >= EPSS_LIKELY_PERCENTILE_THRESHOLD
    ):
        return ExploitationLevel.LIKELY
    return ExploitationLevel.UNKNOWN


def resolve_priority(
    severity: Severity | None,
    exploitation: ExploitationLevel,
) -> TicketPriority | None:
    """Return the Decision Table cell for a resolved severity and evidence.

    `severity` is the resolved severity label; `None` means SQL `NULL`
    (unresolved), distinct from the `Severity.NONE` label, which shares
    the `Low or None` column. Returns `None` (not yet prioritizable) only
    for unresolved severity with `unknown` exploitation. Infallible.
    """
    return _DECISION_TABLE[exploitation][severity]
