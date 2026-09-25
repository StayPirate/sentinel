"""Unit tests for pure Ticket priority resolution
(backend/app/services/ticket_priority.py).

Covers `docs/features/tickets/ticket-priority.md` (Testing Requirements 1-2):
every Decision Table cell (including the `None` severity label versus SQL
`NULL`), the exploitation precedence, the EPSS percentile boundary, ignored
SSVC values and non-inputs, and CVE-less Tickets. Refresh points, the
override, audit, and the API surface (Requirements 3-9) belong to the
service and API work items that persist priority.

The expected Decision Table is transcribed independently from the
specification rather than read back from the module.
"""

from __future__ import annotations

import inspect
import itertools

import pytest

from app.core import enums
from app.core.enums import Severity, TicketPriority
from app.services import ticket_priority
from app.services.ticket_priority import (
    EPSS_LIKELY_PERCENTILE_THRESHOLD,
    ExploitationLevel,
    classify_exploitation,
    resolve_priority,
)
from tests.support.module_imports import (
    APP_ROOT,
    forbidden_imports,
    imported_modules,
)

P1, P2, P3, P4 = (
    TicketPriority.P1,
    TicketPriority.P2,
    TicketPriority.P3,
    TicketPriority.P4,
)

# ticket-priority.md (Decision Table). Columns: Critical, High, Medium,
# Low or None, Severity NULL.
SPEC_DECISION_TABLE: dict[str, tuple[TicketPriority | None, ...]] = {
    "kev": (P1, P1, P1, P1, P1),
    "active": (P1, P1, P2, P3, P2),
    "likely": (P2, P2, P3, P4, P3),
    "unknown": (P2, P3, P4, P4, None),
}


def _decision_cells() -> list[tuple[str, Severity | None, TicketPriority | None]]:
    cells: list[tuple[str, Severity | None, TicketPriority | None]] = []
    for level, (
        critical,
        high,
        medium,
        low_or_none,
        unresolved,
    ) in SPEC_DECISION_TABLE.items():
        cells += [
            (level, Severity.CRITICAL, critical),
            (level, Severity.HIGH, high),
            (level, Severity.MEDIUM, medium),
            (level, Severity.LOW, low_or_none),
            (level, Severity.NONE, low_or_none),
            (level, None, unresolved),
        ]
    return cells


@pytest.mark.unit
class TestExploitationLevelEnum:
    def test_exact_values(self) -> None:
        assert [member.value for member in ExploitationLevel] == [
            "kev",
            "active",
            "likely",
            "unknown",
        ]

    def test_is_service_internal_not_core(self) -> None:
        assert not hasattr(enums, "ExploitationLevel")
        assert ExploitationLevel.__module__ == "app.services.ticket_priority"


@pytest.mark.unit
class TestResolvePriority:
    @pytest.mark.parametrize(("level", "severity", "expected"), _decision_cells())
    def test_decision_table_cell(
        self,
        level: str,
        severity: Severity | None,
        expected: TicketPriority | None,
    ) -> None:
        assert resolve_priority(severity, ExploitationLevel(level)) == expected

    def test_all_twenty_specified_cells_are_covered(self) -> None:
        cells = {
            (level, column)
            for level, row in SPEC_DECISION_TABLE.items()
            for column in range(len(row))
        }
        assert len(cells) == 20

    def test_severity_none_label_differs_from_sql_null(self) -> None:
        unknown = ExploitationLevel.UNKNOWN

        assert resolve_priority(Severity.NONE, unknown) == P4
        assert resolve_priority(None, unknown) is None

    def test_null_only_for_unresolved_severity_with_unknown_evidence(self) -> None:
        null_cells = [
            (severity, level)
            for severity, level in itertools.product(
                [*Severity, None], ExploitationLevel
            )
            if resolve_priority(severity, level) is None
        ]

        assert null_cells == [(None, ExploitationLevel.UNKNOWN)]

    def test_returns_ticket_priority_members(self) -> None:
        for severity, level in itertools.product([*Severity, None], ExploitationLevel):
            result = resolve_priority(severity, level)
            assert result is None or type(result) is TicketPriority


@pytest.mark.unit
class TestClassifyExploitation:
    def test_no_evidence_is_unknown(self) -> None:
        assert (
            classify_exploitation(
                kev_listed=False, ssvc_exploitation=None, epss_percentile=None
            )
            is ExploitationLevel.UNKNOWN
        )

    @pytest.mark.parametrize("ssvc", [None, "none", "poc", "active"])
    @pytest.mark.parametrize("epss", [None, 0.0, 0.5, 0.95, 1.0])
    def test_kev_wins_over_every_other_evidence(
        self, ssvc: str | None, epss: float | None
    ) -> None:
        assert (
            classify_exploitation(
                kev_listed=True, ssvc_exploitation=ssvc, epss_percentile=epss
            )
            is ExploitationLevel.KEV
        )

    @pytest.mark.parametrize("epss", [None, 0.0, 0.94, 0.95, 1.0])
    def test_ssvc_active_wins_over_poc_level_evidence(self, epss: float | None) -> None:
        assert (
            classify_exploitation(
                kev_listed=False, ssvc_exploitation="active", epss_percentile=epss
            )
            is ExploitationLevel.ACTIVE
        )

    @pytest.mark.parametrize("epss", [None, 0.0, 0.5])
    def test_ssvc_poc_is_likely(self, epss: float | None) -> None:
        assert (
            classify_exploitation(
                kev_listed=False, ssvc_exploitation="poc", epss_percentile=epss
            )
            is ExploitationLevel.LIKELY
        )

    def test_epss_threshold_is_the_specified_constant(self) -> None:
        assert EPSS_LIKELY_PERCENTILE_THRESHOLD == 0.95

    @pytest.mark.parametrize(
        ("percentile", "expected"),
        [
            (0.95, ExploitationLevel.LIKELY),
            (0.9500001, ExploitationLevel.LIKELY),
            (1.0, ExploitationLevel.LIKELY),
            (0.9499999, ExploitationLevel.UNKNOWN),
            (0.94, ExploitationLevel.UNKNOWN),
            (0.0, ExploitationLevel.UNKNOWN),
        ],
    )
    def test_epss_percentile_boundary(
        self, percentile: float, expected: ExploitationLevel
    ) -> None:
        assert (
            classify_exploitation(
                kev_listed=False, ssvc_exploitation=None, epss_percentile=percentile
            )
            is expected
        )

    @pytest.mark.parametrize(
        "ssvc",
        ["none", "", "Active", "POC", "unknown", "total", "yes", " active"],
    )
    def test_other_ssvc_values_contribute_no_evidence(self, ssvc: str) -> None:
        assert (
            classify_exploitation(
                kev_listed=False, ssvc_exploitation=ssvc, epss_percentile=None
            )
            is ExploitationLevel.UNKNOWN
        )

    def test_ssvc_none_with_high_epss_is_likely(self) -> None:
        assert (
            classify_exploitation(
                kev_listed=False, ssvc_exploitation="none", epss_percentile=0.99
            )
            is ExploitationLevel.LIKELY
        )

    def test_nan_percentile_is_not_evidence_and_does_not_raise(self) -> None:
        assert (
            classify_exploitation(
                kev_listed=False, ssvc_exploitation=None, epss_percentile=float("nan")
            )
            is ExploitationLevel.UNKNOWN
        )

    def test_only_specified_inputs_exist(self) -> None:
        """The EPSS score, SSVC `automatable`/`technical_impact`, CWE, and every
        other CVE field cannot influence the result: they are not parameters."""
        parameters = inspect.signature(classify_exploitation).parameters

        assert list(parameters) == [
            "kev_listed",
            "ssvc_exploitation",
            "epss_percentile",
        ]
        assert all(
            p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values()
        )


@pytest.mark.unit
class TestCveLessTickets:
    """A Ticket without a CVE passes no evidence and uses `severity_manual`
    with the `unknown` row (ticket-priority.md, Decision Table)."""

    @staticmethod
    def _cve_less_priority(severity_manual: Severity | None) -> TicketPriority | None:
        level = classify_exploitation(
            kev_listed=False, ssvc_exploitation=None, epss_percentile=None
        )
        return resolve_priority(severity_manual, level)

    @pytest.mark.parametrize(
        ("severity_manual", "expected"),
        [
            (Severity.CRITICAL, P2),
            (Severity.HIGH, P3),
            (Severity.MEDIUM, P4),
            (Severity.LOW, P4),
            (Severity.NONE, P4),
        ],
    )
    def test_uses_unknown_row(
        self, severity_manual: Severity, expected: TicketPriority
    ) -> None:
        assert self._cve_less_priority(severity_manual) == expected

    def test_unset_severity_manual_gives_null_priority(self) -> None:
        assert self._cve_less_priority(None) is None


@pytest.mark.unit
class TestTicketPriorityModuleBoundary:
    def test_imports_only_core_enums_from_app(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "ticket_priority.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.")} == {"app.core.enums"}
        assert forbidden_imports(modules) == set()

    def test_public_functions_are_synchronous(self) -> None:
        assert not inspect.iscoroutinefunction(ticket_priority.classify_exploitation)
        assert not inspect.iscoroutinefunction(ticket_priority.resolve_priority)
