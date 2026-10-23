"""Integration tests for the example dataset loader
(backend/app/services/example_dataset.py).

Owning specifications: docs/features/platform/example-dataset.md (Loading
Rules, Service, Dataset Content) and docs/features/platform/testing-strategy.md
(Mandatory Test Scenarios > Example Dataset). The command output (step
report, messages, and exit codes) is verified by the CLI test module; this
module verifies the service.

Every expected value is transcribed literally from Dataset Content. Nothing
is imported from the loader's dataset tables, so a drift between the loader
and the specification fails here.

Each load runs in a dedicated database migrated to the head revision
(`tests/support/example_dataset.py`), from a synchronous test through its
own `asyncio.run()` (Sync Entry-Point Tests); every read uses a fresh
`NullPool` engine that is disposed on the event loop that opened it. The
shared `loaded` database is loaded once with the load instant pinned to `T`
through the `_utc_now()` clock seam, so time-relative values are asserted
exactly: `D = T.date()`, `T - n d`, and `D +/- n`.

Dedicated databases of the module: `loaded`, `empty` (the guard and the
first-operation failure, which leave it empty), and one each for the
isolation load, the three failures that commit operations, and the two
registered effects.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any, Final

import pytest
from sqlalchemy import Table, delete, func, select
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import aliased

from app.core.enums import (
    DeliveryStatus,
    LifecyclePhase,
    PackageStatus,
    Role,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.core.passwords import verify_password
from app.core.permissions import get_effective_scope
from app.database import Base, register_post_commit_callback
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.mixins import AuditEventMixin
from app.models.product import Product
from app.models.product_repository import ProductRepository
from app.models.setting_audit_event import SettingAuditEvent
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.ticket_reference import TicketReference
from app.models.user import User
from app.models.user_role import UserRole
from app.services import example_dataset, package_service, ticket_service, user_service
from app.services import settings as settings_service
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.example_dataset import (
    ExampleDatasetEffectError,
    ExampleDatasetNotEmptyError,
    ExampleDatasetProgress,
    load_example_dataset,
)
from app.services.packages.maintainer_workbench import MaintainerWorkItem
from app.services.product_lifecycle import evaluate_product_lifecycle_phase
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
    register_ticket_convergence,
)
from app.services.ticket_severity import resolved_severity_expression
from app.services.ticket_visibility import TicketCaller
from tests.support.example_dataset import (
    dataset_database,
    dataset_engine,
    production_registries,
    session_factory,
)
from tests.support.no_outbound import DatabaseEndpoint, OutboundGuard
from tests.support.post_ingest_resolution import record_publications

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Dataset Content, transcribed from docs/features/platform/example-dataset.md
# ---------------------------------------------------------------------------

DATASET_PASSWORD: Final = "example-dataset-password"
"""Credentials."""

STEP_NAMES: Final = (
    "Users",
    "System settings",
    "Fetchers",
    "Product catalog",
    "CVEs and tickets",
    "Ticket work",
)
"""Steps and Transactions."""

USERS: Final[dict[str, tuple[str, str, bool, tuple[Role, ...]]]] = {
    "jdoe": ("John Doe", "john.doe@example.com", True, (Role.ADMIN,)),
    "asmith": (
        "Alice Smith",
        "alice.smith@example.com",
        True,
        (Role.VULNERABILITY_ANALYST,),
    ),
    "bwilson": (
        "Bob Wilson",
        "bob.wilson@example.com",
        True,
        (Role.VULNERABILITY_ANALYST,),
    ),
    "cwhite": (
        "Carol White",
        "carol.white@example.com",
        True,
        (Role.RESTRICTED_ANALYST,),
    ),
    "dbrown": ("Dave Brown", "dave.brown@example.com", True, ()),
    "eblack": (
        "Eve Black",
        "eve.black@example.com",
        False,
        (Role.VULNERABILITY_ANALYST,),
    ),
}
"""Users: username -> (full name, email, active, roles), in creation order."""

ROLE_WIRE: Final = {
    Role.ADMIN: "admin",
    Role.VULNERABILITY_ANALYST: "vulnerability_analyst",
    Role.RESTRICTED_ANALYST: "restricted_analyst",
}
"""The role names of the Users table, as identity events record them."""

SERVER_16: Final = "cpe:/o:example:fles:16.0"
SERVER_15_SP7: Final = "cpe:/o:example:fles:15:sp7"
LTSS_15_SP5: Final = "cpe:/o:example:fles-ltss:15:sp5"
LTSS_15_SP4: Final = "cpe:/o:example:fles-ltss:15:sp4"
SERVER_15_SP3: Final = "cpe:/o:example:fles:15:sp3"
SERVER_17: Final = "cpe:/o:example:fles:17.0"
MICRO_6_2: Final = "cpe:/o:example:fles-micro:6.2"

Offsets = tuple[int | None, int | None, int | None, int | None]

PRODUCTS: Final[
    dict[
        str,
        tuple[str, str, str, str, Offsets | None, LifecyclePhase | None, str | None],
    ]
] = {
    SERVER_16: (
        "FLES",
        "16.0",
        "Fictional Linux Enterprise Server 16.0",
        "SUSE:Updates:FLES:16.0:x86_64",
        (-365, 1825, None, None),
        LifecyclePhase.GENERAL_SUPPORT,
        None,
    ),
    SERVER_15_SP7: (
        "FLES",
        "15-SP7",
        "Fictional Linux Enterprise Server 15 SP7",
        "SUSE:Updates:FLES:15-SP7:x86_64",
        (-730, 365, None, None),
        LifecyclePhase.GENERAL_SUPPORT,
        None,
    ),
    LTSS_15_SP5: (
        "FLES-LTSS",
        "15-SP5",
        "Fictional Linux Enterprise Server LTSS 15 SP5",
        "SUSE:Updates:FLES-LTSS:15-SP5:x86_64",
        (-1460, -365, 730, None),
        LifecyclePhase.EXTENDED_SUPPORT,
        "7.0",
    ),
    LTSS_15_SP4: (
        "FLES-LTSS",
        "15-SP4",
        "Fictional Linux Enterprise Server LTSS 15 SP4",
        "SUSE:Updates:FLES-LTSS:15-SP4:x86_64",
        (-1825, -730, -30, 365),
        LifecyclePhase.REACTIVE_SUPPORT,
        None,
    ),
    SERVER_15_SP3: (
        "FLES",
        "15-SP3",
        "Fictional Linux Enterprise Server 15 SP3",
        "SUSE:Updates:FLES:15-SP3:x86_64",
        (-2555, -1460, -365, None),
        LifecyclePhase.EOL,
        None,
    ),
    SERVER_17: (
        "FLES",
        "17.0",
        "Fictional Linux Enterprise Server 17.0",
        "SUSE:Updates:FLES:17.0:x86_64",
        (180, 2000, None, None),
        LifecyclePhase.PRE_RELEASE,
        None,
    ),
    MICRO_6_2: (
        "FLES-Micro",
        "6.2",
        "Fictional Linux Enterprise Micro 6.2",
        "SUSE:Updates:FLES-Micro:6.2:x86_64",
        None,
        None,
        None,
    ),
}
"""Product Catalog: CPE -> (name, version, display name, repository,
lifecycle offsets from `D` for FCS, GS end, ES end, and RS end, phase at
`D` (`None` is unavailable), CVSS threshold)."""

NVD_VECTORS: Final = {
    "CVE-2099-0001": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVE-2099-0002": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "CVE-2099-0003": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "CVE-2099-0004": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    "CVE-2099-0005": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "CVE-2099-0007": (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    ),
    "CVE-2099-0009": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CVE-2099-0010": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "CVE-2099-0011": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CVE-2099-0012": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVE-2099-0013": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "CVE-2099-0014": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "CVE-2099-0015": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "CVE-2099-0016": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CVE-2099-0017": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    "CVE-2099-0018": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVE-2099-0019": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CVE-2099-0020": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CVE-2099-0021": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
    "CVE-2099-0022": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "CVE-2099-0023": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
}
"""CVEs: the NVD CVSS vector of every CVE that an NVD ingestion supplies."""

SUSE_VECTORS: Final = {
    "CVE-2099-0013": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "CVE-2099-0014": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "CVE-2099-0015": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "CVE-2099-0016": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
}
"""CVEs: the SUSE assessments."""

CWES: Final = {
    "CVE-2099-0001": "CWE-787",
    "CVE-2099-0002": "CWE-79",
    "CVE-2099-0003": "CWE-200",
    "CVE-2099-0009": "CWE-22",
    "CVE-2099-0011": "CWE-416",
    "CVE-2099-0013": "CWE-400",
    "CVE-2099-0014": "CWE-787",
    "CVE-2099-0016": "CWE-125",
    "CVE-2099-0018": "CWE-287",
}

CVE_IDS: Final = tuple(f"CVE-2099-{n:04d}" for n in range(1, 24))
MITRE_INGESTED: Final = frozenset(
    {"CVE-2099-0006", "CVE-2099-0008", "CVE-2099-0009", "CVE-2099-0010"}
)
"""CVEs with a MITRE ingestion (first or further), which supplies the title."""
REJECTED_CVE: Final = "CVE-2099-0008"

EPSS: Final = {
    "CVE-2099-0001": (0.94, 0.99),
    "CVE-2099-0002": (0.12, 0.85),
    "CVE-2099-0010": (0.02, 0.40),
    "CVE-2099-0018": (0.31, 0.92),
}
"""EPSS: score and percentile, each assessed `D - 1`."""

CRITICAL, HIGH, MEDIUM = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM
LOW, NONE = Severity.LOW, Severity.NONE
NEW, ANALYSIS, ANALYZED = TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.ANALYZED
RESOLVED, IGNORED = TicketStatus.RESOLVED, TicketStatus.IGNORED
DUPLICATED = TicketStatus.DUPLICATED

TICKETS: Final[
    dict[int, tuple[str | None, TicketStatus, str | None, bool, Severity | None]]
] = {
    1: ("CVE-2099-0001", NEW, None, False, CRITICAL),
    2: ("CVE-2099-0002", NEW, None, False, HIGH),
    3: ("CVE-2099-0003", NEW, None, False, MEDIUM),
    4: ("CVE-2099-0004", NEW, None, False, LOW),
    5: ("CVE-2099-0005", NEW, None, False, NONE),
    6: ("CVE-2099-0006", NEW, None, False, None),
    7: ("CVE-2099-0007", NEW, None, False, CRITICAL),
    8: ("CVE-2099-0008", IGNORED, None, False, None),
    9: ("CVE-2099-0009", NEW, None, False, HIGH),
    10: ("CVE-2099-0010", NEW, None, False, MEDIUM),
    11: ("CVE-2099-0011", ANALYSIS, "bwilson", False, HIGH),
    12: ("CVE-2099-0012", ANALYSIS, "asmith", False, HIGH),
    13: ("CVE-2099-0013", ANALYZED, "asmith", False, HIGH),
    14: ("CVE-2099-0014", RESOLVED, "asmith", False, HIGH),
    15: ("CVE-2099-0015", RESOLVED, "bwilson", False, MEDIUM),
    16: ("CVE-2099-0016", RESOLVED, "asmith", False, MEDIUM),
    17: ("CVE-2099-0017", IGNORED, "bwilson", False, MEDIUM),
    18: ("CVE-2099-0018", ANALYSIS, "asmith", True, CRITICAL),
    19: ("CVE-2099-0019", ANALYSIS, "bwilson", True, HIGH),
    20: ("CVE-2099-0020", NEW, None, False, MEDIUM),
    21: (None, ANALYSIS, "asmith", False, HIGH),
    22: (None, DUPLICATED, "bwilson", False, None),
    23: ("CVE-2099-0021", NEW, None, False, LOW),
    24: ("CVE-2099-0022", NEW, None, False, HIGH),
    25: ("CVE-2099-0023", NEW, None, False, MEDIUM),
}
"""Tickets: `SNTL-n` -> (CVE, status, assignee, confidential, resolved
severity; `None` is unresolved)."""

GIT_16: Final = "fles-16.0"
SP7_UPDATE: Final = "SUSE:FLES-15-SP7:Update"
SP5_UPDATE: Final = "SUSE:FLES-15-SP5:Update"
SP4_UPDATE: Final = "SUSE:FLES-15-SP4:Update"
SP3_UPDATE: Final = "SUSE:FLES-15-SP3:Update"
GIT, IBS = WorkflowType.GIT, WorkflowType.IBS
AFFECTED, FIXED = PackageStatus.AFFECTED, PackageStatus.FIXED
P_PENDING, P_IN_PROGRESS = DeliveryStatus.PENDING, DeliveryStatus.IN_PROGRESS
P_RELEASED = DeliveryStatus.RELEASED

RELEASED: Final = "released"
"""Marks a Product occurrence released at `T - 2d`."""

TrackKey = tuple[int, str, str]
"""(SNTL number, package, track reference)."""

TRACKS: Final[
    dict[
        TrackKey,
        tuple[WorkflowType, PackageStatus, DeliveryStatus, dict[str, tuple[bool, str]]],
    ]
] = {
    (11, "fictional-curl", GIT_16): (
        GIT,
        AFFECTED,
        P_PENDING,
        {SERVER_16: (True, ""), MICRO_6_2: (True, "")},
    ),
    (11, "fictional-curl", SP7_UPDATE): (
        IBS,
        PackageStatus.ANALYSIS,
        P_PENDING,
        {SERVER_15_SP7: (True, "")},
    ),
    (13, "fictional-httpd", SP7_UPDATE): (
        IBS,
        AFFECTED,
        P_IN_PROGRESS,
        {SERVER_15_SP7: (True, "")},
    ),
    (14, "fictional-libxml", SP7_UPDATE): (
        IBS,
        FIXED,
        P_RELEASED,
        {SERVER_15_SP7: (True, RELEASED)},
    ),
    (15, "fictional-sudo", GIT_16): (
        GIT,
        PackageStatus.NOT_AFFECTED,
        P_PENDING,
        {SERVER_16: (True, ""), MICRO_6_2: (True, "")},
    ),
    (15, "fictional-sudo", SP4_UPDATE): (
        IBS,
        PackageStatus.WONT_FIX,
        P_PENDING,
        {LTSS_15_SP4: (False, "")},
    ),
    (16, "fictional-kernel", SP5_UPDATE): (
        IBS,
        AFFECTED,
        P_PENDING,
        {LTSS_15_SP5: (False, "")},
    ),
    (16, "fictional-kernel", SP3_UPDATE): (
        IBS,
        PackageStatus.ANALYSIS,
        P_PENDING,
        {SERVER_15_SP3: (True, "")},
    ),
    (18, "fictional-openssh", SP7_UPDATE): (
        IBS,
        AFFECTED,
        P_IN_PROGRESS,
        {SERVER_15_SP7: (True, "")},
    ),
}
"""Packages, Tracks, and Maintainers: track -> (workflow, status, delivery,
Products as CPE -> (eligible, `RELEASED` or "" for unreleased))."""

MAINTAINED: Final = frozenset(
    {
        (11, "fictional-curl"),
        (13, "fictional-httpd"),
        (14, "fictional-libxml"),
        (18, "fictional-openssh"),
    }
)
"""The packages that `dbrown` maintains."""

MI, MR = "maintenance_incident", "maintenance_release"
BRANCHES: Final = "SUSE:FLES-15-SP7:Branches"

IBS_REQUESTS: Final[dict[int, tuple[str, int, int, str, int]]] = {
    900000: (MI, 13, 20, "declined", 18),
    900001: (MI, 13, 5, "review", 4),
    900002: (MI, 14, 12, "accepted", 10),
    900003: (MR, 14, 6, "accepted", 3),
    900004: (MI, 18, 9, "accepted", 8),
    900005: (MR, 18, 2, "new", 2),
}
"""IBS Requests: number -> (type, SNTL number, upstream created in days
before `T`, final state, upstream update of the final state in days before
`T`, from the last observation that holds the request)."""

IBS_ACTIONS: Final[
    dict[
        int,
        tuple[
            str,
            str,
            str,
            str | None,
            str | None,
            str | None,
            str,
            str,
            int | None,
            str | None,
            str | None,
        ],
    ]
] = {
    900000: (
        MI,
        BRANCHES,
        "fictional-httpd.SUSE_FLES-15-SP7_Update",
        None,
        None,
        SP7_UPDATE,
        "fictional-httpd",
        SP7_UPDATE,
        None,
        None,
        None,
    ),
    900001: (
        MI,
        BRANCHES,
        "fictional-httpd.SUSE_FLES-15-SP7_Update",
        None,
        None,
        SP7_UPDATE,
        "fictional-httpd",
        SP7_UPDATE,
        None,
        None,
        None,
    ),
    900002: (
        MI,
        BRANCHES,
        "fictional-libxml.SUSE_FLES-15-SP7_Update",
        "SUSE:Maintenance:90001",
        "fictional-libxml.SUSE_FLES-15-SP7_Update",
        SP7_UPDATE,
        "fictional-libxml",
        SP7_UPDATE,
        90001,
        "1",
        "00000000000000000000000000900002",
    ),
    900003: (
        MR,
        "SUSE:Maintenance:90001",
        "fictional-libxml.SUSE_FLES-15-SP7_Update",
        SP7_UPDATE,
        "fictional-libxml.90001",
        None,
        "fictional-libxml",
        SP7_UPDATE,
        90001,
        "1",
        "00000000000000000000000000900003",
    ),
    900004: (
        MI,
        BRANCHES,
        "fictional-openssh.SUSE_FLES-15-SP7_Update",
        "SUSE:Maintenance:90002",
        "fictional-openssh.SUSE_FLES-15-SP7_Update",
        SP7_UPDATE,
        "fictional-openssh",
        SP7_UPDATE,
        90002,
        "1",
        "00000000000000000000000000900004",
    ),
    900005: (
        MR,
        "SUSE:Maintenance:90002",
        "fictional-openssh.SUSE_FLES-15-SP7_Update",
        SP7_UPDATE,
        "fictional-openssh.90002",
        None,
        "fictional-openssh",
        SP7_UPDATE,
        90002,
        None,
        None,
    ),
}
"""IBS Requests: the one action of each request as (type, source project,
source package, target project, target package, target release project,
logical package, codestream, incident, accepted revision, accepted
checksum)."""

REFERENCES: Final = {
    (
        1,
        "https://www.example.com/advisories/CVE-2099-0001",
        None,
        "advisory",
        "sync_nvd_cves",
    ),
    (
        1,
        "https://git.example.com/fictional-lib/commit/0123abc",
        None,
        "patch",
        "sync_nvd_cves",
    ),
    (
        12,
        "https://bugzilla.example.com/show_bug.cgi?id=1000012",
        "Fictional bug report",
        "issue",
        "manual",
    ),
}
"""References: (SNTL number, URL, title, type, source). The automatic types
follow the upstream tags (ticket-references.md, CVE Source Tag Mapping)."""

TICKET_EVENT_TYPES: Final = frozenset(
    {
        "ticket_created",
        "assignment",
        "status_change",
        "cve_associated",
        "cvss_assessment_changed",
        "product_eligibility_changed",
        "package_added",
        "package_maintainer_added",
        "track_status_changed",
        "product_released",
        "priority_changed",
        "reference_added",
        "coordinated_release_changed",
        "confidentiality_changed",
        "access_grant_added",
        "duplicate_set",
    }
)
"""Audit Trails: the Ticket events that the dataset names."""

ATTRIBUTED_TICKET_EVENTS: Final = frozenset(
    {
        # Tickets, "Created by": ingestion (system) or the manual creator.
        *((n, "ticket_created", None) for n in (*range(1, 18), 23, 24, 25)),
        (18, "ticket_created", "asmith"),
        (19, "ticket_created", "bwilson"),
        (20, "ticket_created", "cwhite"),
        (21, "ticket_created", "asmith"),
        (22, "ticket_created", "bwilson"),
        (18, "coordinated_release_changed", "asmith"),
        # Ticket work: the direct event of each operation, by its actor.
        (11, "package_added", "bwilson"),
        (11, "track_status_changed", "bwilson"),
        (12, "assignment", "bwilson"),
        (12, "priority_changed", "bwilson"),
        (12, "reference_added", "asmith"),
        (13, "package_added", "asmith"),
        (13, "track_status_changed", "asmith"),
        (13, "cvss_assessment_changed", "asmith"),
        (14, "package_added", "asmith"),
        (14, "track_status_changed", "asmith"),
        (14, "cvss_assessment_changed", "asmith"),
        (14, "track_status_changed", None),  # track release detection
        (14, "product_released", None),  # Product release detection
        (15, "package_added", "bwilson"),
        (15, "track_status_changed", "bwilson"),
        (15, "cvss_assessment_changed", "bwilson"),
        (16, "package_added", "asmith"),
        (16, "track_status_changed", "asmith"),
        (16, "cvss_assessment_changed", "asmith"),
        (17, "status_change", "bwilson"),
        (18, "package_added", "asmith"),
        (18, "track_status_changed", "asmith"),
        (18, "access_grant_added", "asmith"),
        (19, "confidentiality_changed", "bwilson"),
        (22, "duplicate_set", "bwilson"),
        # Maintainership is system-attributed (ticket-audit-log.md).
        *((n, "package_maintainer_added", None) for n in (11, 13, 14, 18)),
    }
)
"""Attribution: `(SNTL number, Ticket event, actor)` that the dataset
operations produce; `None` is the system actor."""

# ---------------------------------------------------------------------------
# Coverage exception lists (testing-strategy.md, Example Dataset > Coverage)
# ---------------------------------------------------------------------------

TABLE_EXCEPTIONS: Final = frozenset(
    {
        "api_key",  # API keys are out of scope (example-dataset.md, Scope)
        "fetcher_run",  # fetcher run history is out of scope
        "session",  # sessions are out of scope
        "track_release_checkpoint",  # IBS track release checkpoints are out of scope
    }
)

ENUM_EXCEPTIONS: Final[dict[str, frozenset[str]]] = {
    "Role": frozenset(),
    "TicketStatus": frozenset(),
    "PackageStatus": frozenset(),
    "DeliveryStatus": frozenset(),
    "WorkflowType": frozenset(),
    "Severity": frozenset(),
    "LifecyclePhase": frozenset(),
}


def coverage_violations(
    universe: Iterable[str], covered: Iterable[str], exceptions: Iterable[str]
) -> list[str]:
    """The violations of one exception list, in both directions.

    An item of `universe` that is neither covered nor excepted, an excepted
    item that is covered, and an exception that names no item of `universe`
    each produce one violation.
    """
    items, present, excepted = set(universe), set(covered), set(exceptions)
    return [
        *(f"{item}: not covered" for item in sorted(items - present - excepted)),
        *(f"{item}: covered but excepted" for item in sorted(excepted & present)),
        *(f"{item}: excepted but unknown" for item in sorted(excepted - items)),
    ]


# ---------------------------------------------------------------------------
# Loads and reads
# ---------------------------------------------------------------------------


class Progress:
    """An `ExampleDatasetProgress` that records every call in order."""

    def __init__(self) -> None:
        self.events: list[tuple[str, ...]] = []

    def step_started(self, step: str) -> None:
        self.events.append(("started", step))

    def step_completed(self, step: str) -> None:
        self.events.append(("completed", step))

    def operation_committed(self) -> None:
        self.events.append(("committed",))

    @property
    def committed(self) -> int:
        return self.events.count(("committed",))

    @property
    def steps(self) -> list[tuple[str, ...]]:
        return [event for event in self.events if event != ("committed",)]


def load(url: str, progress: ExampleDatasetProgress | None = None) -> None:
    """One load of the dedicated database `url` through its own
    `asyncio.run()`."""

    async def run() -> None:
        engine = dataset_engine(url)
        try:
            await load_example_dataset(session_factory(engine), progress=progress)
        finally:
            await engine.dispose()

    asyncio.run(run())


def read[R](url: str, reader: Callable[[AsyncSession], Awaitable[R]]) -> R:
    """Run `reader` in a read session of `url` on a fresh `NullPool` engine."""

    async def run() -> R:
        engine = dataset_engine(url)
        try:
            # Closing the session discards its transaction and keeps the
            # loaded state of the returned instances.
            async with session_factory(engine)() as db:
                return await reader(db)
        finally:
            await engine.dispose()

    return asyncio.run(run())


def application_tables() -> set[str]:
    """The tables of the SQLAlchemy metadata, without the tables of
    test-only models that test support modules register on the same `Base`
    (for example `tests/support/audit_models.py`), which the migrations do
    not create."""
    test_only = {
        mapper.local_table.name
        for mapper in Base.registry.mappers
        if isinstance(mapper.local_table, Table)
        and not mapper.class_.__module__.startswith("app.")
    }
    return set(Base.metadata.tables) - test_only


async def table_counts(db: AsyncSession) -> dict[str, int]:
    """The row count of every application table."""
    counts: dict[str, int] = {}
    for name in sorted(application_tables()):
        table = Base.metadata.tables[name]
        count = await db.scalar(select(func.count()).select_from(table))
        counts[name] = int(count or 0)
    return counts


def populated(counts: dict[str, int]) -> set[str]:
    return {name for name, count in counts.items() if count > 0}


async def usernames(db: AsyncSession) -> dict[uuid.UUID, str]:
    rows = await db.execute(select(User.id, User.username))
    return dict(rows.all())


async def setting_value(db: AsyncSession) -> str | None:
    return await db.scalar(
        select(SystemSetting.value).where(SystemSetting.key == "default_cvss_version")
    )


async def ticket_statuses(db: AsyncSession) -> dict[int, str]:
    rows = await db.execute(select(Ticket.sequence_id, Ticket.status))
    return dict(rows.all())


@dataclass(frozen=True, slots=True)
class Loaded:
    """The shared loaded database and its load instant `T`."""

    url: str
    now: datetime
    fetchers: tuple[str, ...]
    """The production fetcher registry of the load, in name order."""

    @property
    def today(self) -> date:
        return self.now.date()

    def ago(self, days: int) -> datetime:
        return self.now - timedelta(days=days)

    def day(self, offset: int | None) -> date | None:
        return None if offset is None else self.today + timedelta(days=offset)


@pytest.fixture(scope="module")
def loaded(server: URL) -> Iterator[Loaded]:
    """One complete load into a dedicated database, with `T` pinned."""
    with dataset_database(server) as url:
        with production_registries(), pytest.MonkeyPatch.context() as patch:
            fetchers = tuple(sorted(FETCHER_REGISTRY))
            now = datetime.now(UTC)
            patch.setattr(example_dataset, "_utc_now", lambda: now)
            load(url)
        yield Loaded(url, now, fetchers)


@pytest.fixture(scope="module")
def server(_engine: AsyncEngine) -> URL:
    """The URL of the shared test engine, whose PostgreSQL server holds the
    dedicated databases."""
    return _engine.url


@pytest.fixture(scope="module")
def empty(server: URL) -> Iterator[str]:
    """A migrated dedicated database that every user leaves empty."""
    with dataset_database(server) as url:
        yield url


# ---------------------------------------------------------------------------
# Load: the resulting state equals Dataset Content
# ---------------------------------------------------------------------------


class TestUsers:
    def test_users_roles_and_passwords(self, loaded: Loaded) -> None:
        async def reader(
            db: AsyncSession,
        ) -> tuple[
            dict[str, tuple[str | None, str, bool, str | None, uuid.UUID | None]],
            set[tuple[str, str, str, str | None]],
        ]:
            names = await usernames(db)
            users = {
                user.username: (
                    user.full_name,
                    user.email,
                    user.active,
                    user.password_hash,
                    user.external_id,
                )
                for user in (await db.scalars(select(User))).all()
            }
            roles = {
                (
                    names[role.user_id],
                    role.role,
                    role.group_name,
                    None if role.assigned_by is None else names[role.assigned_by],
                )
                for role in (await db.scalars(select(UserRole))).all()
            }
            return users, roles

        users, roles = read(loaded.url, reader)

        assert {
            name: (full_name, email, active)
            for name, (full_name, email, active, _, _) in users.items()
        } == {
            name: (full_name, email, active)
            for name, (full_name, email, active, _) in USERS.items()
        }
        assert roles == {
            (name, role.value, "_manual", None if name == "jdoe" else "jdoe")
            for name, (_, _, _, user_roles) in USERS.items()
            for role in user_roles
        }
        assert not any(name == "dbrown" for name, *_ in roles)
        for name, (_, _, _, password_hash, external_id) in users.items():
            assert external_id is None, name
            assert password_hash is not None, name
            assert verify_password(DATASET_PASSWORD, password_hash), name

    def test_identity_events_and_actors(self, loaded: Loaded) -> None:
        async def reader(
            db: AsyncSession,
        ) -> list[tuple[str, str | None, str | None, str | None, str | None, Any]]:
            names = await usernames(db)
            events = await db.scalars(
                select(IdentityAuditEvent).order_by(
                    IdentityAuditEvent.created_at, IdentityAuditEvent.id
                )
            )
            return [
                (
                    event.event_type,
                    None if event.user_id is None else names[event.user_id],
                    None
                    if event.target_user_id is None
                    else names[event.target_user_id],
                    event.old_value,
                    event.new_value,
                    event.detail,
                )
                for event in events
            ]

        events = read(loaded.url, reader)

        expected = [
            (
                "role_added",
                None if name == "jdoe" else "jdoe",
                name,
                None,
                ROLE_WIRE[role],
                None,
            )
            for name, (_, _, _, roles) in USERS.items()
            for role in roles
        ] + [
            ("user_created", None if name == "jdoe" else "jdoe", name, None, name, None)
            for name in USERS
        ]
        deactivation = (
            "user_deactivated",
            "jdoe",
            "eblack",
            "active",
            "inactive",
            {"reason": "example dataset"},
        )
        assert sorted(events[:-1], key=repr) == sorted(expected, key=repr)
        assert events[-1] == deactivation
        # The users are created in the order of the Users table.
        assert [e[2] for e in events if e[0] == "user_created"] == list(USERS)


def test_system_setting_and_its_events(loaded: Loaded) -> None:
    async def reader(
        db: AsyncSession,
    ) -> tuple[str | None, list[tuple[str, str | None, str, str | None, str]]]:
        names = await usernames(db)
        events = await db.scalars(
            select(SettingAuditEvent).order_by(
                SettingAuditEvent.created_at, SettingAuditEvent.id
            )
        )
        return await setting_value(db), [
            (
                event.event_type,
                None if event.user_id is None else names[event.user_id],
                event.setting_key,
                event.old_value,
                event.new_value,
            )
            for event in events
        ]

    value, events = read(loaded.url, reader)

    assert value == "3.1"
    assert events == [
        ("setting_changed", "jdoe", "default_cvss_version", "3.1", "4.0"),
        ("setting_changed", "jdoe", "default_cvss_version", "4.0", "3.1"),
    ]


def test_every_fetcher_is_disabled_with_its_event(loaded: Loaded) -> None:
    async def reader(
        db: AsyncSession,
    ) -> tuple[dict[str, bool], list[tuple[str, str, str | None, Any, Any, Any]]]:
        names = await usernames(db)
        configs = {
            config.fetcher_name: config.enabled
            for config in (await db.scalars(select(FetcherConfig))).all()
        }
        events = await db.scalars(
            select(FetcherAuditEvent).order_by(
                FetcherAuditEvent.created_at, FetcherAuditEvent.id
            )
        )
        return configs, [
            (
                event.fetcher_name,
                event.event_type,
                None if event.user_id is None else names[event.user_id],
                event.old_value,
                event.new_value,
                event.detail,
            )
            for event in events
        ]

    configs, events = read(loaded.url, reader)

    assert loaded.fetchers
    assert configs == dict.fromkeys(loaded.fetchers, False)
    # One `disabled` event by `jdoe` per fetcher, in ascending name order.
    assert events == [
        (name, "disabled", "jdoe", None, None, None) for name in loaded.fetchers
    ]


def test_products_lifecycle_and_thresholds(loaded: Loaded) -> None:
    async def reader(
        db: AsyncSession,
    ) -> tuple[list[Product], list[tuple[str, str, datetime]]]:
        products = list((await db.scalars(select(Product))).all())
        repositories = await db.execute(
            select(
                Product.cpe,
                ProductRepository.repo_name,
                ProductRepository.catalog_last_seen_at,
            ).join(Product, Product.id == ProductRepository.product_id)
        )
        return products, [(cpe, name, seen) for cpe, name, seen in repositories]

    products, repositories = read(loaded.url, reader)

    actual = {
        product.cpe: (
            product.name,
            product.version,
            product.display_name,
            (
                product.first_customer_ship_date,
                product.general_support_end_date,
                product.extended_support_end_date,
                product.reactive_support_end_date,
            ),
            evaluate_product_lifecycle_phase(
                evaluation_date=loaded.today,
                first_customer_ship_date=product.first_customer_ship_date,
                general_support_end_date=product.general_support_end_date,
                extended_support_end_date=product.extended_support_end_date,
                reactive_support_end_date=product.reactive_support_end_date,
            ),
            product.cvss_threshold,
            product.catalog_last_seen_at,
        )
        for product in products
    }
    assert actual == {
        cpe: (
            name,
            version,
            display_name,
            tuple(loaded.day(offset) for offset in offsets or (None,) * 4),
            phase,
            None if threshold is None else Decimal(threshold),
            loaded.now,
        )
        for cpe, (
            name,
            version,
            display_name,
            _,
            offsets,
            phase,
            threshold,
        ) in PRODUCTS.items()
    }
    # One repository per Product, published in the snapshot at `T`.
    assert sorted(repositories) == sorted(
        (cpe, values[3], loaded.now) for cpe, values in PRODUCTS.items()
    )


class TestCVEs:
    def test_cve_records(self, loaded: Loaded) -> None:
        async def reader(db: AsyncSession) -> list[CVE]:
            return list((await db.scalars(select(CVE))).all())

        cves = {cve.cve_id: cve for cve in read(loaded.url, reader)}

        assert sorted(cves) == list(CVE_IDS)
        for cve_id, cve in cves.items():
            n = int(cve_id[-4:])
            assert cve.description == (
                f"Fictional vulnerability {cve_id} of the Sentinel example dataset."
            ), cve_id
            assert cve.published_date == loaded.ago(n), cve_id
            assert cve.modified_date == (
                loaded.ago(1) if cve_id in NVD_VECTORS else None
            ), cve_id
            assert cve.title == (
                f"Fictional flaw {cve_id}" if cve_id in MITRE_INGESTED else None
            ), cve_id
            if cve_id == REJECTED_CVE:
                assert (cve.cve_state, cve.date_rejected) == ("REJECTED", loaded.ago(2))
            else:
                assert (cve.cve_state, cve.date_rejected) == ("PUBLISHED", None), cve_id

    def test_cvss_assessments_and_cwes(self, loaded: Loaded) -> None:
        async def reader(
            db: AsyncSession,
        ) -> tuple[set[tuple[str, str, str]], set[tuple[str, str, str]]]:
            cvss = await db.execute(
                select(
                    CVE.cve_id,
                    CVECVSSAssessment.provider_name,
                    CVECVSSAssessment.vector_string,
                ).join(CVE, CVE.id == CVECVSSAssessment.cve_id)
            )
            cwes = await db.execute(
                select(CVE.cve_id, CVECWE.cwe_id, CVECWE.source).join(
                    CVE, CVE.id == CVECWE.cve_id
                )
            )
            return {(c, p, v) for c, p, v in cvss}, {(c, w, s) for c, w, s in cwes}

        cvss, cwes = read(loaded.url, reader)

        assert cvss == {
            *((cve_id, "NVD", vector) for cve_id, vector in NVD_VECTORS.items()),
            *((cve_id, "SUSE", vector) for cve_id, vector in SUSE_VECTORS.items()),
        }
        assert cwes == {(cve_id, cwe, "NVD") for cve_id, cwe in CWES.items()}

    def test_further_ingestions(self, loaded: Loaded) -> None:
        async def reader(db: AsyncSession) -> dict[str, list[tuple[Any, ...]]]:
            async def rows(*columns: Any, model: Any) -> list[tuple[Any, ...]]:
                result = await db.execute(
                    select(CVE.cve_id, *columns).join(CVE, CVE.id == model.cve_id)
                )
                return sorted(tuple(row) for row in result)

            return {
                "kev": await rows(
                    CVEKEVEntry.date_added, CVEKEVEntry.reference_url, model=CVEKEVEntry
                ),
                "epss": await rows(
                    CVEEPSSScore.score,
                    CVEEPSSScore.percentile,
                    CVEEPSSScore.assessed_at,
                    model=CVEEPSSScore,
                ),
                "ssvc": await rows(
                    CVESSVCAssessment.exploitation,
                    CVESSVCAssessment.automatable,
                    CVESSVCAssessment.technical_impact,
                    CVESSVCAssessment.version,
                    CVESSVCAssessment.assessed_at,
                    model=CVESSVCAssessment,
                ),
                "affected": await rows(
                    CVEAffectedVersion.source_container,
                    CVEAffectedVersion.vendor,
                    CVEAffectedVersion.product,
                    CVEAffectedVersion.version,
                    CVEAffectedVersion.version_type,
                    CVEAffectedVersion.version_end,
                    CVEAffectedVersion.version_end_inclusive,
                    CVEAffectedVersion.status,
                    model=CVEAffectedVersion,
                ),
                "external": await rows(
                    CVEExternalIdentifier.source,
                    CVEExternalIdentifier.identifier,
                    model=CVEExternalIdentifier,
                ),
            }

        data = read(loaded.url, reader)
        assessed = loaded.today - timedelta(days=1)

        assert data["kev"] == [
            ("CVE-2099-0001", loaded.today - timedelta(days=2), None)
        ]
        assert data["epss"] == sorted(
            (cve_id, score, percentile, assessed)
            for cve_id, (score, percentile) in EPSS.items()
        )
        assert data["ssvc"] == [
            ("CVE-2099-0010", "poc", "no", "partial", "2.0.3", loaded.ago(3))
        ]
        assert data["affected"] == [
            (
                "CVE-2099-0009",
                "cna",
                "Example",
                "fictional-tar",
                "1.0",
                "semver",
                "1.5",
                False,
                "affected",
            )
        ]
        assert data["external"] == [("CVE-2099-0010", "GHSA", "GHSA-2c4f-7h9j-mqrv")]


async def _ticket_rows(
    db: AsyncSession,
) -> dict[int, tuple[str | None, str, str | None, bool, str | None]]:
    assignee = aliased(User)
    rows = await db.execute(
        select(
            Ticket.sequence_id,
            CVE.cve_id,
            Ticket.status,
            assignee.username,
            Ticket.is_confidential,
            resolved_severity_expression(),
        )
        .outerjoin(CVE, CVE.id == Ticket.cve_id)
        .outerjoin(assignee, assignee.id == Ticket.assignee_id)
    )
    return {
        sequence_id: (cve_id, status, username, confidential, severity)
        for sequence_id, cve_id, status, username, confidential, severity in rows
    }


class TestTickets:
    def test_tickets(self, loaded: Loaded) -> None:
        tickets = read(loaded.url, _ticket_rows)

        assert tickets == {
            n: (
                cve_id,
                status.value,
                assignee,
                confidential,
                None if severity is None else severity.value,
            )
            for n, (cve_id, status, assignee, confidential, severity) in TICKETS.items()
        }
        assert (
            sum(not confidential for _, _, _, confidential, _ in tickets.values()) == 23
        )

    def test_ticket_attributes(self, loaded: Loaded) -> None:
        async def reader(
            db: AsyncSession,
        ) -> tuple[
            dict[int, tuple[str | None, str | None, datetime | None, int | None]],
            set[tuple[int, str, str]],
        ]:
            names = await usernames(db)
            tickets = list((await db.scalars(select(Ticket))).all())
            sequence = {ticket.id: ticket.sequence_id for ticket in tickets}
            attributes = {
                ticket.sequence_id: (
                    ticket.severity_manual,
                    ticket.priority_override,
                    ticket.coordinated_release_at,
                    None
                    if ticket.duplicate_of_id is None
                    else sequence[ticket.duplicate_of_id],
                )
                for ticket in tickets
            }
            grants = {
                (
                    sequence[grant.ticket_id],
                    names[grant.user_id],
                    names[grant.granted_by_id],
                )
                for grant in (await db.scalars(select(TicketAccessGrant))).all()
            }
            return attributes, grants

        attributes, grants = read(loaded.url, reader)

        expected: dict[
            int, tuple[str | None, str | None, datetime | None, int | None]
        ] = dict.fromkeys(TICKETS, (None, None, None, None))
        expected[12] = (None, "P1", None, None)
        expected[18] = (None, None, loaded.now + timedelta(days=30), None)
        expected[21] = ("High", None, None, None)
        expected[22] = (None, None, None, 21)
        assert attributes == expected
        # The access grant of `cwhite` on SNTL-18; none on SNTL-19.
        assert grants == {(18, "cwhite", "asmith")}

    def test_ticket_audit_events(self, loaded: Loaded) -> None:
        async def reader(
            db: AsyncSession,
        ) -> list[tuple[int, str, str | None, dict[str, Any] | None]]:
            actor = aliased(User)
            rows = await db.execute(
                select(
                    Ticket.sequence_id,
                    TicketAuditEvent.event_type,
                    actor.username,
                    TicketAuditEvent.detail,
                )
                .join(Ticket, Ticket.id == TicketAuditEvent.ticket_id)
                .outerjoin(actor, actor.id == TicketAuditEvent.user_id)
            )
            return [(n, kind, name, detail) for n, kind, name, detail in rows]

        events = read(loaded.url, reader)
        attributed = {(n, kind, name) for n, kind, name, _ in events}

        assert {kind for _, kind, _ in attributed} >= TICKET_EVENT_TYPES
        assert attributed >= ATTRIBUTED_TICKET_EVENTS
        [released] = [
            detail for _, kind, _, detail in events if kind == "product_released"
        ]
        assert released is not None
        assert released["advisory_id"] == "SUSE-SU-2099:0001-1"
        assert released["product_cpe"] == SERVER_15_SP7


class TestPackages:
    def test_tracks_products_and_eligibility(self, loaded: Loaded) -> None:
        async def reader(
            db: AsyncSession,
        ) -> tuple[
            set[tuple[int, str, datetime | None]],
            dict[TrackKey, tuple[str, str, str, datetime | None]],
            set[tuple[TrackKey, str, bool, bool, datetime | None, datetime | None]],
        ]:
            packages = await db.execute(
                select(
                    Ticket.sequence_id,
                    TicketPackage.package_name,
                    TicketPackage.deleted_at,
                ).join(Ticket, Ticket.id == TicketPackage.ticket_id)
            )
            track_key = (
                Ticket.sequence_id,
                TicketPackage.package_name,
                TicketPackageTrack.reference,
            )
            tracks = await db.execute(
                select(
                    *track_key,
                    TicketPackageTrack.workflow_type,
                    TicketPackageTrack.status,
                    TicketPackageTrack.delivery_status,
                    TicketPackageTrack.deleted_at,
                )
                .join(
                    TicketPackage,
                    TicketPackage.id == TicketPackageTrack.ticket_package_id,
                )
                .join(Ticket, Ticket.id == TicketPackage.ticket_id)
            )
            products = await db.execute(
                select(
                    *track_key,
                    Product.cpe,
                    TicketPackageProduct.eligible,
                    TicketPackageProduct.is_eligible_override,
                    TicketPackageProduct.released_at,
                    TicketPackageProduct.deleted_at,
                )
                .join(Product, Product.id == TicketPackageProduct.product_id)
                .join(
                    TicketPackageTrack,
                    TicketPackageTrack.id
                    == TicketPackageProduct.ticket_package_track_id,
                )
                .join(
                    TicketPackage,
                    TicketPackage.id == TicketPackageTrack.ticket_package_id,
                )
                .join(Ticket, Ticket.id == TicketPackage.ticket_id)
            )
            return (
                {(n, package, deleted) for n, package, deleted in packages},
                {(n, p, r): (w, s, d, x) for n, p, r, w, s, d, x in tracks},
                {((n, p, r), c, e, o, ra, x) for n, p, r, c, e, o, ra, x in products},
            )

        packages, tracks, products = read(loaded.url, reader)

        assert packages == {(n, package, None) for n, package, _ in TRACKS}
        assert tracks == {
            key: (workflow.value, status.value, delivery.value, None)
            for key, (workflow, status, delivery, _) in TRACKS.items()
        }
        assert products == {
            (
                key,
                cpe,
                eligible,
                False,
                loaded.ago(2) if released == RELEASED else None,
                None,
            )
            for key, (_, _, _, occurrences) in TRACKS.items()
            for cpe, (eligible, released) in occurrences.items()
        }

    def test_maintainers(self, loaded: Loaded) -> None:
        async def reader(db: AsyncSession) -> set[tuple[int, str, str]]:
            rows = await db.execute(
                select(Ticket.sequence_id, TicketPackage.package_name, User.username)
                .select_from(TicketPackageMaintainer)
                .join(
                    TicketPackage,
                    TicketPackage.id == TicketPackageMaintainer.ticket_package_id,
                )
                .join(Ticket, Ticket.id == TicketPackage.ticket_id)
                .join(User, User.id == TicketPackageMaintainer.user_id)
            )
            return {(n, package, name) for n, package, name in rows}

        assert read(loaded.url, reader) == {
            (n, package, "dbrown") for n, package in MAINTAINED
        }

    def test_maintainer_workbench_of_dbrown(self, loaded: Loaded) -> None:
        async def reader(
            db: AsyncSession,
        ) -> tuple[list[MaintainerWorkItem], ...]:
            user_id = await db.scalar(select(User.id).where(User.username == "dbrown"))
            assert user_id is not None
            roles = await user_service.get_user_roles(db, user_id)
            caller = TicketCaller.authenticated(user_id, get_effective_scope(roles))
            day, instant = loaded.today, loaded.now
            pending = await package_service.list_maintainer_pending_work(
                db, caller=caller, evaluation_date=day, evaluation_instant=instant
            )
            in_progress = await package_service.list_maintainer_in_progress_work(
                db, caller=caller, evaluation_date=day, evaluation_instant=instant
            )
            completed = await package_service.list_maintainer_completed_work(
                db, caller=caller, evaluation_date=day, evaluation_instant=instant
            )
            sntl_18 = await package_service.get_maintainer_ticket_work(
                db,
                ticket_id="SNTL-18",
                caller=caller,
                evaluation_date=day,
                evaluation_instant=instant,
            )
            assert pending.total == len(pending.items)
            assert in_progress.total == len(in_progress.items)
            assert completed.total == len(completed.items)
            return (
                list(pending.items),
                list(in_progress.items),
                list(completed.items),
                list(sntl_18.in_progress),
            )

        pending, in_progress, completed, sntl_18 = read(loaded.url, reader)

        def keys(items: list[MaintainerWorkItem]) -> set[tuple[str, str, str]]:
            return {(i.ticket_id, i.package_name, i.reference) for i in items}

        assert keys(pending) == {("SNTL-11", "fictional-curl", GIT_16)}
        assert keys(in_progress) == {
            ("SNTL-13", "fictional-httpd", SP7_UPDATE),
            ("SNTL-18", "fictional-openssh", SP7_UPDATE),
        }
        assert keys(completed) == {("SNTL-14", "fictional-libxml", SP7_UPDATE)}
        # `dbrown` holds no role and sees the confidential SNTL-18 through
        # maintainership.
        assert keys(sntl_18) == {("SNTL-18", "fictional-openssh", SP7_UPDATE)}


class TestIBSRequests:
    def test_requests(self, loaded: Loaded) -> None:
        async def reader(
            db: AsyncSession,
        ) -> dict[int, tuple[str, int | None, datetime, datetime]]:
            requests = await db.scalars(select(IBSRequest))
            return {
                request.request_number: (
                    request.state,
                    request.superseded_by_request_number,
                    request.upstream_created_at,
                    request.upstream_updated_at,
                )
                for request in requests
            }

        assert read(loaded.url, reader) == {
            number: (state, None, loaded.ago(created), loaded.ago(updated))
            for number, (_, _, created, state, updated) in IBS_REQUESTS.items()
        }

    def test_actions_and_correlations(self, loaded: Loaded) -> None:
        async def reader(
            db: AsyncSession,
        ) -> tuple[list[tuple[Any, ...]], set[tuple[int, TrackKey]]]:
            actions = await db.execute(
                select(
                    IBSRequest.request_number,
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
                ).join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
            )
            links = await db.execute(
                select(
                    IBSRequest.request_number,
                    Ticket.sequence_id,
                    TicketPackage.package_name,
                    TicketPackageTrack.reference,
                )
                .select_from(IBSRequestActionTrack)
                .join(
                    IBSRequestAction,
                    IBSRequestAction.id == IBSRequestActionTrack.ibs_request_action_id,
                )
                .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
                .join(
                    TicketPackageTrack,
                    TicketPackageTrack.id
                    == IBSRequestActionTrack.ticket_package_track_id,
                )
                .join(
                    TicketPackage,
                    TicketPackage.id == TicketPackageTrack.ticket_package_id,
                )
                .join(Ticket, Ticket.id == TicketPackage.ticket_id)
            )
            return (
                sorted(tuple(row) for row in actions),
                {(number, (n, p, r)) for number, n, p, r in links},
            )

        actions, links = read(loaded.url, reader)

        # Every request has exactly one action.
        assert actions == [
            (number, *IBS_ACTIONS[number]) for number in sorted(IBS_ACTIONS)
        ]
        # Each action is correlated to the SP7 track of its Ticket's package.
        assert links == {
            (number, (ticket, IBS_ACTIONS[number][6], SP7_UPDATE))
            for number, (_, ticket, _, _, _) in IBS_REQUESTS.items()
        }


def test_references(loaded: Loaded) -> None:
    async def reader(
        db: AsyncSession,
    ) -> set[tuple[int, str, str | None, str | None, str]]:
        rows = await db.execute(
            select(
                Ticket.sequence_id,
                TicketReference.url,
                TicketReference.title,
                TicketReference.type,
                TicketReference.source,
            ).join(Ticket, Ticket.id == TicketReference.ticket_id)
        )
        return {(n, url, title, kind, source) for n, url, title, kind, source in rows}

    assert read(loaded.url, reader) == REFERENCES


def test_every_audit_trail_holds_events(loaded: Loaded) -> None:
    """Every audit trail of the application, derived from the event models
    so that a new trail is covered without a change here."""
    trails = {
        mapper.local_table.name
        for mapper in Base.registry.mappers
        if isinstance(mapper.local_table, Table)
        and issubclass(mapper.class_, AuditEventMixin)
        and mapper.class_.__module__.startswith("app.")
    }
    counts = read(loaded.url, table_counts)

    assert trails >= {
        "ticket_audit_event",
        "identity_audit_event",
        "fetcher_audit_event",
        "setting_audit_event",
    }
    assert {trail for trail in trails if counts[trail] == 0} == set()


def test_repeated_load_is_refused_and_changes_nothing(loaded: Loaded) -> None:
    before = read(loaded.url, table_counts)

    with production_registries(), pytest.raises(ExampleDatasetNotEmptyError):
        load(loaded.url)

    assert read(loaded.url, table_counts) == before


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


class TestCoverageViolations:
    """Self-tests of `coverage_violations()` on synthetic inputs."""

    def test_no_violation(self) -> None:
        assert coverage_violations({"a", "b", "c"}, {"a", "b"}, {"c"}) == []

    def test_uncovered_item_without_exception_fails(self) -> None:
        assert coverage_violations({"a", "b"}, {"a"}, set()) == ["b: not covered"]

    def test_covered_item_in_exception_list_fails(self) -> None:
        assert coverage_violations({"a", "b"}, {"a", "b"}, {"b"}) == [
            "b: covered but excepted"
        ]

    def test_exception_naming_no_item_fails(self) -> None:
        assert coverage_violations({"a"}, {"a"}, {"z"}) == ["z: excepted but unknown"]

    def test_covered_values_outside_the_universe_are_ignored(self) -> None:
        assert coverage_violations({"a"}, {"a", "z"}, set()) == []


@dataclass(frozen=True, slots=True)
class Covered:
    """The table and enumeration values that the dataset holds."""

    tables: dict[str, int]
    roles: set[str]
    users_without_roles: int
    ticket_statuses: set[str]
    package_statuses: set[str]
    delivery_statuses: set[str]
    workflow_types: set[str]
    severities: set[str | None]
    phases: set[LifecyclePhase | None]


def test_dataset_covers_every_table_and_enumeration(loaded: Loaded) -> None:
    async def reader(db: AsyncSession) -> Covered:
        async def values(column: Any) -> set[Any]:
            return set((await db.scalars(select(column).distinct())).all())

        products = (await db.scalars(select(Product))).all()
        without_roles = await db.scalar(
            select(func.count())
            .select_from(User)
            .where(~select(UserRole.id).where(UserRole.user_id == User.id).exists())
        )
        return Covered(
            tables=await table_counts(db),
            roles=await values(UserRole.role),
            users_without_roles=int(without_roles or 0),
            ticket_statuses=await values(Ticket.status),
            package_statuses=await values(TicketPackageTrack.status),
            delivery_statuses=await values(TicketPackageTrack.delivery_status),
            workflow_types=await values(TicketPackageTrack.workflow_type),
            severities=await values(resolved_severity_expression()),
            phases={
                evaluate_product_lifecycle_phase(
                    evaluation_date=loaded.today,
                    first_customer_ship_date=product.first_customer_ship_date,
                    general_support_end_date=product.general_support_end_date,
                    extended_support_end_date=product.extended_support_end_date,
                    reactive_support_end_date=product.reactive_support_end_date,
                )
                for product in products
            },
        )

    covered = read(loaded.url, reader)

    def members(enum: Iterable[Any]) -> set[str]:
        return {str(member.value) for member in enum}

    violations = {
        "tables": coverage_violations(
            application_tables(), populated(covered.tables), TABLE_EXCEPTIONS
        ),
        "Role": coverage_violations(
            members(Role), covered.roles, ENUM_EXCEPTIONS["Role"]
        ),
        "TicketStatus": coverage_violations(
            members(TicketStatus),
            covered.ticket_statuses,
            ENUM_EXCEPTIONS["TicketStatus"],
        ),
        "PackageStatus": coverage_violations(
            members(PackageStatus),
            covered.package_statuses,
            ENUM_EXCEPTIONS["PackageStatus"],
        ),
        "DeliveryStatus": coverage_violations(
            members(DeliveryStatus),
            covered.delivery_statuses,
            ENUM_EXCEPTIONS["DeliveryStatus"],
        ),
        "WorkflowType": coverage_violations(
            members(WorkflowType),
            covered.workflow_types,
            ENUM_EXCEPTIONS["WorkflowType"],
        ),
        "Severity": coverage_violations(
            members(Severity),
            {s for s in covered.severities if s is not None},
            ENUM_EXCEPTIONS["Severity"],
        ),
        "LifecyclePhase": coverage_violations(
            members(LifecyclePhase),
            {p.value for p in covered.phases if p is not None},
            ENUM_EXCEPTIONS["LifecyclePhase"],
        ),
    }
    assert violations == {name: [] for name in violations}
    assert covered.users_without_roles >= 1
    assert None in covered.severities  # an unresolved Ticket severity
    assert None in covered.phases  # an unavailable lifecycle phase


# ---------------------------------------------------------------------------
# Isolation and progress
# ---------------------------------------------------------------------------


def test_load_is_isolated_and_reports_its_steps(server: URL) -> None:
    """No outbound HTTP, Redis, or Celery publication, and no commit with a
    registered post-commit effect; the progress receives every step."""
    progress = Progress()
    commits: list[AsyncSession] = []
    violations: list[str] = []
    real_commit = AsyncSession.commit

    async def checked_commit(session: AsyncSession) -> None:
        # The loader detaches callbacks and rolls back before any commit it
        # owns, so for its own commits this spy confirms that the load's
        # check passed (the registered-effect tests prove that the check
        # detects an effect); it also covers the self-committing catalog
        # publications.
        commits.append(session)
        if pending_ticket_convergence_effects(session) != ():
            violations.append("Ticket convergence effect at commit")
        if session.info.get("post_commit_callbacks"):
            violations.append("post-commit callback at commit")
        await real_commit(session)

    with production_registries(), dataset_database(server) as url:
        with pytest.MonkeyPatch.context() as patch:
            guard = OutboundGuard((DatabaseEndpoint.from_url(server),))
            guard.install(patch)
            publications = record_publications(patch)
            patch.setattr(AsyncSession, "commit", checked_commit)
            load(url, progress)
        statuses = read(url, ticket_statuses)

    assert guard.attempts == []
    assert publications.calls == []
    assert violations == []
    assert len(commits) >= progress.committed > 0
    assert progress.steps == [
        event
        for step in STEP_NAMES
        for event in (("started", step), ("completed", step))
    ]
    assert len(statuses) == len(TICKETS)


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------

FICTIONAL_PASSWORD_HASH: Final = "$2b$12$" + "a" * 53
"""Fictional bcrypt-shaped value; never a real hash."""


def guard_row(model: str) -> User | Ticket | CVE | Product:
    """One row of `model` that makes a database non-empty."""
    if model == "User":
        return User(
            username="fgreen",
            email="frank.green@example.com",
            full_name="Frank Green",
            password_hash=FICTIONAL_PASSWORD_HASH,
        )
    if model == "Ticket":
        return Ticket(severity_manual=Severity.HIGH.value)
    if model == "CVE":
        return CVE(cve_id="CVE-2099-9001")
    return Product(
        name="FLES",
        version="99.0",
        display_name="Fictional Linux Enterprise Server 99.0",
        cpe="cpe:/o:example:fles:99.0",
        catalog_last_seen_at=datetime.now(UTC),
    )


@pytest.mark.parametrize("model", ["User", "Ticket", "CVE", "Product"])
def test_guard_refuses_a_non_empty_database(empty: str, model: str) -> None:
    row = guard_row(model)
    row_type = type(row)

    async def insert(db: AsyncSession) -> uuid.UUID:
        db.add(row)
        await db.commit()
        return row.id

    async def remove(db: AsyncSession) -> None:
        await db.execute(delete(row_type).where(row_type.id == row_id))
        await db.commit()

    row_id = read(empty, insert)
    try:
        before = read(empty, table_counts)
        assert before[row_type.__tablename__] == 1
        # The migrations seed the system settings; they stay unchanged.
        assert before["system_setting"] > 0

        with production_registries(), pytest.raises(ExampleDatasetNotEmptyError):
            load(empty)

        assert read(empty, table_counts) == before
    finally:
        read(empty, remove)


# ---------------------------------------------------------------------------
# Failure and interruption
# ---------------------------------------------------------------------------

IDENTITY_TABLES: Final = {"user", "user_role", "identity_audit_event", "system_setting"}
"""The populated tables after the `Users` step; `system_setting` is seeded
by the migrations."""


class InjectedFailureError(Exception):
    """A fictional failure injected into a delegated service."""


def users_step(committed: int) -> list[tuple[str, ...]]:
    """The progress of a completed `Users` step."""
    return [("started", "Users"), *[("committed",)] * committed, ("completed", "Users")]


async def identity_state(
    db: AsyncSession,
) -> tuple[dict[str, bool], list[str], str | None, dict[str, int]]:
    users = {user.username: user.active for user in await db.scalars(select(User))}
    events = await db.scalars(
        select(IdentityAuditEvent.event_type).order_by(
            IdentityAuditEvent.created_at, IdentityAuditEvent.id
        )
    )
    return users, list(events), await setting_value(db), await table_counts(db)


def test_failure_keeps_the_operations_committed_before_it(
    server: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = InjectedFailureError("fictional failure")

    async def fail(*args: Any, **kwargs: Any) -> str:
        raise error

    monkeypatch.setattr(settings_service, "update_default_cvss_version", fail)
    progress = Progress()
    with production_registries(), dataset_database(server) as url:
        with pytest.raises(InjectedFailureError) as raised:
            load(url, progress)
        users, events, value, counts = read(url, identity_state)

    assert raised.value is error
    # Six user creations and the deactivation committed; the failing step
    # started and did not complete.
    assert progress.events == [*users_step(7), ("started", "System settings")]
    assert users == {name: active for name, (_, _, active, _) in USERS.items()}
    assert events.count("user_deactivated") == 1
    # Nothing of the failed or later steps exists.
    assert value == "3.1"
    assert populated(counts) == IDENTITY_TABLES


def test_failure_of_the_first_operation_commits_nothing(
    empty: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = InjectedFailureError("fictional failure")

    async def fail(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(user_service, "create_user", fail)
    progress = Progress()
    before = read(empty, table_counts)

    with production_registries(), pytest.raises(InjectedFailureError) as raised:
        load(empty, progress)

    assert raised.value is error
    assert progress.events == [("started", "Users")]
    assert progress.committed == 0
    assert read(empty, table_counts) == before


def test_failed_catalog_publication_propagates_and_publishes_nothing(
    server: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A catalog publication owns its transaction; its failure propagates
    unchanged and leaves no Product, while the earlier steps remain."""
    error = InjectedFailureError("fictional failure")

    async def fail(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(example_dataset, "publish_snapshot", fail)
    progress = Progress()
    with production_registries(), dataset_database(server) as url:
        with pytest.raises(InjectedFailureError) as raised:
            load(url, progress)
        counts = read(url, table_counts)

    assert raised.value is error
    assert progress.steps[-1] == ("started", "Product catalog")
    assert progress.events[-1] != ("committed",)
    assert counts["product"] == 0
    assert counts["product_repository"] == 0
    assert counts["user"] == len(USERS)
    assert counts["fetcher_config"] > 0


def test_interruption_before_commit_rolls_back_that_operation_only(
    server: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = user_service.deactivate_user

    async def interrupted(db: AsyncSession, *args: Any, **kwargs: Any) -> Any:
        await real(db, *args, **kwargs)  # flushes the deactivation
        raise SystemExit(143)

    monkeypatch.setattr(user_service, "deactivate_user", interrupted)
    progress = Progress()
    with production_registries(), dataset_database(server) as url:
        with pytest.raises(SystemExit) as raised:
            load(url, progress)
        users, events, value, counts = read(url, identity_state)

    assert raised.value.code == 143
    assert progress.events == [("started", "Users"), *[("committed",)] * 6]
    assert users == dict.fromkeys(USERS, True)
    assert "user_deactivated" not in events
    assert sorted(events) == sorted(["user_created"] * 6 + ["role_added"] * 5)
    assert value == "3.1"
    assert populated(counts) == IDENTITY_TABLES


# ---------------------------------------------------------------------------
# Registered effect
# ---------------------------------------------------------------------------


async def _no_effect() -> None:
    pass


def test_registered_post_commit_callback_rolls_back_the_operation(
    server: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = settings_service.update_default_cvss_version

    async def registering(db: AsyncSession, **kwargs: Any) -> str:
        result = await real(db, **kwargs)
        register_post_commit_callback(db, _no_effect)
        return result

    monkeypatch.setattr(settings_service, "update_default_cvss_version", registering)
    progress = Progress()
    with production_registries(), dataset_database(server) as url:
        with pytest.raises(ExampleDatasetEffectError):
            load(url, progress)
        users, _, value, counts = read(url, identity_state)

    assert progress.events == [*users_step(7), ("started", "System settings")]
    # The first setting change rolled back: no change and no setting event.
    assert value == "3.1"
    assert counts["setting_audit_event"] == 0
    assert populated(counts) == IDENTITY_TABLES
    assert users == {name: active for name, (_, _, active, _) in USERS.items()}


def test_registered_ticket_convergence_rolls_back_the_operation(
    server: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = ticket_service.ignore_ticket

    async def registering(db: AsyncSession, **kwargs: Any) -> Ticket:
        ticket = await real(db, **kwargs)
        register_ticket_convergence(db, kwargs["ticket_id"])
        return ticket

    monkeypatch.setattr(ticket_service, "ignore_ticket", registering)
    progress = Progress()
    with production_registries(), dataset_database(server) as url:
        with pytest.raises(ExampleDatasetEffectError):
            load(url, progress)
        statuses = read(url, ticket_statuses)

    assert progress.steps == [
        *(
            event
            for step in STEP_NAMES[:-1]
            for event in (("started", step), ("completed", step))
        ),
        ("started", "Ticket work"),
    ]
    assert progress.events[-1] == ("committed",)
    # SNTL-17 stays `New`; the Ticket work before it is committed.
    assert statuses[17] == TicketStatus.NEW.value
    assert statuses[16] == TicketStatus.RESOLVED.value
