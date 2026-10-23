"""The fictional example dataset and its loader.

Implements docs/features/platform/example-dataset.md (Loading Rules,
Service, Dataset Content). `load_example_dataset()` is a service-owned
orchestration boundary: it receives the session factory, applies the
Empty-Database Guard in its own read session, and runs every dataset
operation in its own session and transaction, which it commits before the
next one begins. The three catalog publications commit their own
transactions (product-catalog.md, Catalog Publication Boundaries).

Every operation is an existing service operation, called as the actor of
Dataset Content reaches it in real use: a user-attributed operation passes
the dataset user with that user's consumer caller context (its identity and
effective scope), and a system operation passes no acting user. Before
committing an operation whose transaction it owns, the load verifies that
the transaction registered no post-commit effect and no Ticket convergence
effect; a registered effect rolls the operation back and raises
`ExampleDatasetEffectError`. The load performs no network I/O, uses no
Redis or Celery broker, and does not apply the RedBeat propagation that
`update_fetcher_config()` returns.

The dataset is static data of this module. Every identifier in it is
fictional (docs/conventions.md, Example Data in Documentation); email
addresses and URLs use the `example.com` domain.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Final, Literal, Protocol

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.enums import (
    CVEExternalIdentifierSource,
    CVESourceType,
    CveState,
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    PackageStatus,
    ReferenceType,
    Role,
    Severity,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
    TicketPriority,
    WorkflowType,
)
from app.core.exceptions import ServiceError
from app.core.identifiers import format_ticket_id
from app.core.permissions import get_effective_scope
from app.database import detach_post_commit_callbacks
from app.models.cve import CVE
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import (
    cve_service,
    fetcher_bootstrap,
    fetcher_operations,
    package_service,
    reference_service,
    ticket_mutations,
    ticket_service,
    user_service,
)
from app.services import settings as settings_service
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.cve_ingest import (
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVEIngestPayload,
    CVSSAssessmentEntry,
    CWEEntry,
    EPSSEntry,
    ExternalIdentifierEntry,
    KEVEntry,
    SSVCEntry,
)
from app.services.packages.ibs_request_identity import action_key
from app.services.packages.ibs_request_observation import (
    ActionWrite,
    Observation,
    RequestWrite,
)
from app.services.packages.ibs_request_reconciliation import (
    apply_ibs_request_observation,
)
from app.services.packages.sync_aimaas_lifecycle import (
    LifecycleDates,
    publish_lifecycle_dates,
)
from app.services.packages.sync_aimaas_thresholds import publish_thresholds
from app.services.packages.sync_smelt_products import (
    CatalogProduct,
    publish_snapshot,
)
from app.services.reference_service import (
    AutomaticReferenceInput,
    ManualReferenceCreateInput,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller

__all__ = [
    "PASSWORD",
    "STEPS",
    "ExampleDatasetEffectError",
    "ExampleDatasetNotEmptyError",
    "ExampleDatasetProgress",
    "ExampleDatasetServiceError",
    "load_example_dataset",
]


# ---------------------------------------------------------------------------
# Exceptions and progress (Service)
# ---------------------------------------------------------------------------


class ExampleDatasetServiceError(ServiceError):
    """Base class of every exception owned by this module. No exception of
    this module reaches an API handler."""


class ExampleDatasetNotEmptyError(ExampleDatasetServiceError):
    """The database is not empty (Empty-Database Guard)."""

    def __init__(self) -> None:
        super().__init__(
            "The database is not empty. The example dataset loads only into "
            "a newly created database."
        )


class ExampleDatasetEffectError(ExampleDatasetServiceError):
    """An operation of the load registered a post-commit effect; the
    operation has rolled back (Isolation)."""

    def __init__(self) -> None:
        super().__init__(
            "An operation of the example dataset registered a post-commit effect."
        )


class ExampleDatasetProgress(Protocol):
    """Receives the progress of a load, which the command turns into its
    step report."""

    def step_started(self, step: str) -> None:
        """`step` (one of `STEPS`) begins."""

    def step_completed(self, step: str) -> None:
        """`step` completed."""

    def operation_committed(self) -> None:
        """One dataset operation committed."""


class _NoProgress:
    def step_started(self, step: str) -> None:
        pass

    def step_completed(self, step: str) -> None:
        pass

    def operation_committed(self) -> None:
        pass


USERS_STEP: Final = "Users"
SETTINGS_STEP: Final = "System settings"
FETCHERS_STEP: Final = "Fetchers"
CATALOG_STEP: Final = "Product catalog"
TICKETS_STEP: Final = "CVEs and tickets"
WORK_STEP: Final = "Ticket work"
STEPS: Final = (
    USERS_STEP,
    SETTINGS_STEP,
    FETCHERS_STEP,
    CATALOG_STEP,
    TICKETS_STEP,
    WORK_STEP,
)
"""The steps of a load, in order (Steps and Transactions)."""


# ---------------------------------------------------------------------------
# Dataset Content
# ---------------------------------------------------------------------------

PASSWORD: Final = "example-dataset-password"
"""The local password of every dataset user (Credentials)."""

_MANUAL_ORIGIN: Final = "_manual"


@dataclass(frozen=True, slots=True)
class _User:
    username: str
    full_name: str
    email: str
    roles: tuple[Role, ...]


_ADMIN: Final = "jdoe"
_USERS: Final = (
    _User("jdoe", "John Doe", "john.doe@example.com", (Role.ADMIN,)),
    _User(
        "asmith",
        "Alice Smith",
        "alice.smith@example.com",
        (Role.VULNERABILITY_ANALYST,),
    ),
    _User(
        "bwilson",
        "Bob Wilson",
        "bob.wilson@example.com",
        (Role.VULNERABILITY_ANALYST,),
    ),
    _User(
        "cwhite",
        "Carol White",
        "carol.white@example.com",
        (Role.RESTRICTED_ANALYST,),
    ),
    _User("dbrown", "Dave Brown", "dave.brown@example.com", ()),
    _User(
        "eblack", "Eve Black", "eve.black@example.com", (Role.VULNERABILITY_ANALYST,)
    ),
)
_INACTIVE: Final = "eblack"
_DEACTIVATION_REASON: Final = "example dataset"
_MAINTAINER_EMAIL: Final = "dave.brown@example.com"

_CVSS_VERSION_CHANGES: Final[tuple[Literal["3.1", "4.0"], ...]] = ("4.0", "3.1")
"""`update_default_cvss_version()` targets: from `3.1` to `4.0` and back."""


@dataclass(frozen=True, slots=True)
class _Product:
    cpe: str
    name: str
    version: str
    display_name: str
    repository: str
    lifecycle: tuple[int | None, int | None, int | None, int | None] | None
    """FCS, GS end, ES end, and RS end in days from `D`; `None` for none."""
    cvss_threshold: Decimal | None = None


_SERVER_16: Final = "cpe:/o:example:fles:16.0"
_SERVER_15_SP7: Final = "cpe:/o:example:fles:15:sp7"
_LTSS_15_SP5: Final = "cpe:/o:example:fles-ltss:15:sp5"
_LTSS_15_SP4: Final = "cpe:/o:example:fles-ltss:15:sp4"
_SERVER_15_SP3: Final = "cpe:/o:example:fles:15:sp3"
_SERVER_17: Final = "cpe:/o:example:fles:17.0"
_MICRO_6_2: Final = "cpe:/o:example:fles-micro:6.2"

_PRODUCTS: Final = (
    _Product(
        _SERVER_16,
        "FLES",
        "16.0",
        "Fictional Linux Enterprise Server 16.0",
        "SUSE:Updates:FLES:16.0:x86_64",
        (-365, 1825, None, None),
    ),
    _Product(
        _SERVER_15_SP7,
        "FLES",
        "15-SP7",
        "Fictional Linux Enterprise Server 15 SP7",
        "SUSE:Updates:FLES:15-SP7:x86_64",
        (-730, 365, None, None),
    ),
    _Product(
        _LTSS_15_SP5,
        "FLES-LTSS",
        "15-SP5",
        "Fictional Linux Enterprise Server LTSS 15 SP5",
        "SUSE:Updates:FLES-LTSS:15-SP5:x86_64",
        (-1460, -365, 730, None),
        Decimal("7.0"),
    ),
    _Product(
        _LTSS_15_SP4,
        "FLES-LTSS",
        "15-SP4",
        "Fictional Linux Enterprise Server LTSS 15 SP4",
        "SUSE:Updates:FLES-LTSS:15-SP4:x86_64",
        (-1825, -730, -30, 365),
    ),
    _Product(
        _SERVER_15_SP3,
        "FLES",
        "15-SP3",
        "Fictional Linux Enterprise Server 15 SP3",
        "SUSE:Updates:FLES:15-SP3:x86_64",
        (-2555, -1460, -365, None),
    ),
    _Product(
        _SERVER_17,
        "FLES",
        "17.0",
        "Fictional Linux Enterprise Server 17.0",
        "SUSE:Updates:FLES:17.0:x86_64",
        (180, 2000, None, None),
    ),
    _Product(
        _MICRO_6_2,
        "FLES-Micro",
        "6.2",
        "Fictional Linux Enterprise Micro 6.2",
        "SUSE:Updates:FLES-Micro:6.2:x86_64",
        None,
    ),
)

_NVD: Final = CVESourceType.NVD
_MITRE: Final = CVESourceType.MITRE


@dataclass(frozen=True, slots=True)
class _CVE:
    cve_id: str
    first: CVESourceType | None
    """The source of the first ingestion; `None` for a manual creation."""
    nvd_vector: str | None = None
    cwe: str | None = None
    rejected: bool = False


_CVES: Final = (
    _CVE(
        "CVE-2099-0001", _NVD, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-787"
    ),
    _CVE(
        "CVE-2099-0002", _NVD, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "CWE-79"
    ),
    _CVE(
        "CVE-2099-0003", _NVD, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "CWE-200"
    ),
    _CVE("CVE-2099-0004", _NVD, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    _CVE("CVE-2099-0005", _NVD, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    _CVE("CVE-2099-0006", _MITRE),
    _CVE(
        "CVE-2099-0007",
        _NVD,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    ),
    _CVE("CVE-2099-0008", _MITRE, rejected=True),
    _CVE(
        "CVE-2099-0009", _NVD, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-22"
    ),
    _CVE("CVE-2099-0010", _NVD, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    _CVE(
        "CVE-2099-0011", _NVD, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-416"
    ),
    _CVE("CVE-2099-0012", _NVD, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    _CVE(
        "CVE-2099-0013", _NVD, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "CWE-400"
    ),
    _CVE(
        "CVE-2099-0014", _NVD, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "CWE-787"
    ),
    _CVE("CVE-2099-0015", _NVD, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    _CVE(
        "CVE-2099-0016", _NVD, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-125"
    ),
    _CVE("CVE-2099-0017", _NVD, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    _CVE(
        "CVE-2099-0018", None, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-287"
    ),
    _CVE("CVE-2099-0019", None, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    _CVE("CVE-2099-0020", None, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    _CVE("CVE-2099-0021", _NVD, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    _CVE("CVE-2099-0022", _NVD, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
    _CVE("CVE-2099-0023", _NVD, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
)
_CVE_DATA: Final = {cve.cve_id: cve for cve in _CVES}

_FIRST_BEFORE_MANUAL: Final = tuple(f"CVE-2099-{n:04d}" for n in range(1, 18))
_FIRST_AFTER_MANUAL: Final = tuple(f"CVE-2099-{n:04d}" for n in range(21, 24))
_NVD_AFTER_MANUAL: Final = ("CVE-2099-0018", "CVE-2099-0019", "CVE-2099-0020")
_MITRE_FURTHER: Final = ("CVE-2099-0009", "CVE-2099-0010")
_KEV_ADDED: Final = {"CVE-2099-0001": -2}
"""KEV date added, in days from `D`."""
_EPSS: Final = {
    "CVE-2099-0001": ("0.94", "0.99"),
    "CVE-2099-0002": ("0.12", "0.85"),
    "CVE-2099-0010": ("0.02", "0.40"),
    "CVE-2099-0018": ("0.31", "0.92"),
}
"""EPSS score and percentile, assessed `D - 1`."""
_GHSA: Final = {"CVE-2099-0010": "GHSA-2c4f-7h9j-mqrv"}

_NVD_FETCHER: Final = "sync_nvd_cves"
"""The fetcher of the source that the automatic references represent."""
_AUTOMATIC_REFERENCES: Final = {
    "CVE-2099-0001": (
        ("https://www.example.com/advisories/CVE-2099-0001", "Vendor Advisory"),
        ("https://git.example.com/fictional-lib/commit/0123abc", "Patch"),
    ),
}


@dataclass(frozen=True, slots=True)
class _ManualTicket:
    number: int
    """The Ticket's dataset number: `SNTL-{number}` on a new database."""
    creator: str
    cve_id: str | None = None
    severity: Severity | None = None
    coordinated_release_days: int | None = None
    """Confidential with a coordinated release date `T + days`."""


_MANUAL_TICKETS: Final = (
    _ManualTicket(18, "asmith", "CVE-2099-0018", coordinated_release_days=30),
    _ManualTicket(19, "bwilson", "CVE-2099-0019"),
    _ManualTicket(20, "cwhite", "CVE-2099-0020"),
    _ManualTicket(21, "asmith", severity=Severity.HIGH),
    _ManualTicket(22, "bwilson"),
)


def _ticket_number(cve_id: str) -> int:
    """The dataset number of the Ticket that the first ingestion of
    `cve_id` creates (Tickets)."""
    n = int(cve_id.rsplit("-", 1)[1])
    return n if n <= 17 else n + 2


@dataclass(frozen=True, slots=True)
class _Track:
    reference: str
    workflow: WorkflowType
    products: tuple[str, ...]


_GIT_16: Final = "fles-16.0"
_SP7_UPDATE: Final = "SUSE:FLES-15-SP7:Update"
_SP5_UPDATE: Final = "SUSE:FLES-15-SP5:Update"
_SP4_UPDATE: Final = "SUSE:FLES-15-SP4:Update"
_SP3_UPDATE: Final = "SUSE:FLES-15-SP3:Update"
_GIT, _IBS = WorkflowType.GIT, WorkflowType.IBS


@dataclass(frozen=True, slots=True)
class _Package:
    ticket: int
    name: str
    actor: str
    tracks: tuple[_Track, ...]
    maintained: bool


_PACKAGES: Final = {
    package.name: package
    for package in (
        _Package(
            11,
            "fictional-curl",
            "bwilson",
            (
                _Track(_GIT_16, _GIT, (_SERVER_16, _MICRO_6_2)),
                _Track(_SP7_UPDATE, _IBS, (_SERVER_15_SP7,)),
            ),
            maintained=True,
        ),
        _Package(
            13,
            "fictional-httpd",
            "asmith",
            (_Track(_SP7_UPDATE, _IBS, (_SERVER_15_SP7,)),),
            maintained=True,
        ),
        _Package(
            14,
            "fictional-libxml",
            "asmith",
            (_Track(_SP7_UPDATE, _IBS, (_SERVER_15_SP7,)),),
            maintained=True,
        ),
        _Package(
            15,
            "fictional-sudo",
            "bwilson",
            (
                _Track(_GIT_16, _GIT, (_SERVER_16, _MICRO_6_2)),
                _Track(_SP4_UPDATE, _IBS, (_LTSS_15_SP4,)),
            ),
            maintained=False,
        ),
        _Package(
            16,
            "fictional-kernel",
            "asmith",
            (
                _Track(_SP5_UPDATE, _IBS, (_LTSS_15_SP5,)),
                _Track(_SP3_UPDATE, _IBS, (_SERVER_15_SP3,)),
            ),
            maintained=False,
        ),
        _Package(
            18,
            "fictional-openssh",
            "asmith",
            (_Track(_SP7_UPDATE, _IBS, (_SERVER_15_SP7,)),),
            maintained=True,
        ),
    )
}

_SUSE_ASSESSMENTS: Final = {
    "CVE-2099-0013": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "asmith"),
    "CVE-2099-0014": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "asmith"),
    "CVE-2099-0015": ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "bwilson"),
    "CVE-2099-0016": ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "asmith"),
}
_SUSE_PROVIDER: Final = "SUSE"

_MANUAL_REFERENCE: Final = ManualReferenceCreateInput(
    url="https://bugzilla.example.com/show_bug.cgi?id=1000012",
    title="Fictional bug report",
    type=ReferenceType.ISSUE,
)

_RELEASE_ADVISORY: Final = "SUSE-SU-2099:0001-1"
_RELEASED_DAYS_AGO: Final = 2

# IBS Requests: number -> (type, incident, upstream created in days before T)
_MI: Final = IBSRequestActionType.MAINTENANCE_INCIDENT
_MR: Final = IBSRequestActionType.MAINTENANCE_RELEASE
_IBS_REQUESTS: Final = {
    900000: (_MI, None, 20),
    900001: (_MI, None, 5),
    900002: (_MI, 90001, 12),
    900003: (_MR, 90001, 6),
    900004: (_MI, 90002, 9),
    900005: (_MR, 90002, 2),
}
_REVIEW, _NEW = IBSRequestState.REVIEW, IBSRequestState.NEW
_ACCEPTED, _DECLINED = IBSRequestState.ACCEPTED, IBSRequestState.DECLINED

_Observed = tuple[int, IBSRequestState, int]
"""`(request number, state, upstream update in days before T)`."""

_OBSERVATIONS: Final[
    dict[str, tuple[tuple[DeliveryStatus, tuple[_Observed, ...]], ...]]
] = {
    "fictional-httpd": (
        (DeliveryStatus.IN_PROGRESS, ((900000, _REVIEW, 19),)),
        (DeliveryStatus.IN_PROGRESS, ((900000, _DECLINED, 18), (900001, _REVIEW, 4))),
    ),
    "fictional-libxml": (
        (DeliveryStatus.IN_PROGRESS, ((900002, _REVIEW, 11),)),
        (DeliveryStatus.IN_PROGRESS, ((900002, _ACCEPTED, 10), (900003, _NEW, 6))),
        (DeliveryStatus.RELEASED, ((900003, _ACCEPTED, 3),)),
    ),
    "fictional-openssh": (
        (DeliveryStatus.IN_PROGRESS, ((900004, _REVIEW, 9),)),
        (DeliveryStatus.IN_PROGRESS, ((900004, _ACCEPTED, 8), (900005, _NEW, 2))),
    ),
}
"""The complete observations of each package's SP7 track, in order (IBS
Requests)."""

_IBS_SOURCE_PROJECT: Final = "SUSE:FLES-15-SP7:Branches"
_IBS_ORIGIN: Final = "SUSE_FLES-15-SP7_Update"
_EVIDENCE_STATES: Final = frozenset({_REVIEW, _NEW, _ACCEPTED})
"""Request states whose action the observation holds; a `declined` request
establishes nothing, so Algorithm step 3 holds its request only."""


# ---------------------------------------------------------------------------
# Payloads and observations
# ---------------------------------------------------------------------------


def _description(cve_id: str) -> str:
    return f"Fictional vulnerability {cve_id} of the Sentinel example dataset."


def _published(cve_id: str, now: datetime) -> datetime:
    return now - timedelta(days=int(cve_id.rsplit("-", 1)[1]))


def _nvd_payload(cve: _CVE, now: datetime) -> CVEIngestPayload:
    """An NVD ingestion. A field without a value is omitted, not `None`,
    because an explicit `None` clears the stored value."""
    assert cve.nvd_vector is not None
    fields: dict[str, object] = {
        "description": _description(cve.cve_id),
        "cve_state": CveState.PUBLISHED,
        "published_date": _published(cve.cve_id, now),
        "modified_date": now - timedelta(days=1),
        "cvss_assessments": [
            CVSSAssessmentEntry(provider_name="NVD", vector_string=cve.nvd_vector)
        ],
    }
    if cve.cwe is not None:
        fields["cwe_classifications"] = [CWEEntry(cwe_id=cve.cwe, source="NVD")]
    return CVEIngestPayload.model_validate(fields)


def _mitre_payload(cve: _CVE, now: datetime) -> CVEIngestPayload:
    """A MITRE ingestion with the further data of the table."""
    fields: dict[str, object] = {
        "title": f"Fictional flaw {cve.cve_id}",
        "description": _description(cve.cve_id),
        "published_date": _published(cve.cve_id, now),
        "cve_state": CveState.REJECTED if cve.rejected else CveState.PUBLISHED,
    }
    if cve.cve_id == "CVE-2099-0009":
        fields["affected_version_operations"] = [
            AffectedVersionScopeOperation(
                source_container="cna",
                operation=AffectedVersionOperation.REPLACE,
                entries=[
                    AffectedVersionEntry(
                        vendor="Example",
                        product="fictional-tar",
                        version="1.0",
                        version_type="semver",
                        version_end="1.5",
                        version_end_inclusive=False,
                        status="affected",
                    )
                ],
            )
        ]
    elif cve.cve_id == "CVE-2099-0010":
        fields["ssvc_assessment"] = SSVCEntry(
            exploitation=SSVCExploitation.POC,
            automatable=SSVCAutomatable.NO,
            technical_impact=SSVCTechnicalImpact.PARTIAL,
            version="2.0.3",
            assessed_at=now - timedelta(days=3),
        )
    if cve.rejected:
        fields["date_rejected"] = now - timedelta(days=2)
    return CVEIngestPayload.model_validate(fields)


def _ibs_action(package: str, number: int, *, state: IBSRequestState) -> ActionWrite:
    """The one action of request `number` for `package` in the SP7
    codestream, in the form of its state (IBS Requests)."""
    action_type, incident, _ = _IBS_REQUESTS[number]
    accepted = state is _ACCEPTED
    physical = f"{package}.{_IBS_ORIGIN}"
    if action_type is _MI:
        source_project = _IBS_SOURCE_PROJECT
        target_project = f"SUSE:Maintenance:{incident}" if accepted else None
        target_package = physical if accepted else None
        target_release_project: str | None = _SP7_UPDATE
        incident_number = incident if accepted else None
    else:
        source_project = f"SUSE:Maintenance:{incident}"
        target_project = _SP7_UPDATE
        target_package = f"{package}.{incident}"
        target_release_project = None
        incident_number = incident
    return ActionWrite(
        key=action_key(
            number,
            action_type,
            source_project=source_project,
            source_package=physical,
            target_project=target_project,
            target_package=target_package,
            target_release_project=target_release_project,
        ),
        request_number=number,
        action_type=action_type,
        source_project=source_project,
        source_package=physical,
        target_project=target_project,
        target_package=target_package,
        target_release_project=target_release_project,
        logical_package=package,
        codestream_name=_SP7_UPDATE,
        incident_number=incident_number,
        accepted_revision="1" if accepted else None,
        accepted_srcmd5=f"{number:032d}" if accepted else None,
    )


def _observation(
    package: str,
    derived: DeliveryStatus,
    observed: Sequence[_Observed],
    now: datetime,
) -> Observation:
    requests = tuple(
        RequestWrite(
            request_number=number,
            state=state,
            superseded_by_request_number=None,
            upstream_created_at=now - timedelta(days=_IBS_REQUESTS[number][2]),
            upstream_updated_at=now - timedelta(days=updated),
        )
        for number, state, updated in observed
    )
    actions = tuple(
        _ibs_action(package, number, state=state)
        for number, state, _ in observed
        if state in _EVIDENCE_STATES
    )
    return Observation(derived, requests, actions)


# ---------------------------------------------------------------------------
# The load
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    """Clock seam for the load instant `T` (Time Base)."""
    return datetime.now(UTC)


async def load_example_dataset(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    progress: ExampleDatasetProgress | None = None,
) -> None:
    """Load the example dataset into a newly created database.

    Service-owned orchestration boundary (example-dataset.md, Service:
    `load_example_dataset()`; docs/conventions.md, Caller-Owned Service
    Transactions): opens one session for the guard and one for each
    operation.

    Q1: `session_factory` creates the load's sessions; `progress`, when
    given, receives the start and completion of each step and every
    committed operation.

    Q2: the Empty-Database Guard, before any write: a `User`, `Ticket`,
    `CVE`, or `Product` row raises `ExampleDatasetNotEmptyError`.

    Q3: captures `T` and `D`, applies the guard, imports the production
    fetcher registry, then performs the six steps of `STEPS` with the
    operations, attribution, and values of Dataset Content, each operation
    committed in its own transaction, under Isolation. A failure stops the
    load at the failing operation, which rolls back; the operations
    committed before it remain.

    Q4: creates no audit event of its own; the delegated services create
    their events.

    Q5: not idempotent; after a load that committed at least one
    operation, a repeated invocation raises `ExampleDatasetNotEmptyError`
    and writes nothing.

    Q6: `ExampleDatasetNotEmptyError` and `ExampleDatasetEffectError`;
    every exception of a delegated service and every database exception
    propagate unchanged.
    """
    load = _Load(session_factory, progress or _NoProgress(), _utc_now())
    await load.guard()
    import app.services.fetcher_discovery  # noqa: F401  (production registry)

    for step, perform in (
        (USERS_STEP, load.users),
        (SETTINGS_STEP, load.system_settings),
        (FETCHERS_STEP, load.fetchers),
        (CATALOG_STEP, load.product_catalog),
        (TICKETS_STEP, load.cves_and_tickets),
        (WORK_STEP, load.ticket_work),
    ):
        load.progress.step_started(step)
        await perform()
        load.progress.step_completed(step)


class _Load:
    """The state of one load: its time base and the identifiers that its
    operations create."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        progress: ExampleDatasetProgress,
        now: datetime,
    ) -> None:
        self.session_factory = session_factory
        self.progress = progress
        self.now = now
        self.today: date = now.date()
        self.user_ids: dict[str, uuid.UUID] = {}
        self.ticket_ids: dict[int, uuid.UUID] = {}
        self.cve_ids: dict[str, uuid.UUID] = {}

    # -- transactions -------------------------------------------------------

    async def run[R](self, operation: Callable[[AsyncSession], Awaitable[R]]) -> R:
        """Run one operation in its own session and transaction and commit
        it, unless it registered a post-commit effect (Isolation)."""
        async with self.session_factory() as session:
            try:
                result = await operation(session)
                convergence = pending_ticket_convergence_effects(session)
                callbacks = detach_post_commit_callbacks(session)
                if convergence or callbacks:
                    # The rollback below discards the effect unpublished.
                    raise ExampleDatasetEffectError()
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
        self.progress.operation_committed()
        return result

    async def publish(
        self, publication: Callable[[AsyncSession], Awaitable[object]]
    ) -> None:
        """Run one catalog publication, which commits its own transaction
        in a session with no open transaction."""
        async with self.session_factory() as session:
            try:
                await publication(session)
            except BaseException:
                await session.rollback()
                raise
        self.progress.operation_committed()

    async def guard(self) -> None:
        """The Empty-Database Guard."""
        async with self.session_factory() as session:
            occupied = await session.scalar(
                select(
                    or_(
                        *(
                            select(model.id).exists()
                            for model in (User, Ticket, CVE, Product)
                        )
                    )
                )
            )
            await session.rollback()
        if occupied:
            raise ExampleDatasetNotEmptyError()

    async def caller(self, db: AsyncSession, username: str) -> TicketCaller:
        """The consumer caller context of a dataset user: its identity and
        effective scope."""
        user_id = self.user_ids[username]
        roles = await user_service.get_user_roles(db, user_id)
        return TicketCaller.authenticated(user_id, get_effective_scope(roles))

    # -- Users --------------------------------------------------------------

    async def users(self) -> None:
        for user in _USERS:
            # The first administrator is created without an acting user.
            acting = None if user.username == _ADMIN else self.user_ids[_ADMIN]

            async def create(
                db: AsyncSession,
                user: _User = user,
                acting: uuid.UUID | None = acting,
            ) -> uuid.UUID:
                created = await user_service.create_user(
                    db,
                    username=user.username,
                    email=user.email,
                    full_name=user.full_name,
                    password=PASSWORD,
                    roles=[(role, _MANUAL_ORIGIN) for role in user.roles],
                    acting_user_id=acting,
                )
                return created.id

            self.user_ids[user.username] = await self.run(create)

        async def deactivate(db: AsyncSession) -> None:
            await user_service.deactivate_user(
                db,
                self.user_ids[_INACTIVE],
                acting_user_id=self.user_ids[_ADMIN],
                reason=_DEACTIVATION_REASON,
            )

        await self.run(deactivate)

    # -- System settings ------------------------------------------------------

    async def system_settings(self) -> None:
        for version in _CVSS_VERSION_CHANGES:

            async def change(
                db: AsyncSession, version: Literal["3.1", "4.0"] = version
            ) -> None:
                await settings_service.update_default_cvss_version(
                    db, new_version=version, acting_user_id=self.user_ids[_ADMIN]
                )

            await self.run(change)

    # -- Fetchers -------------------------------------------------------------

    async def fetchers(self) -> None:
        await self.run(fetcher_bootstrap.bootstrap_fetcher_configs)
        for name in sorted(FETCHER_REGISTRY):

            async def disable(db: AsyncSession, name: str = name) -> None:
                # The returned RedBeat propagation is not applied (Isolation).
                await fetcher_operations.update_fetcher_config(
                    db,
                    fetcher_name=name,
                    user_id=self.user_ids[_ADMIN],
                    payload=fetcher_operations.UpdateConfigPayload(enabled=False),
                )

            await self.run(disable)

    # -- Product catalog ------------------------------------------------------

    def _day(self, offset: int | None) -> date | None:
        return None if offset is None else self.today + timedelta(days=offset)

    def _lifecycle(self, product: _Product) -> LifecycleDates:
        assert product.lifecycle is not None
        fcs, gs_end, es_end, rs_end = product.lifecycle
        return LifecycleDates(
            first_customer_ship_date=self._day(fcs),
            general_support_end_date=self._day(gs_end),
            extended_support_end_date=self._day(es_end),
            reactive_support_end_date=self._day(rs_end),
        )

    async def product_catalog(self) -> None:
        products = [
            CatalogProduct(
                cpe=product.cpe,
                name=product.name,
                version=product.version,
                display_name=product.display_name,
                repos=(product.repository,),
            )
            for product in _PRODUCTS
        ]
        await self.publish(lambda db: publish_snapshot(db, products, self.now))
        lifecycle = {
            product.cpe: self._lifecycle(product)
            for product in _PRODUCTS
            if product.lifecycle is not None
        }
        await self.publish(lambda db: publish_lifecycle_dates(db, lifecycle))
        thresholds = {
            product.cpe: product.cvss_threshold
            for product in _PRODUCTS
            if product.cvss_threshold is not None
        }
        await self.publish(lambda db: publish_thresholds(db, thresholds))

    # -- CVEs and tickets -----------------------------------------------------

    async def ingest(
        self, cve_id: str, source: CVESourceType, payload: CVEIngestPayload
    ) -> None:
        """One ingestion: `upsert_cve()` with its automatic references in
        the same transaction, as the fetcher of `source` would."""
        first = cve_id not in self.cve_ids
        references = _AUTOMATIC_REFERENCES.get(cve_id, ()) if first else ()

        async def upsert(db: AsyncSession) -> tuple[uuid.UUID, uuid.UUID]:
            result = await cve_service.upsert_cve(db, cve_id, source, payload)
            if references:
                await reference_service.upsert_references(
                    db,
                    result.ticket.id,
                    cve_id,
                    _NVD_FETCHER,
                    None,
                    [
                        AutomaticReferenceInput(url=url, upstream_tags=[tag])
                        for url, tag in references
                    ],
                )
            return result.cve.id, result.ticket.id

        cve_uuid, ticket_id = await self.run(upsert)
        if first:
            self.cve_ids[cve_id] = cve_uuid
            self.ticket_ids[_ticket_number(cve_id)] = ticket_id

    async def first_ingestion(self, cve_id: str) -> None:
        cve = _CVE_DATA[cve_id]
        assert cve.first is not None
        payload = (
            _nvd_payload(cve, self.now)
            if cve.first is _NVD
            else _mitre_payload(cve, self.now)
        )
        await self.ingest(cve_id, cve.first, payload)

    async def manual_ticket(self, ticket: _ManualTicket) -> None:
        async def create(db: AsyncSession) -> tuple[uuid.UUID, uuid.UUID | None]:
            created = await ticket_service.create_ticket(
                db,
                acting_user_id=self.user_ids[ticket.creator],
                cve_id=ticket.cve_id,
                severity_manual=ticket.severity,
                is_confidential=ticket.coordinated_release_days is not None,
                coordinated_release_at=None
                if ticket.coordinated_release_days is None
                else self.now + timedelta(days=ticket.coordinated_release_days),
                source=ticket_service.TicketCreationSource.MANUAL,
            )
            return created.id, created.cve_id

        ticket_id, cve_uuid = await self.run(create)
        self.ticket_ids[ticket.number] = ticket_id
        if ticket.cve_id is not None and cve_uuid is not None:
            self.cve_ids[ticket.cve_id] = cve_uuid

    async def cves_and_tickets(self) -> None:
        for cve_id in _FIRST_BEFORE_MANUAL:
            await self.first_ingestion(cve_id)
        for ticket in _MANUAL_TICKETS:
            await self.manual_ticket(ticket)
        for cve_id in _FIRST_AFTER_MANUAL:
            await self.first_ingestion(cve_id)
        for cve_id in _NVD_AFTER_MANUAL:
            await self.ingest(cve_id, _NVD, _nvd_payload(_CVE_DATA[cve_id], self.now))
        for cve_id in _MITRE_FURTHER:
            await self.ingest(
                cve_id, _MITRE, _mitre_payload(_CVE_DATA[cve_id], self.now)
            )
        for cve_id, days in _KEV_ADDED.items():
            await self.ingest(
                cve_id,
                CVESourceType.KEV,
                CVEIngestPayload(
                    kev_data=KEVEntry(date_added=self.today + timedelta(days=days))
                ),
            )
        for cve_id, (score, percentile) in _EPSS.items():
            await self.ingest(
                cve_id,
                CVESourceType.EPSS,
                CVEIngestPayload(
                    epss_score=EPSSEntry(
                        score=float(score),
                        percentile=float(percentile),
                        assessed_at=self.today - timedelta(days=1),
                    )
                ),
            )
        for cve_id, identifier in _GHSA.items():
            await self.ingest(
                cve_id,
                CVESourceType.GHSA,
                CVEIngestPayload(
                    external_identifiers=[
                        ExternalIdentifierEntry(
                            source=CVEExternalIdentifierSource.GHSA,
                            identifier=identifier,
                        )
                    ]
                ),
            )

    # -- Ticket work ----------------------------------------------------------

    async def add_package(self, name: str) -> None:
        package = _PACKAGES[name]

        async def add(db: AsyncSession) -> None:
            tracks = []
            for track in package.tracks:
                product_ids = await _product_ids(db, track.products)
                tracks.append(
                    package_service.ResolvedTrackData(
                        reference=track.reference,
                        workflow_type=track.workflow,
                        catalog_product_ids=product_ids,
                    )
                )
            await package_service.add_package_records(
                db,
                ticket_id=self.ticket_ids[package.ticket],
                package_name=package.name,
                tracks=tracks,
                maintainer_emails={_MAINTAINER_EMAIL} if package.maintained else set(),
                acting_user_id=self.user_ids[package.actor],
                caller=await self.caller(db, package.actor),
            )

        await self.run(add)

    async def track_status(
        self, name: str, reference: str, status: PackageStatus, actor: str | None
    ) -> None:
        """`set_track_status()` by `actor`; `None` stands for track release
        detection, a system operation."""
        package = _PACKAGES[name]
        ticket_id = self.ticket_ids[package.ticket]

        async def set_status(db: AsyncSession) -> None:
            package_id, track_id = await _track(db, ticket_id, name, reference)
            await package_service.set_track_status(
                db,
                ticket_id=ticket_id,
                package_id=package_id,
                track_id=track_id,
                status=status,
                acting_user_id=None if actor is None else self.user_ids[actor],
                caller=package_service.SYSTEM_INVOCATION
                if actor is None
                else await self.caller(db, actor),
            )

        await self.run(set_status)

    async def suse_assessment(self, cve_id: str) -> None:
        vector, actor = _SUSE_ASSESSMENTS[cve_id]

        async def assess(db: AsyncSession) -> None:
            await ticket_mutations.upsert_cvss_assessment(
                db,
                cve_id=self.cve_ids[cve_id],
                provider=_SUSE_PROVIDER,
                vector_string=vector,
                caller=ticket_mutations.CVSSMutationCaller.MANUAL_SUSE,
                acting_user_id=self.user_ids[actor],
                ticket_caller=await self.caller(db, actor),
            )

        await self.run(assess)

    async def ibs_observations(self, name: str) -> None:
        package = _PACKAGES[name]
        ticket_id = self.ticket_ids[package.ticket]
        for derived, observed in _OBSERVATIONS[name]:
            observation = _observation(name, derived, observed, self.now)

            async def apply(
                db: AsyncSession, observation: Observation = observation
            ) -> None:
                _, track_id = await _track(db, ticket_id, name, _SP7_UPDATE)
                await apply_ibs_request_observation(
                    db, track_id=track_id, observation=observation
                )

            await self.run(apply)

    async def product_release(self, name: str, cpe: str) -> None:
        """Product release detection confirms the release of `cpe` on the
        package's SP7 track (a system operation)."""
        ticket_id = self.ticket_ids[_PACKAGES[name].ticket]

        async def release(db: AsyncSession) -> None:
            package_id, track_id = await _track(db, ticket_id, name, _SP7_UPDATE)
            [product_id] = await _product_ids(db, (cpe,))
            occurrence_id = await db.scalar(
                select(TicketPackageProduct.id).where(
                    TicketPackageProduct.ticket_package_track_id == track_id,
                    TicketPackageProduct.product_id == product_id,
                )
            )
            assert occurrence_id is not None
            await package_service.set_product_released_at(
                db,
                ticket_id=ticket_id,
                package_id=package_id,
                track_id=track_id,
                ticket_package_product_id=occurrence_id,
                released_at=self.now - timedelta(days=_RELEASED_DAYS_AGO),
                advisory_id=_RELEASE_ADVISORY,
            )

        await self.run(release)

    async def ticket_work(self) -> None:
        affected, fixed = PackageStatus.AFFECTED, PackageStatus.FIXED
        # SNTL-11
        await self.add_package("fictional-curl")
        await self.track_status("fictional-curl", _GIT_16, affected, "bwilson")
        # SNTL-12
        sntl_12 = self.ticket_ids[12]

        async def assign(db: AsyncSession) -> None:
            await ticket_service.assign_ticket(
                db,
                ticket_id=sntl_12,
                assignee="asmith",
                acting_user_id=self.user_ids["bwilson"],
                caller=await self.caller(db, "bwilson"),
            )

        async def prioritize(db: AsyncSession) -> None:
            await ticket_service.set_priority_override(
                db,
                ticket_id=sntl_12,
                priority=TicketPriority.P1,
                acting_user_id=self.user_ids["bwilson"],
                caller=await self.caller(db, "bwilson"),
            )

        async def reference(db: AsyncSession) -> None:
            sequence_id = await db.scalar(
                select(Ticket.sequence_id).where(Ticket.id == sntl_12)
            )
            assert sequence_id is not None
            await reference_service.create_reference(
                db,
                format_ticket_id(sequence_id),
                await self.caller(db, "asmith"),
                _MANUAL_REFERENCE,
            )

        await self.run(assign)
        await self.run(prioritize)
        await self.run(reference)
        # SNTL-13
        await self.add_package("fictional-httpd")
        await self.track_status("fictional-httpd", _SP7_UPDATE, affected, "asmith")
        await self.suse_assessment("CVE-2099-0013")
        await self.ibs_observations("fictional-httpd")
        # SNTL-14
        await self.add_package("fictional-libxml")
        await self.track_status("fictional-libxml", _SP7_UPDATE, affected, "asmith")
        await self.suse_assessment("CVE-2099-0014")
        await self.ibs_observations("fictional-libxml")
        await self.track_status("fictional-libxml", _SP7_UPDATE, fixed, None)
        await self.product_release("fictional-libxml", _SERVER_15_SP7)
        # SNTL-15
        await self.add_package("fictional-sudo")
        await self.track_status(
            "fictional-sudo", _GIT_16, PackageStatus.NOT_AFFECTED, "bwilson"
        )
        await self.track_status(
            "fictional-sudo", _SP4_UPDATE, PackageStatus.WONT_FIX, "bwilson"
        )
        await self.suse_assessment("CVE-2099-0015")
        # SNTL-16
        await self.add_package("fictional-kernel")
        await self.track_status("fictional-kernel", _SP5_UPDATE, affected, "asmith")
        await self.suse_assessment("CVE-2099-0016")
        # SNTL-17
        sntl_17 = self.ticket_ids[17]

        async def ignore(db: AsyncSession) -> None:
            await ticket_service.ignore_ticket(
                db,
                ticket_id=sntl_17,
                acting_user_id=self.user_ids["bwilson"],
                caller=await self.caller(db, "bwilson"),
            )

        await self.run(ignore)
        # SNTL-18
        await self.add_package("fictional-openssh")
        await self.track_status("fictional-openssh", _SP7_UPDATE, affected, "asmith")
        await self.ibs_observations("fictional-openssh")
        sntl_18 = self.ticket_ids[18]

        async def grant(db: AsyncSession) -> None:
            await ticket_service.grant_access(
                db,
                ticket_id=sntl_18,
                target_user="cwhite",
                acting_user_id=self.user_ids["asmith"],
                caller=await self.caller(db, "asmith"),
            )

        await self.run(grant)
        # SNTL-19
        sntl_19 = self.ticket_ids[19]

        async def confidential(db: AsyncSession) -> None:
            await ticket_service.set_confidentiality(
                db,
                ticket_id=sntl_19,
                is_confidential=True,
                acting_user_id=self.user_ids["bwilson"],
                caller=await self.caller(db, "bwilson"),
            )

        await self.run(confidential)
        # SNTL-22
        sntl_21, sntl_22 = self.ticket_ids[21], self.ticket_ids[22]

        async def duplicate(db: AsyncSession) -> None:
            await ticket_service.mark_as_duplicate(
                db,
                ticket_id=sntl_22,
                duplicate_of_id=sntl_21,
                acting_user_id=self.user_ids["bwilson"],
                caller=await self.caller(db, "bwilson"),
            )

        await self.run(duplicate)


# ---------------------------------------------------------------------------
# Identifier reads
# ---------------------------------------------------------------------------


async def _product_ids(db: AsyncSession, cpes: Sequence[str]) -> tuple[uuid.UUID, ...]:
    """The Product IDs of `cpes`, in their order."""
    rows = await db.execute(
        select(Product.cpe, Product.id).where(Product.cpe.in_(list(cpes)))
    )
    ids = {row.cpe: row.id for row in rows}
    return tuple(ids[cpe] for cpe in cpes)


async def _track(
    db: AsyncSession, ticket_id: uuid.UUID, package_name: str, reference: str
) -> tuple[uuid.UUID, uuid.UUID]:
    """`(package ID, track ID)` of the track `reference` of `package_name`
    below `ticket_id`."""
    row = (
        await db.execute(
            select(TicketPackage.id, TicketPackageTrack.id)
            .join(
                TicketPackageTrack,
                TicketPackageTrack.ticket_package_id == TicketPackage.id,
            )
            .where(
                TicketPackage.ticket_id == ticket_id,
                TicketPackage.package_name == package_name,
                TicketPackageTrack.reference == reference,
            )
        )
    ).one()
    return row[0], row[1]
