"""SQLAlchemy ORM models."""

from app.models.api_key import ApiKey
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_source import CVESource
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.mixins import AuditEventMixin
from app.models.product import Product
from app.models.product_repository import ProductRepository
from app.models.session import Session
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

__all__ = [
    "CVE",
    "CVECWE",
    "ApiKey",
    "AuditEventMixin",
    "CVEAffectedVersion",
    "CVECVSSAssessment",
    "CVEEPSSScore",
    "CVEExternalIdentifier",
    "CVEKEVEntry",
    "CVESSVCAssessment",
    "CVESource",
    "FetcherAuditEvent",
    "FetcherConfig",
    "FetcherRun",
    "IdentityAuditEvent",
    "Product",
    "ProductRepository",
    "Session",
    "SettingAuditEvent",
    "SystemSetting",
    "Ticket",
    "TicketAccessGrant",
    "TicketAuditEvent",
    "TicketPackage",
    "TicketPackageMaintainer",
    "TicketPackageProduct",
    "TicketPackageTrack",
    "TicketReference",
    "User",
    "UserRole",
]
