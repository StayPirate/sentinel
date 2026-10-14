"""End-to-end tests of the shared IBS request reconciliation over the
sanitized live provenance chains.

Owning specifications: docs/features/packages/ibs-submission-tracking.md
(Required Roots, Effective SR, Release Discovery, Accepted RR Provenance,
Delivery Derivation, Shared Authoritative Reconciliation) and
docs/features/packages/package-model.md (Automatic Transitions: delivery
transitions, `PENDING -> IN_PROGRESS -> RELEASED` in one transaction).

Each test reconciles one committed scope through the real boundary, with
the request group of `tests/support/ibs_request_api.py` and the
provenance group of `tests/support/ibs_request_provenance.py` served at
their recorded method, path, and query behind a real `IBSClient`; every
other request is unrouted (HTTP 404) and asserted absent. The rows the
reconciliation writes are deleted at teardown through the world's request
numbers.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Final

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.enums import DeliveryStatus, IBSRequestActionType, IBSRequestState
from tests.support.ibs_product_release import UnitSessions
from tests.support.ibs_request_provenance import (
    A_CVES,
    B_CVE,
    B_INCIDENT,
    B_RR,
    B_SR,
    C_INCIDENT,
    C_RR,
    C_RR_NEWER,
    SLE15,
    SP6,
)
from tests.support.ibs_request_reconciliation import (
    EvidenceRow,
    FakeRequests,
    RequestSeed,
    RequestWorld,
    cve_issue,
    delivery_of,
    evidence_of,
    install_fake_requests,
    install_request_units,
    kinds,
    reconcile,
    serve_provenance,
    serve_request_group_fixture,
)

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]

A_RR: Final = 910051
A_INCIDENT: Final = 80001
A_LOOKUP_SRCMD5: Final = "c40f9d03a8728b65ac857fe47495c082"
C_KERNEL_CVE: Final = "CVE-2024-44981"
"""A CVE released by kernel release request 960035 and not by 960036."""


@pytest.fixture(autouse=True)
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeRequests:
    return install_fake_requests(monkeypatch)


@pytest.fixture(autouse=True)
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> UnitSessions:
    return install_request_units(monkeypatch, real_session_factory)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RequestWorld]:
    created = RequestWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


class TestReleaseProvenChains:
    async def test_the_openvpn_release_is_proven_through_the_release_scan(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(cve_id=A_CVES[0]), package="openvpn")
        await seed.commit()
        world.numbers().add(A_RR)
        for name in ("a_sourceinfo_current", "a_diff_current"):
            serve_provenance(fake, name)
        for name in (
            "history_codestream",
            "request_rr_accepted",
            "diff_rr_accepted",
            "history_lookup_revision",
        ):
            serve_request_group_fixture(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.RELEASED
        assert await evidence_of(probe, scope.track_id) == [
            EvidenceRow(
                request_number=A_RR,
                state=IBSRequestState.ACCEPTED.value,
                superseded_by_request_number=None,
                action_type=IBSRequestActionType.MAINTENANCE_RELEASE.value,
                logical_package="openvpn",
                codestream_name=SP6,
                incident_number=A_INCIDENT,
                accepted_revision="1",
                accepted_srcmd5=A_LOOKUP_SRCMD5,
                target_project=SP6,
                target_package=f"openvpn.{A_INCIDENT}",
                source_project=f"SUSE:Maintenance:{A_INCIDENT}",
            )
        ]

    async def test_a_release_before_2023_is_proven_by_its_release_request_alone(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=B_CVE), package="openvpn", codestream=SLE15
        )
        await seed.commit()
        world.numbers().update({B_RR, B_SR})
        for name in (
            "b_sourceinfo_current",
            "b_diff_current",
            "b_history_codestream",
            "b_request_rr_accepted",
            "b_diff_rr_accepted",
            "b_history_lookup",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.RELEASED
        [row] = await evidence_of(probe, scope.track_id)
        assert (row.request_number, row.incident_number) == (B_RR, B_INCIDENT)

    async def test_a_kernel_release_is_proven_at_an_older_scan_entry(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=C_KERNEL_CVE), package="kernel-source"
        )
        await seed.commit()
        world.numbers().update({C_RR, C_RR_NEWER})
        fake.release_evidence(SP6, "kernel-source", cve_issue(C_KERNEL_CVE))
        for name in (
            "c_history_codestream_source",
            "c_request_rr_newer",
            "c_diff_rr_source_newer",
            "c_request_rr_accepted",
            "c_diff_rr_source",
            "c_history_lookup_source",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.RELEASED
        [row] = await evidence_of(probe, scope.track_id)
        assert (row.request_number, row.incident_number) == (C_RR, C_INCIDENT)
