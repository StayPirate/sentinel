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

import xml.etree.ElementTree as ET
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
    C_SR_FIRST,
    C_SR_SECOND,
    SLE15,
    SP6,
    load_provenance_fixture,
)
from tests.support.ibs_request_reconciliation import (
    Accept,
    Action,
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


def _fixture_action(name: str, target_package: str) -> Action:
    """The action of provenance fixture `name` whose target package is
    `target_package`, as served."""
    root = ET.fromstring(load_provenance_fixture(name))
    for element in root.iter("action"):
        target = element.find("target")
        if target is None or target.get("package") != target_package:
            continue
        source = element.find("source")
        assert source is not None
        accept = element.find("acceptinfo")
        return Action(
            type=element.get("type", ""),
            source_project=source.get("project", ""),
            source_package=source.get("package", ""),
            rev=source.get("rev"),
            target_project=target.get("project"),
            target_package=target.get("package"),
            release_project=target.get("releaseproject"),
            accept=None if accept is None else Accept(**accept.attrib),
        )
    raise AssertionError(f"no action for {target_package} in {name}")


def _served_paths(fake: FakeRequests) -> list[str]:
    return [f"{method} {path}" for method, path, _ in fake.served]


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


class TestKernelIncident:
    async def test_the_second_sr_replaces_the_first_and_establishes_progress(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The track is correlated to the first kernel SR; the incident
        history names a second SR after it, which is the effective one and
        carries the Ticket CVE in its own diff."""
        package = "kernel-source.SUSE_SLE-15-SP6_Update"
        first = _fixture_action("c_request_sr_first", package)
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=C_KERNEL_CVE), package="kernel-source"
        )
        await seed.evidence(C_SR_FIRST, IBSRequestState.ACCEPTED, first, tracks=[scope])
        await seed.commit()
        world.numbers().update({C_SR_SECOND, C_RR})
        fake.quiet("kernel-source", SP6)
        for name in (
            "c_history_incident_source",
            "c_request_sr_second",
            "c_diff_sr_second",
            "c_request_rr_accepted",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        assert f"GET /request/{C_SR_FIRST}" not in _served_paths(fake)
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.IN_PROGRESS
        assert [
            row.request_number for row in await evidence_of(probe, scope.track_id)
        ] == [
            C_SR_FIRST,
            C_SR_SECOND,
        ]

    async def test_a_flavor_release_without_acceptinfo_stops_the_scan(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The newest release of the link-only flavor has no acceptinfo:
        neither it nor an older release can be proven, so the observation
        continues with the other roots and finds nothing."""
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=C_KERNEL_CVE), package="kernel-default"
        )
        await seed.commit()
        world.numbers().add(C_RR_NEWER)
        fake.quiet("kernel-default", SP6)
        fake.release_evidence(SP6, "kernel-default", cve_issue(C_KERNEL_CVE))
        for name in ("c_history_codestream_default", "c_request_rr_newer"):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "no_op"}
        assert fake.unrouted == []
        assert [
            path for path in _served_paths(fake) if path.startswith("GET /request/")
        ] == [f"GET /request/{C_RR_NEWER}"]
        assert not [
            (path, query)
            for _, path, query in fake.served
            if ("withissues", "1") in query or (path.endswith("/_history") and query)
        ]
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.PENDING
        assert await evidence_of(probe, scope.track_id) == []

    async def test_kernel_default_base_is_released_without_cve_evidence(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """`kernel-default-base` has no SR in its incident; its release
        request alone passes the exact lookup, but its release diff names
        no CVE, so it proves nothing and is not incomplete."""
        target = f"kernel-default-base.{C_INCIDENT}"
        release_action = _fixture_action("c_request_rr_accepted", target)
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=C_KERNEL_CVE), package="kernel-default-base"
        )
        await seed.evidence(
            C_RR, IBSRequestState.ACCEPTED, release_action, tracks=[scope]
        )
        await seed.commit()
        fake.quiet("kernel-default-base", SP6)
        for name in (
            "c_request_rr_accepted",
            "c_history_lookup_default_base",
            "c_diff_rr_default_base",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "no_op"}
        assert fake.unrouted == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.PENDING


class TestReleaseBefore2023Submission:
    async def test_the_effective_sr_establishes_progress_from_retained_provenance(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The correlated accepted SR is effective in its incident history
        (a branch commit before it, its release request after it), checked
        from retained provenance without point detail; current release
        evidence without the CVE needs no scan."""
        sr = _fixture_action("b_request_sr_accepted", "openvpn.SUSE_SLE-15_Update")
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=B_CVE), package="openvpn", codestream=SLE15
        )
        await seed.evidence(B_SR, IBSRequestState.ACCEPTED, sr, tracks=[scope])
        await seed.commit()
        world.numbers().add(B_RR)
        fake.quiet("openvpn", SLE15)
        for name in ("b_history_incident", "b_request_rr_accepted"):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert fake.unrouted == []
        assert f"GET /request/{B_SR}" not in _served_paths(fake)
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.IN_PROGRESS
