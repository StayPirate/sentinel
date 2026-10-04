"""Shared helpers for the `add_package_to_ticket()` service tests.

`package_service.add_package_to_ticket()` is the I/O-then-Lock package
addition orchestrator (package-service.md, `add_package_to_ticket()`;
package-model.md, Adding Packages to a Ticket, SMELT Query for Package
Resolution). These helpers provide:

- `PackageSmelt`, an in-process `httpx.MockTransport` handler serving both
  SMELT endpoints the orchestrator calls (the package-scoped maintained
  endpoint and the package maintainership endpoint). It records every
  request in order (`kinds`), optionally appends `("http", kind)` to a
  shared `events` list so a test can order requests against statements or
  other events, and can hold a request on a `Pause` so that an
  independent session acts deterministically while the external phase is
  in flight;
- fictional response builders for both endpoints;
- `publish()`, which places catalog Products in the current Product
  catalog snapshot (`catalog_last_seen_at = SNAPSHOT_AT`, the snapshot
  `MAX`, product-catalog.md, Catalog Readiness and Freshness) or in an
  earlier, historical one;
- `add()`, which calls the orchestrator as the user-facing package
  addition (`actor`, effective `scope`, `NULL` comment) or a system
  workflow (`None`, the canonical comment) would, with the fake client.

`SNAPSHOT_AT` lies far in the future, so a published Product is current
whatever other Products a test seeds through `catalog_product()` (whose
`catalog_last_seen_at` is the wall clock). All values are fictional
(`smelt.example.test`, `cpe:/o:example:...`, `example.com` emails).

Consumers: `tests/test_services/test_add_package_to_ticket.py`,
`tests/test_services/test_add_package_to_ticket_races.py`, and
`tests/test_services/test_new_to_analysis_promotion.py`.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Scope
from app.models.product import Product
from app.models.user import User
from app.services.package_service import (
    SYSTEM_INVOCATION,
    AddPackageResult,
    PackageAddedComment,
    add_package_to_ticket,
)
from app.services.ticket_visibility import TicketCaller

SNAPSHOT_AT = datetime(2099, 1, 1, 3, 0, tzinfo=UTC)
"""The current Product catalog snapshot timestamp of a published Product."""

HISTORICAL_AT = SNAPSHOT_AT - timedelta(days=1)
"""An earlier snapshot: a Product published at it is retained historical."""

Kind = Literal["maintained", "maintainership"]
Respond = Callable[[httpx.Request], httpx.Response | Awaitable[httpx.Response]]

MAINTAINED_PATH = "/experimental/v2/maintained/"
MAINTAINERSHIP_SUFFIX = "/maintainership"


# ---------------------------------------------------------------------------
# Catalog snapshot
# ---------------------------------------------------------------------------


async def publish(
    db: AsyncSession, *products: Product, at: datetime = SNAPSHOT_AT
) -> None:
    """Set `catalog_last_seen_at` of `products` to `at` and flush."""
    for product in products:
        product.catalog_last_seen_at = at
    await db.flush()


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------


def target(cpe: str, friendly_name: str | None = None) -> dict[str, Any]:
    """One maintained target with the unconsumed upstream fields."""
    return {
        "product": {
            "id": 1001,
            "friendly_name": friendly_name or f"Example {cpe.rsplit(':', 2)[-2]}",
            "cpe": cpe,
            "support_status": "General Support",
        },
        "repository": "EXAMPLE:Products:Product:1",
        "product_definition": {
            "name": "Example-Product_1",
            "url": "https://build.example.invalid/fictional/definition",
            "type": "channel",
        },
        "binary_packages": [],
    }


def codestream(name: str, process: str, *cpes: str) -> dict[str, Any]:
    """One grouped maintained entry of maintenance process `process`
    (`SLFO`, `SLE_15`, `SLFO_IBS`, or `UNKNOWN`) with one target per CPE."""
    return {
        "codestream": {
            "name": name,
            "url": "https://build.example.invalid/fictional/codestream",
            "type": process,
        },
        "targets": [target(cpe) for cpe in cpes],
    }


def maintained(*entries: dict[str, Any]) -> dict[str, Any]:
    """A JSend success envelope of the maintained endpoint."""
    return {"status": "success", "data": list(entries)}


def not_found(package_name: str = "fictional-package") -> dict[str, Any]:
    """The JSend error envelope of an HTTP 404 package-not-found response."""
    return {"status": "error", "data": f"Package {package_name} not found"}


def maintainership(*emails: str | None) -> dict[str, Any]:
    """A JSend success envelope of the maintainership endpoint: one entry
    with one direct user per email (`None` is a null email)."""
    return {
        "status": "success",
        "data": [
            {
                "codestream": {
                    "name": "Fictional:Codestream:1",
                    "url": "https://example.com/fictional-codestream-1",
                },
                "users": [
                    {"username": f"maintainer-{index}", "email": email}
                    for index, email in enumerate(emails, start=1)
                ],
                "groups": [],
            }
        ],
    }


def reply(status_code: int, body: Any) -> Respond:
    """Respond with `status_code` and the JSON `body`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=body)

    return respond


def fail(error: Exception) -> Respond:
    """Raise `error` (for example `httpx.ConnectError`) at the transport."""

    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


# ---------------------------------------------------------------------------
# Fake SMELT
# ---------------------------------------------------------------------------


class Pause:
    """Holds a request until `release` is set; `arrived` is set when the
    request reaches the fake server."""

    def __init__(self) -> None:
        self.arrived = asyncio.Event()
        self.release = asyncio.Event()

    async def hold(self) -> None:
        self.arrived.set()
        await self.release.wait()


class PackageSmelt:
    """A fake SMELT serving the maintained and maintainership endpoints.

    `responses` maps each endpoint kind to its responder; an unset kind
    answers with an HTTP 500 that the test would observe as a failure.
    `pauses` maps a kind to a `Pause` that holds its request before the
    responder runs.
    """

    def __init__(
        self,
        *,
        maintained: Respond | None = None,
        maintainership: Respond | None = None,
        events: list[tuple[str, str]] | None = None,
    ) -> None:
        self.responses: dict[Kind, Respond] = {}
        if maintained is not None:
            self.responses["maintained"] = maintained
        if maintainership is not None:
            self.responses["maintainership"] = maintainership
        self.pauses: dict[Kind, Pause] = {}
        self.requests: list[tuple[Kind, httpx.Request]] = []
        self.events = events
        self.clients: list[httpx.AsyncClient] = []

    @classmethod
    def ok(
        cls,
        *entries: dict[str, Any],
        emails: Iterable[str | None] = (),
        events: list[tuple[str, str]] | None = None,
    ) -> PackageSmelt:
        """Both endpoints succeed: `entries` and the maintainer `emails`."""
        return cls(
            maintained=reply(200, maintained(*entries)),
            maintainership=reply(200, maintainership(*emails)),
            events=events,
        )

    def pause(self, kind: Kind) -> Pause:
        """Install and return a `Pause` for `kind`."""
        self.pauses[kind] = Pause()
        return self.pauses[kind]

    async def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        kind: Kind
        if MAINTAINED_PATH in path:
            kind = "maintained"
        elif path.endswith(MAINTAINERSHIP_SUFFIX):
            kind = "maintainership"
        else:  # pragma: no cover - a wrong URL fails the test loudly
            raise AssertionError(f"unexpected SMELT request: {request.url}")
        self.requests.append((kind, request))
        if self.events is not None:
            self.events.append(("http", kind))
        if kind in self.pauses:
            await self.pauses[kind].hold()
        respond = self.responses.get(kind)
        if respond is None:
            return httpx.Response(500)
        response = respond(request)
        if inspect.isawaitable(response):
            response = await response
        return response

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server; tracked in `clients`."""
        client = httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
        self.clients.append(client)
        return client

    @property
    def kinds(self) -> list[Kind]:
        """The endpoint kind of every request, in order."""
        return [kind for kind, _ in self.requests]


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------


async def add(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    package_name: str,
    smelt: PackageSmelt,
    *,
    actor: User | None = None,
    scope: Scope = Scope.ALL,
    comment: PackageAddedComment = "CVE package resolution",
    active_ticket_only: bool = False,
    reresolution: bool = False,
) -> AddPackageResult:
    """Call the orchestrator as the user-facing package addition (`actor`,
    with effective `scope`, and a `NULL` comment) or a system workflow
    (`None`, with the canonical `comment`) would, through a client of
    `smelt` that is closed afterwards."""
    async with smelt.client() as client:
        return await add_package_to_ticket(
            db,
            ticket_id=ticket_id,
            package_name=package_name,
            acting_user_id=actor.id if actor else None,
            caller=(
                TicketCaller.authenticated(actor.id, scope)
                if actor
                else SYSTEM_INVOCATION
            ),
            audit_comment=None if actor else comment,
            active_ticket_only=active_ticket_only,
            allow_excluded_reresolution=reresolution,
            http_client=client,
        )
