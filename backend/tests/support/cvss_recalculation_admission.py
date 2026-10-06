"""Shared spy for the manual CVSS recalculation admission tests
(`admit_cvss_recalculation()`,
backend/app/services/cvss_recalculation_admission.py).

Consumers:

- `tests/test_services/test_cvss_recalculation_admission.py` (ordering,
  rejections, failures, publication classification, connection ownership,
  and event privacy);
- `tests/test_services/test_cvss_recalculation_admission_races.py`
  (concurrent admissions and the interplay with the real runner);
- `tests/test_api/test_settings_impact_preview_active_run.py` (the preview
  while a recalculation is admitted, queued, or running).

The spy is installed after the recalculation harness
(tests/support/cvss_recalculation.py), so its recorder replaces the
harness's convergence publisher; consumers whose runner publishes Ticket
convergence must not combine both. It wraps the coordination steps the
admission calls through its own module, the settings read and the broker
call through theirs, and delegates to the real operations. `Gate` and
`finish()` hold an admission or a runner at a named boundary and bound the
wait for it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from app.services import cvss_recalculation_admission as admission
from app.services import cvss_recalculation_coordination as coordination
from app.services import settings as settings_service
from app.services import task_publication
from app.services.cvss_recalculation_coordination import (
    FenceAcquireOutcome,
    FenceReleaseOutcome,
    LeaseDeleteOutcome,
)
from app.services.task_publication import JSONValue
from tests.support.cvss_recalculation import connection_pid

Hook = Callable[[AsyncConnection], Awaitable[None]]
"""An awaited hook receiving the admission's fenced connection."""

WAIT = 5.0
"""Bound of every wait on a barrier or a background workflow."""


class Gate:
    """A one-shot `asyncio.Event` barrier that pauses a workflow at a
    chosen boundary: the first `pause()` signals `reached` and waits for
    `release()`; later calls pass through."""

    def __init__(self) -> None:
        self.reached = asyncio.Event()
        self.released = asyncio.Event()

    async def pause(self, *_args: object) -> None:
        if self.reached.is_set():
            return
        self.reached.set()
        await self.released.wait()

    async def wait_reached(self) -> None:
        await asyncio.wait_for(self.reached.wait(), WAIT)

    def release(self) -> None:
        self.released.set()


async def finish(task: asyncio.Task[Any], *gates: Gate) -> None:
    """Teardown guard: release `gates` and wait, bounded, for a background
    workflow a failed assertion left running, so the harness never tears
    down under it; its outcome has already been asserted or is moot."""
    for gate in gates:
        gate.release()
    if not task.done():
        with suppress(BaseException):
            await asyncio.wait_for(asyncio.shield(task), WAIT)


@dataclass(frozen=True)
class Publication:
    """One recorded broker publication call."""

    task_name: str
    kwargs: dict[str, JSONValue]
    task_id: str | None
    queue: str | None


@contextmanager
def failing_execute(target: AsyncConnection, error: BaseException) -> Iterator[None]:
    """Make `target.execute()` raise `error` inside a real helper, so the
    helper's own invalidate-and-propagate path runs; every other connection
    is unaffected."""
    original = AsyncConnection.execute

    async def _execute(self: AsyncConnection, *args: Any, **kwargs: Any) -> Any:
        if self is target:
            raise error
        return await original(self, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(AsyncConnection, "execute", _execute)
        yield


class AdmissionSpy:
    """Wraps every coordination step the admission calls through its
    module (and the settings read and the publisher through theirs),
    recording the step sequence and delegating to the real operation.

    Injection points: `fence_error`, `setting_error`, and `release_error`
    make the real helper's statement fail; `lease_error` replaces the
    acquire (or follows the real write when `lease_error_after_write`);
    `delete_error` replaces the compare-and-delete; `before_setting` runs
    before the real setting read, `after_lease` after the real acquire, and
    `before_release` before the real release; `on_publish` runs after a
    publication is recorded, and `publish_error` is raised by the recorder
    after recording; `close_error` is raised by the lease client's
    `aclose()` after the real close.

    `clients` counts lease-client creations and `closes` the `aclose()`
    calls on those clients; neither is part of `sequence`.

    The settings read is wrapped module-wide, so a runner's own setting
    read is recorded (and hooked) as well."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.sequence: list[str] = []
        self.task_ids: list[str] = []
        self.fence_pids: list[int] = []
        self.release_raised: list[BaseException] = []
        self.published: list[Publication] = []
        self.clients = 0
        self.closes = 0
        self.close_error: BaseException | None = None
        self.fence_error: BaseException | None = None
        self.before_setting: Callable[[], Awaitable[None]] | None = None
        self.setting_error: BaseException | None = None
        self.lease_error: BaseException | None = None
        self.lease_error_after_write = False
        self.after_lease: Callable[[], Awaitable[None]] | None = None
        self.before_release: Hook | None = None
        self.release_error: BaseException | None = None
        self.delete_error: BaseException | None = None
        self.on_publish: Callable[[Publication], Awaitable[None]] | None = None
        self.publish_error: BaseException | None = None
        self._connection: AsyncConnection | None = None
        self._install(monkeypatch)

    def _install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fence = coordination.try_acquire_execution_fence
        setting = settings_service.get_default_cvss_version
        client_factory = coordination.new_cvss_recalculation_redis_client
        lease = coordination.acquire_lease
        release = coordination.release_execution_fence
        delete = coordination.compare_and_delete_lease

        async def _fence(connection: AsyncConnection) -> FenceAcquireOutcome:
            self.sequence.append("fence")
            self._connection = connection
            self.fence_pids.append(connection_pid(connection))
            if self.fence_error is not None:
                with failing_execute(connection, self.fence_error):
                    return await fence(connection)
            return await fence(connection)

        async def _setting(session: AsyncSession) -> str:
            self.sequence.append("setting")
            if self.before_setting is not None:
                await self.before_setting()
            if self.setting_error is not None:
                raise self.setting_error
            return await setting(session)

        def _client() -> redis_asyncio.Redis:
            self.clients += 1
            client = client_factory()
            close = client.aclose

            async def _aclose(*args: Any, **kwargs: Any) -> None:
                self.closes += 1
                await close(*args, **kwargs)
                if self.close_error is not None:
                    raise self.close_error

            client.aclose = _aclose  # type: ignore[method-assign]
            return client

        async def _lease(
            client: redis_asyncio.Redis, *, task_id: str, target_version: str
        ) -> Any:
            self.sequence.append("lease")
            self.task_ids.append(task_id)
            if self.lease_error is not None and not self.lease_error_after_write:
                raise self.lease_error
            outcome = await lease(
                client, task_id=task_id, target_version=target_version
            )
            if self.lease_error is not None:
                raise self.lease_error
            if self.after_lease is not None:
                await self.after_lease()
            return outcome

        async def _release(connection: AsyncConnection) -> FenceReleaseOutcome:
            self.sequence.append("release")
            try:
                if self.before_release is not None:
                    await self.before_release(connection)
                if self.release_error is not None:
                    with failing_execute(connection, self.release_error):
                        return await release(connection)
                return await release(connection)
            except BaseException as exc:
                self.release_raised.append(exc)
                raise

        async def _delete(
            client: redis_asyncio.Redis, *, task_id: str, target_version: str
        ) -> LeaseDeleteOutcome:
            self.sequence.append("delete")
            if self.delete_error is not None:
                raise self.delete_error
            return await delete(client, task_id=task_id, target_version=target_version)

        async def _publish(
            task_name: str,
            *,
            kwargs: Mapping[str, JSONValue],
            task_id: str | None = None,
            queue: str | None = None,
        ) -> None:
            self.sequence.append("publish")
            call = Publication(task_name, dict(kwargs), task_id, queue)
            self.published.append(call)
            if self.on_publish is not None:
                await self.on_publish(call)
            if self.publish_error is not None:
                raise self.publish_error

        monkeypatch.setattr(admission, "try_acquire_execution_fence", _fence)
        monkeypatch.setattr(settings_service, "get_default_cvss_version", _setting)
        monkeypatch.setattr(admission, "new_cvss_recalculation_redis_client", _client)
        monkeypatch.setattr(admission, "acquire_lease", _lease)
        monkeypatch.setattr(admission, "release_execution_fence", _release)
        monkeypatch.setattr(admission, "compare_and_delete_lease", _delete)
        monkeypatch.setattr(task_publication, "publish_task", _publish)

    @property
    def task_id(self) -> str:
        """The single task ID this test's admission allocated."""
        assert len(self.task_ids) == 1
        return self.task_ids[0]

    @property
    def connection(self) -> AsyncConnection:
        """The admission's fenced connection."""
        assert self._connection is not None
        return self._connection
