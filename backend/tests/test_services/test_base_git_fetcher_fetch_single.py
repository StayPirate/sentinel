"""The default `BaseGitFetcher.fetch_single()` over real temporary bare clones
(backend/app/services/base_git_fetcher.py).

Owning specifications:

- docs/features/platform/git-fetcher-infrastructure.md (Default
  `fetch_single()` Implementation, steps 1-5, Exceptions, and the two caller
  purposes; `_construct_candidate_paths(item_id)`, ordering and the
  exception contract; Concurrency Rules 1-3; Inherited Utility Methods,
  `_repo_path()`).
- docs/features/platform/cve-fetcher-infrastructure.md (On-demand
  Single-Item Fetch: no `FetcherRun`, no metric; `CVENotInSource` Signal;
  `fetch_single` Signaling Convention: `CVENotInSource` only before any
  ingestion mutation).
- docs/features/platform/testing-strategy.md (Tier 1, the hermetic Git
  subprocess rules; CVE Fetcher Infrastructure: Typed result, Git
  boundaries).

Every repository is a real temporary one under `tmp_path`: a work-tree
upstream served through a `file://` URL and the fetcher's bare clone under
the redirected `GIT_CLONE_BASE_DIR`, created outside the code under test. No
Git process inherits a `GIT_*` variable or a user or system Git
configuration. The `git_operations` functions are wrapped by the recording
`GitCalls` spy; candidate read failures replace `show_file` for named paths
only, because real Git cannot make one `git show` of a valid clone fail
deterministically. The harness lives in `tests/support/git_fetchers.py`.

The unit tests pass a session that fails on any use: the scripted
`process_item()` steps never touch it, so a test reaching it would prove
database work the specification forbids. The integration tests run the real
ingestion in the rolled-back `db_session`. Test-only fetchers are defined per
test under `isolated_fetcher_registries`. All identifiers are fictional.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.models.cve import CVE
from app.models.fetcher_run import FetcherRun
from app.services import git_operations
from app.services.base_cve_fetcher import CVEFetchResult, CVENotInSource
from app.services.base_git_fetcher import (
    ALL_CANDIDATES_FAILED_MESSAGE,
    CANDIDATE_READ_FAILED_EVENT,
    CLONE_UNAVAILABLE_MESSAGE,
    ITEM_ID_MALFORMED_EVENT,
)
from app.services.cve_ingest import UpsertAction
from app.services.git_operations import GitFileError
from tests.support.git_fetchers import (
    GitCalls,
    GitFetcherProbe,
    GitWorkspace,
    counters,
    cve_file,
    cve_path,
    define_git_fetcher,
    ingest,
    install_git_workspace,
    raises,
    show_failing,
    show_missing,
    token,
)
from tests.support.git_repos import commit_files, git, init_bare, init_upstream

pytestmark = pytest.mark.usefixtures("isolated_fetcher_registries")

CVE_ID = "CVE-2099-0001"
PUBLISHED = f"cves/published/2099/{CVE_ID}.json"
REJECTED = f"cves/rejected/2099/{CVE_ID}.json"
D_BASE = "2024-01-05T00:00:00+00:00"
D_LATER = "2024-01-06T00:00:00+00:00"

SECRET = "upstream-secret-detail"
"""Text carried by injected exceptions; never logged."""

READ_ONLY_CALLS = {"is_clone_valid", "show_file"}
"""The only `git_operations` functions `fetch_single()` may call."""

_REAL_FETCH_ORIGIN = git_operations.fetch_origin
"""The unwrapped periodic-run fetch, captured before any spy is installed,
so the spy records only the calls of `fetch_single()`."""


class _UntouchedSession:
    """Stands in for the caller's session where no database work may
    occur: any use fails the test."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"session.{name} must not be used")


UNTOUCHED = cast(AsyncSession, _UntouchedSession())


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GitWorkspace:
    return install_git_workspace(tmp_path, monkeypatch)


@pytest.fixture
def git_calls(workspace: GitWorkspace, monkeypatch: pytest.MonkeyPatch) -> GitCalls:
    return GitCalls(monkeypatch)


def _published_then_rejected(item_id: str) -> list[str]:
    """Two ordered candidates of a `CVE-<year>-<n>` item, else `ValueError`
    (the kernel-style example of `_construct_candidate_paths`)."""
    parts = item_id.split("-")
    if len(parts) != 3 or parts[0] != "CVE":
        raise ValueError(f"Unrecognizable item_id format: {item_id}")
    return [
        f"cves/published/{parts[1]}/{item_id}.json",
        f"cves/rejected/{parts[1]}/{item_id}.json",
    ]


def _probe(workspace: GitWorkspace, **options: Any) -> GitFetcherProbe:
    options.setdefault("repo_url", workspace.upstream.url)
    options.setdefault("construct_candidate_paths", _published_then_rejected)
    options.setdefault("step", token())
    return define_git_fetcher(**options)


def _cloned(
    workspace: GitWorkspace, files: dict[str, bytes | None], **options: Any
) -> tuple[GitFetcherProbe, Path]:
    """A probe whose bare clone holds one upstream commit of `files`."""
    workspace.upstream.commit({"README": b"example\n", **files}, date=D_BASE)
    probe = _probe(workspace, **options)
    return probe, workspace.clone(probe)


def _clone_state(git_dir: Path) -> tuple[str, list[tuple[str, int, int]]]:
    """Every ref with its object, and every file of the clone (objects,
    refs, `HEAD`, configuration) with its size and modification time."""
    refs = git(
        None,
        f"--git-dir={git_dir}",
        "for-each-ref",
        "--format=%(refname) %(objectname)",
    ).stdout
    files = sorted(
        (
            path.relative_to(git_dir).as_posix(),
            path.stat().st_size,
            path.stat().st_mtime_ns,
        )
        for path in git_dir.rglob("*")
        if path.is_file()
    )
    return refs, files


def _object_names(git_dir: Path) -> list[str]:
    objects = git_dir / "objects"
    return sorted(path.relative_to(objects).as_posix() for path in objects.rglob("*"))


def _show_file_paths(git_calls: GitCalls, clone: Path) -> list[str]:
    """The `file_path` of every `show_file` call, asserting each read
    `HEAD` of `clone`."""
    paths = []
    for args, kwargs in git_calls.of("show_file"):
        assert kwargs == {}
        repo_path, ref, file_path = args
        assert (repo_path, ref) == (clone, "HEAD")
        paths.append(file_path)
    return paths


def _recording(construct: Any, received: list[str]) -> Any:
    def wrapper(item_id: str) -> list[str]:
        received.append(item_id)
        result: list[str] = construct(item_id)
        return result

    return wrapper


def _raising(error: BaseException) -> Any:
    def construct(item_id: str) -> list[str]:
        raise error

    return construct


# ---------------------------------------------------------------------------
# Step 2: clone availability
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCloneAvailability:
    @pytest.mark.parametrize(
        "state", ["absent", "plain-directory", "empty-bare", "non-bare"]
    )
    async def test_invalid_clone_raises_fixed_runtime_error_before_any_lookup(
        self, workspace: GitWorkspace, git_calls: GitCalls, state: str
    ) -> None:
        """Step 2 precedes step 3: even a malformed item is not looked up.
        Nothing is cloned, fetched, deleted, or repaired."""
        received: list[str] = []
        probe = _probe(
            workspace,
            construct_candidate_paths=_recording(_published_then_rejected, received),
        )
        path = workspace.clone_path(probe)
        marker: Path | None = None
        if state == "plain-directory":
            path.mkdir()
            marker = path / "stale-marker.txt"
            marker.write_bytes(b"stale\n")
        elif state == "empty-bare":
            init_bare(path)
            marker = path / "HEAD"
        elif state == "non-bare":
            init_upstream(path)
            commit_files(path, {"README": b"example\n"}, date=D_BASE)
            marker = path / ".git" / "HEAD"

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await probe.cls().fetch_single("malformed-item", UNTOUCHED)

        assert str(raised.value) == CLONE_UNAVAILABLE_MESSAGE
        assert raised.value.__cause__ is None
        assert git_calls.names() == ["is_clone_valid"]
        assert received == []
        assert probe.calls == []
        assert logs == []
        if marker is None:
            assert not path.exists()
        else:
            assert marker.exists()


# ---------------------------------------------------------------------------
# Step 3: malformed item identifiers
# ---------------------------------------------------------------------------


def _rejects_every_item(item_id: str) -> list[str]:
    raise ValueError(f"Unrecognizable item_id format: {item_id}")


@pytest.mark.unit
class TestMalformedItemId:
    @pytest.mark.parametrize(
        ("item_id", "construct", "canonical"),
        [
            pytest.param(
                "CVE-2099-0001", _rejects_every_item, True, id="canonical-cve-id"
            ),
            pytest.param(
                "EXAMPLE-RAW-ITEM-9f3c", _published_then_rejected, False, id="raw"
            ),
            pytest.param(
                "CVE-99-1\nforged-entry", _published_then_rejected, False, id="near-cve"
            ),
        ],
    )
    async def test_value_error_logs_bounded_error_then_signals_not_in_source(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        item_id: str,
        construct: Any,
        canonical: bool,
    ) -> None:
        """`cve_id` is logged only when it is a canonical CVE-ID; the raw
        value is never logged. No candidate is read and `process_item()` is
        never called."""
        probe, _ = _cloned(
            workspace, {PUBLISHED: b"published\n"}, construct_candidate_paths=construct
        )

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await probe.cls().fetch_single(item_id, UNTOUCHED)

        expected: dict[str, Any] = {
            "event": ITEM_ID_MALFORMED_EVENT,
            "log_level": "error",
            "fetcher_name": probe.name,
        }
        if canonical:
            expected["cve_id"] = item_id
        assert logs == [expected]
        if not canonical:
            assert item_id not in repr(logs)
        assert git_calls.names() == ["is_clone_valid"]
        assert probe.calls == []


# ---------------------------------------------------------------------------
# Step 4: ordered candidate lookup
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCandidateLookup:
    async def test_first_matching_candidate_wins(
        self, workspace: GitWorkspace, git_calls: GitCalls
    ) -> None:
        probe, clone = _cloned(
            workspace, {PUBLISHED: b"published\n", REJECTED: b"rejected\n"}
        )

        result = await probe.cls().fetch_single(CVE_ID, UNTOUCHED)

        assert probe.calls == [(PUBLISHED, b"published\n")]
        assert result is probe.results[0]
        assert _show_file_paths(git_calls, clone) == [PUBLISHED]

    async def test_absent_candidate_falls_through_to_the_next(
        self, workspace: GitWorkspace, git_calls: GitCalls
    ) -> None:
        probe, clone = _cloned(workspace, {REJECTED: b"rejected\n"})

        await probe.cls().fetch_single(CVE_ID, UNTOUCHED)

        assert probe.calls == [(REJECTED, b"rejected\n")]
        assert _show_file_paths(git_calls, clone) == [PUBLISHED, REJECTED]

    async def test_candidate_read_failure_warns_and_tries_the_next(
        self, workspace: GitWorkspace, git_calls: GitCalls
    ) -> None:
        """The WARNING carries `fetcher_name`, `cve_id`, and the exception
        class only; no metric is recorded (there is no run)."""
        probe, clone = _cloned(
            workspace, {PUBLISHED: b"published\n", REJECTED: b"rejected\n"}
        )
        git_calls.replacements["show_file"] = show_failing(
            GitFileError(f"fatal: {SECRET} {PUBLISHED}"), PUBLISHED
        )
        fetcher = probe.cls()

        with capture_logs() as logs:
            await fetcher.fetch_single(CVE_ID, UNTOUCHED)

        assert probe.calls == [(REJECTED, b"rejected\n")]
        assert _show_file_paths(git_calls, clone) == [PUBLISHED, REJECTED]
        assert logs == [
            {
                "event": CANDIDATE_READ_FAILED_EVENT,
                "log_level": "warning",
                "fetcher_name": probe.name,
                "cve_id": CVE_ID,
                "cause": "GitFileError",
            }
        ]
        assert SECRET not in repr(logs)
        assert counters(fetcher) == (0, 0, 0, 0)

    @pytest.mark.parametrize(
        ("failing", "missing"),
        [
            pytest.param((PUBLISHED, REJECTED), (), id="every-candidate-fails"),
            pytest.param((PUBLISHED,), (REJECTED,), id="fails-then-absent"),
            pytest.param((REJECTED,), (PUBLISHED,), id="absent-then-fails"),
        ],
    )
    async def test_read_failure_without_content_raises_chained_runtime_error(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        failing: tuple[str, ...],
        missing: tuple[str, ...],
    ) -> None:
        """Step 5a: at least one `GitFileError` and no content raises the
        fixed `RuntimeError`, chained from the last `GitFileError`; it
        never calls `record_failed()`."""
        probe, clone = _cloned(
            workspace, {PUBLISHED: b"published\n", REJECTED: b"rejected\n"}
        )
        errors = {path: GitFileError(f"{SECRET} {path}") for path in failing}

        async def replacement(
            real: Any, repo_path: Path, ref: str, file_path: str
        ) -> bytes | None:
            if file_path in errors:
                raise errors[file_path]
            if file_path in missing:
                return None
            result: bytes | None = await real(repo_path, ref, file_path)
            return result

        git_calls.replacements["show_file"] = replacement
        fetcher = probe.cls()

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await fetcher.fetch_single(CVE_ID, UNTOUCHED)

        assert str(raised.value) == ALL_CANDIDATES_FAILED_MESSAGE
        assert raised.value.__cause__ is errors[failing[-1]]
        assert probe.calls == []
        assert _show_file_paths(git_calls, clone) == [PUBLISHED, REJECTED]
        assert [entry["event"] for entry in logs] == [
            CANDIDATE_READ_FAILED_EVENT
        ] * len(failing)
        assert SECRET not in repr(logs)
        assert counters(fetcher) == (0, 0, 0, 0)

    @pytest.mark.parametrize(
        "construct",
        [
            pytest.param(_published_then_rejected, id="no-candidate-exists"),
            pytest.param(lambda item_id: [], id="no-candidate-path"),
        ],
    )
    async def test_no_candidate_found_signals_not_in_source_before_any_mutation(
        self, workspace: GitWorkspace, git_calls: GitCalls, construct: Any
    ) -> None:
        """Step 5b: `CVENotInSource` is raised before `process_item()` and
        before any use of the session."""
        probe, clone = _cloned(
            workspace,
            {"cves/published/2099/CVE-2099-0002.json": b"other\n"},
            construct_candidate_paths=construct,
        )

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await probe.cls().fetch_single(CVE_ID, UNTOUCHED)

        assert probe.calls == []
        assert logs == []
        assert _show_file_paths(git_calls, clone) == construct(CVE_ID)


# ---------------------------------------------------------------------------
# Hook exceptions and the returned token
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestHookOutcomes:
    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(TypeError(SECRET), id="type-error"),
            pytest.param(AttributeError(SECRET), id="attribute-error"),
            pytest.param(KeyError(SECRET), id="key-error"),
            pytest.param(NotImplementedError(SECRET), id="not-implemented"),
        ],
    )
    async def test_other_candidate_hook_exception_propagates_unchanged(
        self, workspace: GitWorkspace, git_calls: GitCalls, error: Exception
    ) -> None:
        probe, _ = _cloned(
            workspace,
            {PUBLISHED: b"published\n"},
            construct_candidate_paths=_raising(error),
        )

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await probe.cls().fetch_single(CVE_ID, UNTOUCHED)

        assert raised.value is error
        assert logs == []
        assert git_calls.names() == ["is_clone_valid"]

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(ValueError(SECRET), id="value-error-is-not-malformed-id"),
            pytest.param(GitFileError(SECRET), id="git-file-error-is-not-a-read"),
            pytest.param(CVENotInSource(), id="not-in-source"),
            pytest.param(RuntimeError(SECRET), id="runtime-error"),
        ],
    )
    async def test_process_item_exception_propagates_unchanged(
        self, workspace: GitWorkspace, git_calls: GitCalls, error: Exception
    ) -> None:
        """Only `_construct_candidate_paths()`'s `ValueError` and
        `show_file()`'s `GitFileError` are handled; the same types from
        `process_item()` propagate, and no further candidate is tried."""
        probe, clone = _cloned(
            workspace,
            {PUBLISHED: b"published\n", REJECTED: b"rejected\n"},
            step=raises(error),
        )
        fetcher = probe.cls()

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await fetcher.fetch_single(CVE_ID, UNTOUCHED)

        assert raised.value is error
        assert probe.paths == [PUBLISHED]
        assert _show_file_paths(git_calls, clone) == [PUBLISHED]
        assert logs == []
        assert counters(fetcher) == (0, 0, 0, 0)

    @pytest.mark.parametrize("action", list(UpsertAction))
    async def test_returns_the_process_item_token_unconsumed(
        self, workspace: GitWorkspace, git_calls: GitCalls, action: UpsertAction
    ) -> None:
        """The caller owns flush and finalization: the token is returned
        as is, with no finalization, metric, or session use."""
        probe, _ = _cloned(workspace, {PUBLISHED: b"published\n"}, step=token(action))
        fetcher = probe.cls()

        result = await fetcher.fetch_single(CVE_ID, UNTOUCHED)

        assert isinstance(result, CVEFetchResult)
        assert result is probe.results[0]
        assert result.action is action
        assert result._consumed is False
        assert "commit_and_dispatch" not in probe.events
        assert counters(fetcher) == (0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Git boundaries and Concurrency Rules 1-3
# ---------------------------------------------------------------------------


def _not_found(probe: GitFetcherProbe, git_calls: GitCalls) -> None:
    git_calls.replacements["show_file"] = show_missing(PUBLISHED, REJECTED)


def _all_fail(probe: GitFetcherProbe, git_calls: GitCalls) -> None:
    git_calls.replacements["show_file"] = show_failing(
        GitFileError(SECRET), PUBLISHED, REJECTED
    )


def _process_fails(probe: GitFetcherProbe, git_calls: GitCalls) -> None:
    probe.step = raises(RuntimeError(SECRET))


@pytest.mark.unit
class TestReadOnlyClone:
    @pytest.mark.parametrize(
        ("item_id", "arrange", "expected"),
        [
            pytest.param(CVE_ID, None, None, id="found"),
            pytest.param(CVE_ID, _not_found, CVENotInSource, id="not-found"),
            pytest.param(CVE_ID, _all_fail, RuntimeError, id="all-candidates-fail"),
            pytest.param(CVE_ID, _process_fails, RuntimeError, id="process-fails"),
            pytest.param("malformed-item", None, CVENotInSource, id="malformed"),
        ],
    )
    async def test_lookup_reads_only_and_mutates_no_ref_or_object(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        item_id: str,
        arrange: Any,
        expected: type[Exception] | None,
    ) -> None:
        """Rules 1-2: no clone, fetch, or deletion; every read is a
        `show_file` of `HEAD`; refs, objects, and every other file of the
        clone are unchanged; no metric is recorded."""
        probe, clone = _cloned(
            workspace, {PUBLISHED: b"published\n", REJECTED: b"rejected\n"}
        )
        if arrange is not None:
            arrange(probe, git_calls)
        before = _clone_state(clone)
        fetcher = probe.cls()

        if expected is None:
            await fetcher.fetch_single(item_id, UNTOUCHED)
        else:
            with pytest.raises(expected):
                await fetcher.fetch_single(item_id, UNTOUCHED)

        assert set(git_calls.names()) <= READ_ONLY_CALLS
        _show_file_paths(git_calls, clone)
        assert _clone_state(clone) == before
        assert counters(fetcher) == (0, 0, 0, 0)

    async def test_reads_succeed_while_a_periodic_fetch_updates_the_clone(
        self, workspace: GitWorkspace, git_calls: GitCalls
    ) -> None:
        """Rules 1-3: each lookup runs concurrently with the periodic run's
        real `fetch_origin` of a new upstream commit. The lookup succeeds,
        sees the content of the old or the new `HEAD` (a stale read is
        acceptable), and performs only reads; the fetch advances `HEAD`."""
        probe, clone = _cloned(workspace, {PUBLISHED: b"revision 0\n"})
        fetcher = probe.cls()
        objects_before = _object_names(clone)

        for revision in range(1, 4):
            old, new = f"revision {revision - 1}\n", f"revision {revision}\n"
            head = workspace.upstream.commit(
                {PUBLISHED: new.encode()}, date=D_LATER, message=f"revision {revision}"
            )
            probe.calls.clear()

            _, result = await asyncio.gather(
                _REAL_FETCH_ORIGIN(clone), fetcher.fetch_single(CVE_ID, UNTOUCHED)
            )

            assert isinstance(result, CVEFetchResult)
            assert [path for path, _ in probe.calls] == [PUBLISHED]
            assert probe.calls[0][1].decode() in {old, new}
            assert (
                git(None, f"--git-dir={clone}", "rev-parse", "HEAD").stdout.strip()
                == head
            )

        assert set(git_calls.names()) <= READ_ONLY_CALLS
        assert git_calls.names().count("is_clone_valid") == 3
        # Only the periodic fetch wrote: it added objects and removed none.
        assert set(objects_before) <= set(_object_names(clone))

    async def test_item_published_after_the_last_fetch_is_a_stale_not_in_source(
        self, workspace: GitWorkspace, git_calls: GitCalls
    ) -> None:
        """Rule 3: a lookup before the periodic fetch does not see a newly
        published item (`CVENotInSource`, not an error); it never fetches
        on its own. After the periodic fetch the item is found."""
        probe, clone = _cloned(workspace, {})
        workspace.upstream.commit({PUBLISHED: b"published\n"}, date=D_LATER)
        fetcher = probe.cls()

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(CVE_ID, UNTOUCHED)
        assert set(git_calls.names()) <= READ_ONLY_CALLS

        await _REAL_FETCH_ORIGIN(clone)
        await fetcher.fetch_single(CVE_ID, UNTOUCHED)

        assert probe.calls == [(PUBLISHED, b"published\n")]


# ---------------------------------------------------------------------------
# Real ingestion: no commit, no metric, no FetcherRun
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRealIngestion:
    async def test_ingests_in_the_caller_session_without_commit_or_fetcher_run(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        db_session: AsyncSession,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """The real `upsert_cve()` / `upsert_references()` ingestion runs in
        the caller's session; `fetch_single()` neither commits nor
        finalizes, records no metric, and creates no `FetcherRun`. The
        per-test rollback discards the ingestion."""
        cve_id = "CVE-2099-7300001"
        path = cve_path(cve_id)
        probe, _ = _cloned(
            workspace,
            {path: cve_file("Example lookup title")},
            construct_candidate_paths=None,
            step=ingest(),
        )
        fetcher = probe.cls()

        result = await fetcher.fetch_single(cve_id, db_session)

        assert result.action is UpsertAction.CREATED
        assert result._consumed is False
        assert probe.paths == [path]
        ingested = await db_session.scalar(select(CVE).where(CVE.cve_id == cve_id))
        assert ingested is not None
        assert ingested.title == "Example lookup title"
        async with real_session_factory() as observer:
            committed = await observer.scalar(
                select(CVE.id).where(CVE.cve_id == cve_id)
            )
            runs = await observer.scalar(
                select(func.count())
                .select_from(FetcherRun)
                .where(FetcherRun.fetcher_name == probe.name)
            )
        assert committed is None
        assert runs == 0
        assert "commit_and_dispatch" not in probe.events
        assert counters(fetcher) == (0, 0, 0, 0)
        assert set(git_calls.names()) <= READ_ONLY_CALLS
