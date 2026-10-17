"""Tests for the published-release guard (`scripts/check-release-unpublished.sh`).

A published GitHub Release is final: the guard must fail before any image
push or attestation when one exists for the build's tag, let draft and not
yet created releases pass, and fail closed on any lookup error
(`docs/deployment.md`, Release Publication and Immutability; issue #457).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "check-release-unpublished.sh"
)

# Prints the canned API response and logs every invocation.
GH_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "${GH_STUB_LOG}"
cat "${GH_STUB_RESPONSE}"
exit "${GH_STUB_EXIT:-0}"
"""


def _release(tag: str, *, draft: bool) -> dict[str, Any]:
    return {
        "tag_name": tag,
        "draft": draft,
        "html_url": f"https://github.com/example/sentinel/releases/tag/{tag}",
    }


def _pages(*pages: list[dict[str, Any]]) -> str:
    """Render `gh api --paginate` output: one JSON array per page."""
    return "".join(json.dumps(page) for page in pages)


def _run_guard(
    tmp_path: Path,
    *,
    response: str = "[]",
    tag: str = "v1.2.3",
    gh_exit: int = 0,
    env_overrides: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub_path = bin_dir / "gh"
    stub_path.write_text(GH_STUB, encoding="utf-8")
    stub_path.chmod(stub_path.stat().st_mode | stat.S_IEXEC)
    response_path = tmp_path / "response.json"
    response_path.write_text(response, encoding="utf-8")
    log_path = tmp_path / "gh.log"
    log_path.write_text("", encoding="utf-8")

    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_STUB_LOG": str(log_path),
        "GH_STUB_RESPONSE": str(response_path),
        "GH_STUB_EXIT": str(gh_exit),
        "RELEASE_TAG": tag,
        "GITHUB_REPOSITORY": "example/sentinel",
    }
    env |= env_overrides or {}
    result = subprocess.run(
        [str(SCRIPT_PATH)], env=env, capture_output=True, text=True, check=False
    )
    return result, log_path.read_text(encoding="utf-8").splitlines()


@pytest.mark.unit
def test_guard_lists_every_release_page_of_the_repository(tmp_path: Path) -> None:
    result, gh_calls = _run_guard(tmp_path)

    assert result.returncode == 0
    assert gh_calls == ["api --paginate repos/example/sentinel/releases?per_page=100"]


@pytest.mark.unit
def test_guard_passes_when_no_release_exists(tmp_path: Path) -> None:
    result, _ = _run_guard(tmp_path, response=_pages([]))

    assert result.returncode == 0
    assert "v1.2.3 is not published" in result.stdout


@pytest.mark.unit
def test_guard_passes_for_a_draft_release(tmp_path: Path) -> None:
    result, _ = _run_guard(tmp_path, response=_pages([_release("v1.2.3", draft=True)]))

    assert result.returncode == 0


@pytest.mark.unit
def test_guard_ignores_published_releases_of_other_tags(tmp_path: Path) -> None:
    response = _pages(
        [_release("v1.2.2", draft=False), _release("v1.2.30", draft=False)]
    )

    result, _ = _run_guard(tmp_path, response=response)

    assert result.returncode == 0


@pytest.mark.unit
def test_guard_rejects_a_published_release(tmp_path: Path) -> None:
    result, _ = _run_guard(tmp_path, response=_pages([_release("v1.2.3", draft=False)]))

    assert result.returncode != 0
    assert "Release v1.2.3 is already published" in result.stderr
    assert "https://github.com/example/sentinel/releases/tag/v1.2.3" in result.stderr
    assert result.stdout == ""


@pytest.mark.unit
def test_guard_finds_a_published_release_on_a_later_page(tmp_path: Path) -> None:
    response = _pages(
        [_release(f"v0.{minor}.0", draft=False) for minor in range(100)],
        [_release("v1.2.3", draft=False)],
    )

    result, _ = _run_guard(tmp_path, response=response)

    assert result.returncode != 0
    assert "already published" in result.stderr


@pytest.mark.unit
def test_guard_fails_closed_when_the_listing_fails(tmp_path: Path) -> None:
    result, _ = _run_guard(tmp_path, response="", gh_exit=1)

    assert result.returncode != 0
    assert "not published" not in result.stdout


@pytest.mark.unit
def test_guard_fails_closed_on_a_malformed_listing(tmp_path: Path) -> None:
    result, _ = _run_guard(tmp_path, response="<html>unavailable</html>")

    assert result.returncode != 0
    assert "not published" not in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize("tag", ["1.2.3", "v1.2", "v1.2.3-rc.1", 'v1.2.3";id'])
def test_guard_rejects_a_non_release_tag_without_lookup(
    tmp_path: Path, tag: str
) -> None:
    result, gh_calls = _run_guard(tmp_path, tag=tag)

    assert result.returncode != 0
    assert "Release tag must have the form" in result.stderr
    assert gh_calls == []


@pytest.mark.unit
@pytest.mark.parametrize("variable", ["RELEASE_TAG", "GITHUB_REPOSITORY"])
def test_guard_requires_its_inputs(tmp_path: Path, variable: str) -> None:
    result, gh_calls = _run_guard(tmp_path, env_overrides={variable: ""})

    assert result.returncode != 0
    assert variable in result.stderr
    assert gh_calls == []
