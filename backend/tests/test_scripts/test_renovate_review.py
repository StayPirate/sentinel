"""Deterministic tests for the guarded Renovate review utility."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "scripts" / "renovate_review.py"
FIXTURE_DIR = REPO_ROOT / "backend" / "tests" / "fixtures" / "github_renovate_review"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("renovate_review", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


renovate_review = _load_script()


def _fixture(name: str) -> Any:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _identity(login: str, account_id: int, kind: str) -> dict[str, Any]:
    return {"login": login, "id": account_id, "type": kind}


def _snapshot() -> dict[str, Any]:
    check_app = {"id": 15368, "slug": "github-actions", "name": "GitHub Actions"}
    return {
        "schema_version": 1,
        "repository": {
            "full_name": "example-org/example-repo",
            "default_branch": "main",
            "default_sha": "base111",
        },
        "observed_at": "2026-09-14T18:00:00Z",
        "pull_request": {
            "number": 42,
            "title": "chore(deps): update fictional dependency",
            "url": "https://github.example/example-org/example-repo/pull/42",
            "state": "open",
            "draft": False,
            "merged": False,
            "mergeable_state": "clean",
            "base_ref": "main",
            "base_sha": "base111",
            "head_ref": "renovate/example-2.x",
            "head_sha": "head222",
            "author": _identity("renovate[bot]", 29139614, "Bot"),
            "merge_commit_sha": None,
        },
        "body_sha256": "body-hash",
        "diff_sha256": "diff-hash",
        "commits": [
            {
                "sha": "head222",
                "message": "chore(deps): update fictional dependency",
                "author": _identity("renovate[bot]", 29139614, "Bot"),
                "committer": _identity("web-flow", 19864447, "User"),
            }
        ],
        "files": [
            {
                "filename": "example.lock",
                "sha": "blob333",
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "changes": 2,
            }
        ],
        "issue_comments": [],
        "reviews": [],
        "review_comments": [],
        "review_threads": [],
        "closing_issues": [],
        "checks": [
            {
                "id": 3001,
                "name": "CI",
                "head_sha": "head222",
                "status": "completed",
                "conclusion": "success",
                "app": check_app,
            }
        ],
        "statuses": [],
        "workflows": [
            {
                "id": 4001,
                "workflow_id": 5001,
                "path": ".github/workflows/ci.yml",
                "name": "CI",
                "head_sha": "head222",
                "status": "completed",
                "conclusion": "success",
            }
        ],
        "protection": {
            "required_status_checks": {
                "strict": True,
                "contexts": ["CI"],
                "checks": [{"context": "CI", "app_id": 15368}],
            },
            "required_conversation_resolution": True,
            "effective_rules": [{"type": "deletion", "ruleset_id": 6001}],
            "rulesets": [
                {
                    "id": 6001,
                    "name": "protect main",
                    "target": "branch",
                    "enforcement": "active",
                    "conditions": {
                        "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
                    },
                    "rules": [{"type": "deletion"}],
                    "bypass_actors": [],
                    "bypass_actors_visible": True,
                }
            ],
        },
        "ancestry": {
            "base": "base111",
            "head": "head222",
            "status": "ahead",
            "ahead_by": 1,
            "behind_by": 0,
        },
        "open_prs": [
            {
                "number": 42,
                "base_ref": "main",
                "base_sha": "base111",
                "head_ref": "renovate/example-2.x",
                "head_sha": "head222",
                "author": _identity("renovate[bot]", 29139614, "Bot"),
            }
        ],
    }


def _evidence() -> dict[str, Any]:
    sources = {}
    for category in renovate_review.SOURCE_CATEGORIES:
        sources[category] = [
            {
                "source": "primary-agent",
                "reference": f"https://upstream.example/{category}",
                "finding": f"Verified fictional {category}.",
            }
        ]
    return {
        "schema_version": 1,
        "repository": "example-org/example-repo",
        "pull_request": 42,
        "base_sha": "base111",
        "head_sha": "head222",
        "primary_verdict": "Clean",
        "sources": sources,
        "reviewers": [
            {
                "name": "security-reviewer",
                "required": True,
                "reason": "Dependency trust boundary.",
                "verdict": "Clean",
                "reviewed_head": "head222",
            }
        ],
        "expected_checks": [
            {
                "name": "CI",
                "app": {
                    "id": 15368,
                    "slug": "github-actions",
                    "name": "GitHub Actions",
                },
            }
        ],
        "expected_statuses": {
            "items": [],
            "empty_reason": "No commit-status producers apply.",
        },
        "expected_workflows": {
            "items": [
                {"path": ".github/workflows/ci.yml", "workflow_id": 5001, "name": "CI"}
            ],
            "empty_reason": None,
        },
    }


def _evidence_for_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    evidence = _evidence()
    evidence["expected_checks"] = [
        {"name": check["name"], "app": copy.deepcopy(check["app"])}
        for check in snapshot["checks"]
    ]
    evidence["expected_workflows"]["items"] = [
        {
            "path": workflow["path"],
            "workflow_id": workflow["workflow_id"],
            "name": workflow["name"],
        }
        for workflow in snapshot["workflows"]
    ]
    return evidence


@pytest.mark.unit
def test_contract_fixtures_preserve_consumed_shapes_and_pagination() -> None:
    rest = _fixture("rest_responses.json")
    graphql = _fixture("graphql_responses.json")
    metadata = _fixture("source_metadata.json")

    assert metadata["source"].endswith("PR #522")
    assert "empty commit statuses" in metadata["observed_live"]
    assert "non-empty commit statuses" in metadata["documentation_only_or_synthetic"]
    assert rest["pull_request"]["merge_commit_sha"] is None
    assert rest["pull_request"]["user"]["type"] == "Bot"
    assert rest["commits_pages"][0][0]["commit"]["committer"]["date"].endswith("Z")
    assert len(rest["check_runs_pages"][0]["check_runs"]) == 7
    assert {item["name"] for item in rest["check_runs_pages"][0]["check_runs"]} == set(
        rest["branch_protection"]["required_status_checks"]["contexts"]
    )
    assert rest["statuses_pages"] == [[]]
    assert rest["workflow_runs_pages"][0]["workflow_runs"][0]["path"].endswith(".yml")
    assert rest["branch_protection"]["required_status_checks"]["checks"][0]["app_id"]
    assert rest["ruleset_detail"]["conditions"]["ref_name"]["include"]
    assert "bypass_actors" not in rest["ruleset_detail"]
    assert rest["compare"]["merge_base_commit"]["sha"] == "base111"
    assert rest["open_prs_pages"][0][0]["head"]["sha"] == "head222"
    thread = graphql["review_threads_pages"][0]["data"]["repository"]["pullRequest"][
        "reviewThreads"
    ]
    assert thread == {
        "nodes": [],
        "pageInfo": {"hasNextPage": False, "endCursor": None},
    }


@pytest.mark.unit
def test_collect_snapshot_consumes_sanitized_github_contract() -> None:
    rest = _fixture("rest_responses.json")
    graphql = _fixture("graphql_responses.json")
    review_thread_pages = iter(graphql["review_threads_pages"])
    closing_issue_pages = iter(graphql["closing_issues_pages"])
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> str:
        calls.append(argv)
        endpoint = argv[-1]
        if "graphql" in argv:
            query = next(value for value in argv if value.startswith("query="))
            pages = (
                closing_issue_pages
                if "closingIssuesReferences" in query
                else review_thread_pages
            )
            return json.dumps(next(pages))
        if any("application/vnd.github.diff" in value for value in argv):
            return (FIXTURE_DIR / "pr.diff").read_text(encoding="utf-8")
        if endpoint == "repos/example-org/example-repo":
            return json.dumps(rest["repository"])
        if endpoint.endswith("pulls/42"):
            return json.dumps(rest["pull_request"])
        if "/pulls/42/commits?" in endpoint:
            return json.dumps(rest["commits_pages"][0])
        if "/pulls/42/files?" in endpoint:
            return json.dumps(rest["files_pages"][0])
        if "/issues/42/comments?" in endpoint:
            return json.dumps(rest["issue_comments_pages"][0])
        if "/pulls/42/reviews?" in endpoint:
            return json.dumps(rest["reviews_pages"][0])
        if "/pulls/42/comments?" in endpoint:
            return json.dumps(rest["review_comments_pages"][0])
        if "/check-runs?" in endpoint:
            return json.dumps(rest["check_runs_pages"][0])
        if "/statuses?" in endpoint:
            return json.dumps(rest["statuses_pages"][0])
        if "/actions/runs?" in endpoint:
            return json.dumps(rest["workflow_runs_pages"][0])
        if endpoint.endswith("branches/main/protection"):
            return json.dumps(rest["branch_protection"])
        if "/rules/branches/main?" in endpoint:
            return json.dumps(rest["effective_rules"])
        if endpoint.endswith("branches/main"):
            return json.dumps(rest["default_branch"])
        if "/rulesets?" in endpoint:
            return json.dumps(rest["rulesets_pages"][0])
        if "/rulesets/6001?" in endpoint:
            return json.dumps(rest["ruleset_detail"])
        if "/compare/" in endpoint:
            return json.dumps(rest["compare"])
        if "/pulls?" in endpoint:
            return json.dumps(rest["open_prs_pages"][0])
        raise AssertionError(f"unexpected fake GitHub command: {argv}")

    snapshot = renovate_review.collect_snapshot(
        "example-org/example-repo",
        42,
        runner=runner,
        now=lambda: renovate_review.datetime(
            2026, 9, 14, 18, 0, tzinfo=renovate_review.UTC
        ),
    )

    body = rest["pull_request"]["body"]
    diff = (FIXTURE_DIR / "pr.diff").read_text(encoding="utf-8")
    assert snapshot["body_sha256"] == hashlib.sha256(body.encode()).hexdigest()
    assert snapshot["diff_sha256"] == hashlib.sha256(diff.encode()).hexdigest()
    assert snapshot["pull_request"]["title"].startswith("chore(deps)")
    assert snapshot["pull_request"]["url"].endswith("/pull/42")
    assert snapshot["commits"][0]["author"]["login"] == "renovate[bot]"
    assert len(snapshot["checks"]) == 7
    assert snapshot["checks"][0]["app"] == {
        "id": 15368,
        "slug": "github-actions",
        "name": "GitHub Actions",
    }
    assert snapshot["statuses"] == []
    assert snapshot["workflows"][0]["workflow_id"] == 5001
    assert snapshot["review_threads"] == []
    assert snapshot["protection"]["rulesets"][0]["id"] == 6001
    assert snapshot["protection"]["rulesets"][0]["bypass_actors"] == []
    assert snapshot["protection"]["rulesets"][0]["bypass_actors_visible"] is False
    assert snapshot["open_prs"][0]["number"] == 42
    assert any("filter=latest" in value for call in calls for value in call)
    renovate_review.evaluate_snapshot(snapshot, _evidence_for_snapshot(snapshot))


@pytest.mark.unit
def test_rest_and_graphql_pagination_combines_pages() -> None:
    first_page = [{"id": value} for value in range(100)]
    rest_pages = iter([json.dumps(first_page), json.dumps([{"id": 100}])])
    graphql_pages = iter(
        [
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [{"id": "THREAD_1"}],
                                "pageInfo": {
                                    "hasNextPage": True,
                                    "endCursor": "thread-cursor",
                                },
                            }
                        }
                    }
                }
            },
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [],
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                            }
                        }
                    }
                }
            },
        ]
    )
    rest_calls: list[list[str]] = []

    def runner(argv: list[str]) -> str:
        rest_calls.append(argv)
        return (
            json.dumps(next(graphql_pages)) if "graphql" in argv else next(rest_pages)
        )

    client = renovate_review.GhClient(runner)
    assert client.rest_pages("repos/o/r/items") == [
        {"id": value} for value in range(101)
    ]
    nodes = client.graphql_connection(
        "query", {"owner": "o", "name": "r", "number": 42}, "reviewThreads"
    )
    assert [node["id"] for node in nodes] == ["THREAD_1"]
    assert any("page=2" in arg for call in rest_calls for arg in call)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("not-json", "valid JSON"),
        ("{}", "JSON list"),
        ('[{"id": 1, "id": 2}]', "duplicate JSON key"),
        ('[{"id": NaN}]', "non-standard JSON constant"),
    ],
)
def test_rest_pagination_rejects_malformed_or_incomplete_json(
    payload: str, message: str
) -> None:
    client = renovate_review.GhClient(lambda _argv: payload)
    with pytest.raises(renovate_review.ReviewError, match=message):
        client.rest_pages("repos/o/r/items")


@pytest.mark.unit
def test_wrapped_pagination_rejects_incomplete_total_count() -> None:
    payload = json.dumps({"total_count": 2, "check_runs": [{"id": 1}]})
    client = renovate_review.GhClient(lambda _argv: payload)
    with pytest.raises(renovate_review.ReviewError, match="incomplete"):
        client.rest_pages("repos/o/r/check-runs", wrapper="check_runs")


@pytest.mark.unit
def test_wrapped_pagination_rejects_total_count_change() -> None:
    pages = iter(
        [
            json.dumps(
                {"total_count": 101, "check_runs": [{"id": i} for i in range(100)]}
            ),
            json.dumps({"total_count": 102, "check_runs": [{"id": 100}]}),
        ]
    )
    with pytest.raises(renovate_review.ReviewError, match="total_count changed"):
        renovate_review.GhClient(lambda _argv: next(pages)).rest_pages(
            "repos/o/r/check-runs", wrapper="check_runs"
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"errors": [{"message": "denied"}]}, "GraphQL returned errors"),
        (
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [],
                                "pageInfo": {
                                    "hasNextPage": True,
                                    "endCursor": None,
                                },
                            }
                        }
                    }
                }
            },
            "without an endCursor",
        ),
    ],
)
def test_graphql_fails_closed(payload: dict[str, Any], message: str) -> None:
    client = renovate_review.GhClient(lambda _argv: json.dumps(payload))
    with pytest.raises(renovate_review.ReviewError, match=message):
        client.graphql_connection("query", {}, "reviewThreads")


@pytest.mark.unit
def test_review_thread_comments_are_paginated_independently() -> None:
    first = {
        "data": {
            "repository": {
                "pullRequest": {
                    "reviewThreads": {
                        "nodes": [
                            {
                                "id": "THREAD_1",
                                "isResolved": True,
                                "comments": {
                                    "nodes": [],
                                    "pageInfo": {
                                        "hasNextPage": True,
                                        "endCursor": "comment-cursor",
                                    },
                                },
                            }
                        ],
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                    }
                }
            }
        }
    }
    second = {
        "data": {
            "node": {
                "comments": {
                    "nodes": [
                        {
                            "id": "COMMENT_1",
                            "author": {"login": "fictional-reviewer"},
                            "body": "Resolved.",
                            "createdAt": "2026-09-14T17:43:00Z",
                            "url": "https://github.example/review/1",
                        }
                    ],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }
    }
    pages = iter([json.dumps(first), json.dumps(second)])
    threads = renovate_review._collect_review_threads(
        renovate_review.GhClient(lambda _argv: next(pages)), "o", "r", 42
    )
    assert threads[0]["comments"][0]["id"] == "COMMENT_1"


@pytest.mark.unit
def test_run_command_success_nonzero_and_oserror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        renovate_review.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "ok", ""),
    )
    assert renovate_review.run_command(["gh", "version"]) == "ok"
    monkeypatch.setattr(
        renovate_review.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 3, "", "denied"),
    )
    with pytest.raises(renovate_review.CommandError, match="denied"):
        renovate_review.run_command(["gh", "api"])

    def missing(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise OSError("missing executable")

    monkeypatch.setattr(renovate_review.subprocess, "run", missing)
    with pytest.raises(renovate_review.CommandError, match="missing executable"):
        renovate_review.run_command(["gh"])


@pytest.mark.unit
def test_ruleset_bypass_visibility_distinguishes_omitted_and_explicit() -> None:
    rest = _fixture("rest_responses.json")
    hidden = renovate_review._normalize_ruleset(rest["ruleset_detail"], "ruleset")
    assert hidden["bypass_actors"] == []
    assert hidden["bypass_actors_visible"] is False

    visible_input = copy.deepcopy(rest["ruleset_detail"])
    visible_input["bypass_actors"] = [
        {"actor_id": 7, "actor_type": "Integration", "bypass_mode": "always"}
    ]
    visible = renovate_review._normalize_ruleset(visible_input, "ruleset")
    assert visible["bypass_actors"] == visible_input["bypass_actors"]
    assert visible["bypass_actors_visible"] is True


@pytest.mark.unit
def test_real_shaped_status_and_review_comment_are_normalized() -> None:
    status = renovate_review._normalize_status(
        {
            "id": 901,
            "context": "coverage/project",
            "sha": "head222",
            "state": "success",
            "creator": {"login": "coverage-bot", "id": 902, "type": "Bot"},
        },
        0,
        "head222",
    )
    comment = renovate_review._normalize_comment(
        {
            "id": 903,
            "user": {"login": "review-bot", "id": 904, "type": "Bot"},
            "body": "Fictional inline finding.",
            "created_at": "2026-09-14T17:43:00Z",
            "updated_at": "2026-09-14T17:44:00Z",
            "path": "example.lock",
            "commit_id": "head222",
        },
        0,
        "review comment",
    )
    assert status["exact_head"] is True
    assert status["creator"]["id"] == 902
    assert comment["path"] == "example.lock"
    assert comment["commit_id"] == "head222"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("repo", "number", "message"),
    [
        ("missing-owner", 42, "OWNER/REPO"),
        ("owner/repo", 0, "positive"),
    ],
)
def test_collect_snapshot_rejects_invalid_inputs(
    repo: str, number: int, message: str
) -> None:
    with pytest.raises(renovate_review.ReviewError, match=message):
        renovate_review.collect_snapshot(repo, number, runner=lambda _argv: "{}")


@pytest.mark.unit
def test_collect_snapshot_rejects_malformed_repository_response() -> None:
    with pytest.raises(renovate_review.ReviewError, match="full_name"):
        renovate_review.collect_snapshot(
            "example-org/example-repo", 42, runner=lambda _argv: "{}"
        )


@pytest.mark.unit
def test_collect_snapshot_rejects_undiscoverable_ruleset() -> None:
    rest = _fixture("rest_responses.json")
    graphql = _fixture("graphql_responses.json")
    review_thread_pages = iter(graphql["review_threads_pages"])
    closing_issue_pages = iter(graphql["closing_issues_pages"])

    def runner(argv: list[str]) -> str:
        endpoint = argv[-1]
        if "graphql" in argv:
            query = next(value for value in argv if value.startswith("query="))
            pages = (
                closing_issue_pages
                if "closingIssuesReferences" in query
                else review_thread_pages
            )
            return json.dumps(next(pages))
        if any("application/vnd.github.diff" in value for value in argv):
            return "diff"
        if endpoint == "repos/example-org/example-repo":
            return json.dumps(rest["repository"])
        if endpoint.endswith("pulls/42"):
            return json.dumps(rest["pull_request"])
        if "/pulls/42/commits?" in endpoint:
            return json.dumps(rest["commits_pages"][0])
        if "/pulls/42/files?" in endpoint:
            return json.dumps(rest["files_pages"][0])
        if "/issues/42/comments?" in endpoint:
            return "[]"
        if "/pulls/42/reviews?" in endpoint or "/pulls/42/comments?" in endpoint:
            return "[]"
        if "/check-runs?" in endpoint:
            return json.dumps(rest["check_runs_pages"][0])
        if "/statuses?" in endpoint:
            return "[]"
        if "/actions/runs?" in endpoint:
            return json.dumps(rest["workflow_runs_pages"][0])
        if endpoint.endswith("branches/main/protection"):
            return json.dumps(rest["branch_protection"])
        if "/rules/branches/main?" in endpoint:
            return json.dumps(rest["effective_rules"])
        if endpoint.endswith("branches/main"):
            return json.dumps(rest["default_branch"])
        if "/rulesets?" in endpoint:
            return "[]"
        raise AssertionError(f"unexpected fake GitHub command: {argv}")

    with pytest.raises(renovate_review.ReviewError, match="undiscoverable"):
        renovate_review.collect_snapshot("example-org/example-repo", 42, runner=runner)


@pytest.mark.unit
def test_ruleset_required_context_enforces_provider() -> None:
    snapshot = _snapshot()
    snapshot["protection"]["rulesets"][0]["rules"] = [
        {
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [{"context": "CI", "integration_id": 15368}]
            },
        }
    ]
    renovate_review.evaluate_snapshot(snapshot, _evidence())
    snapshot["protection"]["rulesets"][0]["rules"][0]["parameters"][
        "required_status_checks"
    ][0]["integration_id"] = 999
    with pytest.raises(renovate_review.ReviewError, match="wrong provider"):
        renovate_review.evaluate_snapshot(snapshot, _evidence())


@pytest.mark.unit
def test_classic_provider_bound_check_rejects_wrong_provider() -> None:
    snapshot = _snapshot()
    snapshot["checks"][0]["app"]["id"] = 999
    evidence = _evidence_for_snapshot(snapshot)
    evidence["expected_checks"][0]["app"]["id"] = 15368
    with pytest.raises(renovate_review.ReviewError, match="provider"):
        renovate_review.evaluate_snapshot(snapshot, evidence)


@pytest.mark.unit
def test_runner_api_failure_is_actionable() -> None:
    def runner(_argv: list[str]) -> str:
        raise renovate_review.CommandError(["gh", "api", "endpoint"], 1, "forbidden")

    with pytest.raises(renovate_review.ReviewError, match="forbidden"):
        renovate_review.GhClient(runner).rest_json("repos/o/r")


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["pull_request"].update(author=None), "PR author identity"),
        (
            lambda value: value["pull_request"].update(
                author=_identity("other-bot", 29139614, "Bot")
            ),
            "PR author identity",
        ),
        (
            lambda value: value["pull_request"].update(
                author=_identity("renovate[bot]", 999, "Bot")
            ),
            "PR author identity",
        ),
        (
            lambda value: value["pull_request"].update(
                author=_identity("app/renovate", 29139614, "Bot")
            ),
            "PR author identity",
        ),
        (
            lambda value: value["commits"][0].update(author=None),
            "commit author identity",
        ),
        (
            lambda value: value["commits"][0].update(committer=None),
            "commit committer identity",
        ),
        (
            lambda value: value["commits"][0].update(
                author=_identity("other-bot", 29139614, "Bot")
            ),
            "commit author identity",
        ),
        (
            lambda value: value["commits"][0].update(
                author=_identity("renovate[bot]", 999, "Bot")
            ),
            "commit author identity",
        ),
        (
            lambda value: value["commits"][0].update(
                committer=_identity("web-flow", 999, "User")
            ),
            "untrusted committer",
        ),
        (lambda value: value["pull_request"].update(state="closed"), "open"),
        (lambda value: value["pull_request"].update(draft=True), "draft"),
        (
            lambda value: value["pull_request"].update(mergeable_state="blocked"),
            "merge state",
        ),
        (
            lambda value: value["pull_request"].update(base_ref="other"),
            "default branch",
        ),
        (
            lambda value: value["repository"].update(default_sha="other"),
            "default SHA",
        ),
        (lambda value: value["ancestry"].update(status="behind"), "ancestry"),
        (lambda value: value["ancestry"].update(status="diverged"), "ancestry"),
        (
            lambda value: value["review_threads"].append(
                {"id": "T", "is_resolved": False, "comments": []}
            ),
            "unresolved",
        ),
        (
            lambda value: value["closing_issues"].append(
                {"number": 9, "url": "https://github.example/issues/9"}
            ),
            "closing issue",
        ),
        (lambda value: value["checks"].clear(), "expected check"),
        (lambda value: value["checks"][0].update(conclusion="failure"), "successful"),
        (lambda value: value["checks"][0].update(conclusion="skipped"), "successful"),
        (
            lambda value: value["checks"][0].update(
                status="in_progress", conclusion=None
            ),
            "successful",
        ),
        (lambda value: value["checks"][0]["app"].update(id=999), "provider"),
        (lambda value: value["workflows"][0].update(head_sha="old-head"), "workflow"),
        (
            lambda value: value["protection"]["required_status_checks"][
                "checks"
            ].append({"context": "Required Missing", "app_id": 15368}),
            "required context",
        ),
    ],
)
def test_snapshot_gate_fails_closed(
    mutation: Callable[[dict[str, Any]], None], message: str
) -> None:
    snapshot = _snapshot()
    mutation(snapshot)
    with pytest.raises(renovate_review.ReviewError, match=message):
        renovate_review.evaluate_snapshot(snapshot, _evidence())


@pytest.mark.unit
def test_check_and_status_namespaces_do_not_substitute() -> None:
    snapshot = _snapshot()
    snapshot["checks"].clear()
    snapshot["statuses"] = [
        {
            "id": 1,
            "context": "CI",
            "sha": "head222",
            "state": "success",
            "creator": _identity("github-actions[bot]", 41898282, "Bot"),
        }
    ]
    with pytest.raises(renovate_review.ReviewError, match="expected check"):
        renovate_review.evaluate_snapshot(snapshot, _evidence())


@pytest.mark.unit
def test_duplicate_same_provider_check_is_reported_as_ambiguous() -> None:
    snapshot = _snapshot()
    duplicate = copy.deepcopy(snapshot["checks"][0])
    duplicate["id"] = 3002
    snapshot["checks"].append(duplicate)
    with pytest.raises(renovate_review.ReviewError, match="duplicate or ambiguous"):
        renovate_review.evaluate_snapshot(snapshot, _evidence())


@pytest.mark.unit
@pytest.mark.parametrize(
    ("kind", "ambiguous"),
    [
        pytest.param("check", False, id="check-success"),
        pytest.param("status", False, id="status-success"),
        pytest.param("both", True, id="check-status-ambiguous"),
    ],
)
def test_context_only_requirement_uses_expected_provider_binding(
    kind: str, ambiguous: bool
) -> None:
    snapshot = _snapshot()
    evidence = _evidence()
    snapshot["protection"]["required_status_checks"]["checks"] = []
    if kind in {"status", "both"}:
        status = {
            "id": 10,
            "context": "CI",
            "sha": "head222",
            "state": "success",
            "creator": _identity("status-bot", 2001, "Bot"),
        }
        snapshot["statuses"] = [status]
        evidence["expected_statuses"] = {
            "items": [{"context": "CI", "creator": copy.deepcopy(status["creator"])}],
            "empty_reason": None,
        }
    if kind == "status":
        snapshot["checks"] = []
        evidence["expected_checks"] = [
            {
                "name": "Other",
                "app": {
                    "id": 15368,
                    "slug": "github-actions",
                    "name": "GitHub Actions",
                },
            }
        ]
        snapshot["checks"] = [
            {
                "id": 11,
                "name": "Other",
                "head_sha": "head222",
                "status": "completed",
                "conclusion": "success",
                "app": evidence["expected_checks"][0]["app"],
            }
        ]
    if ambiguous:
        with pytest.raises(
            renovate_review.ReviewError, match="no unique expected provider binding"
        ):
            renovate_review.evaluate_snapshot(snapshot, evidence)
    else:
        renovate_review.evaluate_snapshot(snapshot, evidence)


@pytest.mark.unit
def test_ruleset_required_checks_require_visible_bypass_actors() -> None:
    snapshot = _snapshot()
    snapshot["protection"]["rulesets"][0].update(
        bypass_actors=[],
        bypass_actors_visible=False,
        rules=[
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [
                        {"context": "CI", "integration_id": 15368}
                    ]
                },
            }
        ],
    )

    with pytest.raises(renovate_review.ReviewError, match="bypass actors"):
        renovate_review.evaluate_snapshot(snapshot, _evidence())


@pytest.mark.unit
@pytest.mark.parametrize("kind", ["checks", "statuses", "workflows"])
def test_snapshot_gate_rejects_observed_automation_omitted_from_expected(
    kind: str,
) -> None:
    snapshot = _snapshot()
    evidence = _evidence()
    if kind == "checks":
        snapshot["checks"].append(
            {
                "id": 3002,
                "name": "Security",
                "head_sha": "head222",
                "status": "completed",
                "conclusion": "success",
                "app": {
                    "id": 15368,
                    "slug": "github-actions",
                    "name": "GitHub Actions",
                },
            }
        )
    elif kind == "statuses":
        snapshot["statuses"].append(
            {
                "id": 3003,
                "context": "coverage/project",
                "sha": "head222",
                "state": "success",
                "creator": _identity("coverage-bot", 2001, "Bot"),
            }
        )
    else:
        snapshot["workflows"].append(
            {
                "id": 4002,
                "workflow_id": 5002,
                "path": ".github/workflows/security.yml",
                "name": "Security",
                "head_sha": "head222",
                "status": "completed",
                "conclusion": "success",
            }
        )
    with pytest.raises(renovate_review.ReviewError, match="expected evidence"):
        renovate_review.evaluate_snapshot(snapshot, evidence)


@pytest.mark.unit
@pytest.mark.parametrize("category", renovate_review.SOURCE_CATEGORIES)
def test_semantic_evidence_requires_every_source_category(category: str) -> None:
    evidence = _evidence()
    evidence["sources"][category] = []
    with pytest.raises(renovate_review.ReviewError, match=category):
        renovate_review.validate_evidence(evidence)


@pytest.mark.unit
@pytest.mark.parametrize(
    "change",
    [
        pytest.param({"reviewed_head": "old-head"}, id="wrong-head"),
        pytest.param({"verdict": "Findings"}, id="non-clean"),
    ],
)
def test_semantic_evidence_rejects_invalid_required_reviewer(
    change: dict[str, str],
) -> None:
    evidence = _evidence()
    evidence["reviewers"][0].update(change)
    with pytest.raises(renovate_review.ReviewError, match="reviewer"):
        renovate_review.validate_evidence(evidence)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("repository", "other/repo", "repository"),
        ("pull_request", 43, "pull request"),
        ("base_sha", "other-base", "base SHA"),
        ("head_sha", "other-head", "head SHA"),
    ],
)
def test_semantic_evidence_binding_mismatch_fails(
    key: str, value: Any, message: str
) -> None:
    evidence = _evidence()
    evidence[key] = value
    with pytest.raises(renovate_review.ReviewError, match=message):
        renovate_review.evaluate_snapshot(_snapshot(), evidence)


@pytest.mark.unit
def test_semantic_evidence_requires_explicit_empty_status_and_workflow_reasons() -> (
    None
):
    evidence = _evidence()
    evidence["expected_statuses"]["empty_reason"] = ""
    evidence["expected_workflows"] = {"items": [], "empty_reason": ""}
    with pytest.raises(renovate_review.ReviewError, match="empty_reason"):
        renovate_review.validate_evidence(evidence)


@pytest.mark.unit
def test_expected_status_requires_creator_and_successful_exact_head() -> None:
    snapshot = _snapshot()
    status = {
        "id": 1,
        "context": "coverage/project",
        "sha": "head222",
        "state": "success",
        "creator": _identity("coverage-bot", 2001, "Bot"),
    }
    snapshot["statuses"] = [status]
    evidence = _evidence()
    evidence["expected_statuses"] = {
        "items": [
            {
                "context": "coverage/project",
                "creator": _identity("coverage-bot", 2001, "Bot"),
            }
        ],
        "empty_reason": None,
    }
    renovate_review.evaluate_snapshot(snapshot, evidence)

    snapshot["statuses"][0]["state"] = "pending"
    with pytest.raises(renovate_review.ReviewError, match="not successful"):
        renovate_review.evaluate_snapshot(snapshot, evidence)


@pytest.mark.unit
def test_stability_rejects_interval_below_minimum() -> None:
    with pytest.raises(renovate_review.ReviewError, match="at least 30"):
        renovate_review.stabilize(
            "example-org/example-repo",
            42,
            _evidence(),
            lambda: _snapshot(),
            interval=29,
            sleeper=lambda _seconds: None,
            monotonic=iter([0.0]).__next__,
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda value: value["pull_request"].update(head_sha="new-head"), id="head"
        ),
        pytest.param(
            lambda value: value["pull_request"].update(base_sha="new-base"), id="base"
        ),
        pytest.param(lambda value: value.update(diff_sha256="new-diff"), id="diff"),
        pytest.param(
            lambda value: value["issue_comments"].append({"id": 2}), id="comment"
        ),
        pytest.param(
            lambda value: value["commits"].append({"sha": "other"}), id="commit"
        ),
        pytest.param(
            lambda value: value["review_threads"].append(
                {"id": "T", "is_resolved": True, "comments": []}
            ),
            id="conversation",
        ),
        pytest.param(
            lambda value: value["checks"][0].update(conclusion="failure"), id="check"
        ),
        pytest.param(
            lambda value: value["checks"][0]["app"].update(slug="other"), id="provider"
        ),
        pytest.param(lambda value: value["statuses"].append({"id": 2}), id="status"),
        pytest.param(lambda value: value["workflows"][0].update(id=999), id="workflow"),
        pytest.param(
            lambda value: value["open_prs"].append({"number": 43}), id="inventory"
        ),
    ],
)
def test_stability_detects_merge_relevant_drift(
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    first = _snapshot()
    second = copy.deepcopy(first)
    second["observed_at"] = "2026-09-14T18:00:30Z"
    mutation(second)
    observations = iter([first, second])
    clock = iter([10.0, 40.0])
    with pytest.raises(renovate_review.ReviewError, match="changed during stability"):
        renovate_review.stabilize(
            "example-org/example-repo",
            42,
            _evidence(),
            observations.__next__,
            interval=30,
            sleeper=lambda _seconds: None,
            monotonic=clock.__next__,
        )


@pytest.mark.unit
def test_stabilize_happy_path_uses_injected_sleep_and_clock() -> None:
    first = _snapshot()
    second = copy.deepcopy(first)
    second["observed_at"] = "2026-09-14T18:00:30Z"
    observations = iter([first, second])
    clock = iter([10.0, 40.0])
    sleeps: list[float] = []
    bundle = renovate_review.stabilize(
        "example-org/example-repo",
        42,
        _evidence(),
        observations.__next__,
        interval=30,
        sleeper=sleeps.append,
        monotonic=clock.__next__,
    )
    assert sleeps == [30]
    assert bundle["approved_identity"]["head_sha"] == "head222"
    assert bundle["elapsed_seconds"] == 30.0


@pytest.mark.unit
def test_stabilize_rejects_lying_sleeper_using_monotonic_clock() -> None:
    observations = iter([_snapshot(), _snapshot()])
    with pytest.raises(renovate_review.ReviewError, match="shorter than requested"):
        renovate_review.stabilize(
            "example-org/example-repo",
            42,
            _evidence(),
            observations.__next__,
            interval=30,
            sleeper=lambda _seconds: None,
            monotonic=iter([10.0, 39.0]).__next__,
        )


@pytest.mark.unit
def test_stability_bundle_rejects_missing_merge_relevant_field() -> None:
    bundle = _stability_bundle()
    del bundle["observations"][0]["diff_sha256"]
    del bundle["observations"][1]["diff_sha256"]
    with pytest.raises(renovate_review.ReviewError, match="diff_sha256"):
        renovate_review.validate_stability_bundle(
            bundle, "example-org/example-repo", 42, _evidence()
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda bundle: bundle["observations"][1].update(
                observed_at="2026-09-14T18:00:29Z"
            ),
            "too close",
        ),
        (
            lambda bundle: bundle["observations"][1].update(
                observed_at="2026-09-14T18:00:30"
            ),
            "UTC offsets",
        ),
        (
            lambda bundle: bundle["observations"][1].update(observed_at="invalid"),
            "timestamps are invalid",
        ),
        (
            lambda bundle: bundle["approved_identity"].update(head_sha="other"),
            "approved identity",
        ),
    ],
)
def test_stability_bundle_rejects_invalid_time_or_identity(
    mutation: Callable[[dict[str, Any]], None], message: str
) -> None:
    bundle = _stability_bundle()
    mutation(bundle)
    with pytest.raises(renovate_review.ReviewError, match=message):
        renovate_review.validate_stability_bundle(
            bundle, "example-org/example-repo", 42, _evidence()
        )


def _stability_bundle() -> dict[str, Any]:
    first = _snapshot()
    second = copy.deepcopy(first)
    second["observed_at"] = "2026-09-14T18:00:30Z"
    return {
        "schema_version": 1,
        "interval_seconds": 30,
        "elapsed_seconds": 30.0,
        "approved_identity": {
            "repository": "example-org/example-repo",
            "pull_request": 42,
            "base_sha": "base111",
            "head_sha": "head222",
        },
        "observations": [first, second],
    }


def _merge_observations() -> tuple[dict[str, Any], dict[str, Any]]:
    first = _snapshot()
    first["observed_at"] = "2026-09-14T18:01:00Z"
    second = copy.deepcopy(first)
    second["observed_at"] = "2026-09-14T18:01:30Z"
    return first, second


@pytest.mark.unit
def test_merge_final_refresh_drift_prevents_merge() -> None:
    first = _snapshot()
    first["observed_at"] = "2026-09-14T18:01:00Z"
    first["diff_sha256"] = "changed"
    observations = iter([first])
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> str:
        calls.append(argv)
        return ""

    with pytest.raises(renovate_review.ReviewError, match="changed after stability"):
        renovate_review.merge_pull_request(
            "example-org/example-repo",
            42,
            _evidence(),
            _stability_bundle(),
            observations.__next__,
            runner,
            sleeper=lambda _seconds: None,
            monotonic=iter([0.0, 30.0]).__next__,
        )
    assert calls == []


@pytest.mark.unit
def test_merge_live_wait_drift_prevents_merge() -> None:
    first, final = _merge_observations()
    final["review_threads"].append({"id": "T", "is_resolved": True, "comments": []})
    observations = iter([first, final])
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> str:
        calls.append(argv)
        return ""

    with pytest.raises(renovate_review.ReviewError, match="changed after stability"):
        renovate_review.merge_pull_request(
            "example-org/example-repo",
            42,
            _evidence(),
            _stability_bundle(),
            observations.__next__,
            runner,
            sleeper=lambda _seconds: None,
            monotonic=iter([0.0, 30.0]).__next__,
        )
    assert calls == []


@pytest.mark.unit
def test_merge_uses_exact_guarded_argv_and_verifies_reachability() -> None:
    calls: list[list[str]] = []
    observations = iter(_merge_observations())
    sleeps: list[float] = []

    def runner(argv: list[str]) -> str:
        calls.append(argv)
        if argv[1:3] == ["pr", "merge"]:
            return ""
        if "pulls/42" in argv[-1]:
            return json.dumps(
                {"state": "closed", "merged": True, "merge_commit_sha": "merge333"}
            )
        if argv[-1].endswith("branches/main"):
            return json.dumps({"commit": {"sha": "default444"}})
        return json.dumps({"status": "ahead", "ahead_by": 1, "behind_by": 0})

    proof = renovate_review.merge_pull_request(
        "example-org/example-repo",
        42,
        _evidence(),
        _stability_bundle(),
        observations.__next__,
        runner,
        sleeper=sleeps.append,
        monotonic=iter([0.0, 30.0]).__next__,
    )
    merge_call = calls[0]
    assert merge_call == [
        "gh",
        "pr",
        "merge",
        "42",
        "--repo",
        "example-org/example-repo",
        "--squash",
        "--match-head-commit",
        "head222",
    ]
    assert "--admin" not in merge_call
    assert sleeps == [30]
    assert proof["merge_commit_sha"] == "merge333"


@pytest.mark.unit
def test_merge_command_failure_is_not_retried() -> None:
    calls = 0
    observations = iter(_merge_observations())

    def runner(argv: list[str]) -> str:
        nonlocal calls
        calls += 1
        raise renovate_review.CommandError(argv, 1, "merge rejected")

    with pytest.raises(renovate_review.ReviewError, match="merge rejected"):
        renovate_review.merge_pull_request(
            "example-org/example-repo",
            42,
            _evidence(),
            _stability_bundle(),
            observations.__next__,
            runner,
            sleeper=lambda _seconds: None,
            monotonic=iter([0.0, 30.0]).__next__,
        )
    assert calls == 1


@pytest.mark.unit
def test_merge_post_merge_reachability_failure_is_reported() -> None:
    observations = iter(_merge_observations())
    responses = iter(
        [
            "",
            json.dumps(
                {"state": "closed", "merged": True, "merge_commit_sha": "merge333"}
            ),
            json.dumps({"commit": {"sha": "default444"}}),
            json.dumps({"status": "diverged", "ahead_by": 1, "behind_by": 1}),
        ]
    )
    with pytest.raises(renovate_review.ReviewError, match="not reachable"):
        renovate_review.merge_pull_request(
            "example-org/example-repo",
            42,
            _evidence(),
            _stability_bundle(),
            observations.__next__,
            lambda _argv: next(responses),
            sleeper=lambda _seconds: None,
            monotonic=iter([0.0, 30.0]).__next__,
        )


@pytest.mark.unit
def test_merge_command_success_but_pr_unmerged_fails() -> None:
    observations = iter(_merge_observations())
    responses = iter(
        [
            "",
            json.dumps({"state": "open", "merged": False, "merge_commit_sha": None}),
        ]
    )
    with pytest.raises(renovate_review.ReviewError, match="not merged"):
        renovate_review.merge_pull_request(
            "example-org/example-repo",
            42,
            _evidence(),
            _stability_bundle(),
            observations.__next__,
            lambda _argv: next(responses),
            sleeper=lambda _seconds: None,
            monotonic=iter([0.0, 30.0]).__next__,
        )


@pytest.mark.unit
def test_merge_rejects_short_live_stability_interval() -> None:
    observations = iter(_merge_observations())
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> str:
        calls.append(argv)
        return ""

    with pytest.raises(renovate_review.ReviewError, match="live merge interval"):
        renovate_review.merge_pull_request(
            "example-org/example-repo",
            42,
            _evidence(),
            _stability_bundle(),
            observations.__next__,
            runner,
            sleeper=lambda _seconds: None,
            monotonic=iter([0.0, 29.0]).__next__,
        )

    assert calls == []


@pytest.mark.unit
def test_cli_parser_accepts_each_documented_command() -> None:
    parser = renovate_review._parser()
    snapshot = parser.parse_args(
        ["snapshot", "--repo", "example-org/example-repo", "--pr", "42"]
    )
    stabilize = parser.parse_args(
        [
            "stabilize",
            "--repo",
            "example-org/example-repo",
            "--pr",
            "42",
            "--evidence",
            "/tmp/opencode/evidence.json",
        ]
    )
    merge = parser.parse_args(
        [
            "merge",
            "--repo",
            "example-org/example-repo",
            "--pr",
            "42",
            "--evidence",
            "/tmp/opencode/evidence.json",
            "--stability",
            "/tmp/opencode/stability.json",
        ]
    )
    assert snapshot.command == "snapshot"
    assert stabilize.interval == 30
    assert merge.command == "merge"


@pytest.mark.unit
def test_main_snapshot_writes_structured_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "snapshot.json"
    monkeypatch.setattr(
        renovate_review,
        "collect_snapshot",
        lambda _repo, _number: {"schema_version": 1, "result": "ok"},
    )
    result = renovate_review.main(
        [
            "snapshot",
            "--repo",
            "example-org/example-repo",
            "--pr",
            "42",
            "--output",
            str(output),
        ]
    )
    assert result == 0
    assert json.loads(output.read_text(encoding="utf-8"))["result"] == "ok"
    assert capsys.readouterr() == ("", "")


@pytest.mark.unit
def test_main_snapshot_writes_structured_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        renovate_review,
        "collect_snapshot",
        lambda _repo, _number: {"schema_version": 1, "result": "ok"},
    )
    result = renovate_review.main(
        ["snapshot", "--repo", "example-org/example-repo", "--pr", "42"]
    )
    captured = capsys.readouterr()
    assert result == 0
    assert json.loads(captured.out)["result"] == "ok"
    assert captured.err == ""


@pytest.mark.unit
def test_main_output_failure_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        renovate_review,
        "collect_snapshot",
        lambda _repo, _number: {"schema_version": 1},
    )
    result = renovate_review.main(
        [
            "snapshot",
            "--repo",
            "example-org/example-repo",
            "--pr",
            "42",
            "--output",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert "cannot write output" in captured.err


@pytest.mark.unit
def test_main_failure_writes_only_actionable_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(_repo: str, _number: int) -> dict[str, Any]:
        raise renovate_review.ReviewError("fictional API failure")

    monkeypatch.setattr(renovate_review, "collect_snapshot", fail)
    result = renovate_review.main(
        ["snapshot", "--repo", "example-org/example-repo", "--pr", "42"]
    )
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == "renovate-review: fictional API failure\n"


@pytest.mark.unit
@pytest.mark.parametrize("command", ["stabilize", "merge"])
def test_main_dispatches_evidence_commands(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(_evidence()), encoding="utf-8")
    argv = [
        command,
        "--repo",
        "example-org/example-repo",
        "--pr",
        "42",
        "--evidence",
        str(evidence_path),
    ]
    if command == "stabilize":
        monkeypatch.setattr(
            renovate_review,
            "stabilize",
            lambda *_args, **_kwargs: {"command": "stabilize"},
        )
    else:
        stability_path = tmp_path / "stability.json"
        stability_path.write_text(json.dumps(_stability_bundle()), encoding="utf-8")
        argv.extend(["--stability", str(stability_path)])
        monkeypatch.setattr(
            renovate_review,
            "merge_pull_request",
            lambda *_args, **_kwargs: {"command": "merge"},
        )

    assert renovate_review.main(argv) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"command": command}
    assert captured.err == ""
