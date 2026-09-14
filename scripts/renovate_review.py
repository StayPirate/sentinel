#!/usr/bin/env python3
"""Collect and enforce deterministic GitHub gates for Renovate pull requests.

Semantic evidence schema (JSON, schema_version 1):

* repository, pull_request, base_sha, and head_sha bind the assessment.
* primary_verdict must be exactly "Clean".
* sources contains non-empty primary-agent records for release_notes,
  upstream_compare, advisories, known_regressions, and artifact_identity. Each
  record has source="primary-agent", an authoritative URL/endpoint in
  reference, and a concise non-empty finding.
* reviewers lists every considered reviewer with name, required, and reason.
  Required reviewers also have verdict="Clean" and reviewed_head=head_sha.
* expected_checks is a list of {name, app:{id,slug,name}}.
* expected_statuses is {items:[{context,creator:{id,login,type}}], empty_reason}.
* expected_workflows is
  {items:[{path,workflow_id,name}], empty_reason}. Empty status/workflow lists
  require a non-empty rationale; expected checks may not be empty.

The utility validates this structure and its binding, not the semantic truth of
the primary agent's findings.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import quote

JsonObject = dict[str, Any]
Runner = Callable[[list[str]], str]
Collector = Callable[[], JsonObject]

SOURCE_CATEGORIES = (
    "release_notes",
    "upstream_compare",
    "advisories",
    "known_regressions",
    "artifact_identity",
)
RENOVATE_IDENTITY = ("renovate[bot]", 29139614, "Bot")
TRUSTED_COMMITTERS = {
    ("renovate[bot]", 29139614, "Bot"),
    ("web-flow", 19864447, "User"),
}
SUCCESS = "success"
MINIMUM_INTERVAL = 30


class ReviewError(ValueError):
    """Raised when evidence cannot be verified safely."""


class CommandError(RuntimeError):
    """Raised when a subprocess command fails."""

    def __init__(self, argv: list[str], returncode: int, stderr: str) -> None:
        self.argv = argv
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(
            f"command failed ({returncode}): {' '.join(argv)}: "
            f"{stderr.strip() or 'no diagnostic output'}"
        )


def run_command(argv: list[str]) -> str:
    """Run one command without a shell and return its stdout."""
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise CommandError(argv, 127, str(exc)) from exc
    if result.returncode != 0:
        raise CommandError(argv, result.returncode, result.stderr)
    return result.stdout


def _parse_json(raw: str, source: str) -> Any:
    def reject_constant(value: str) -> NoReturn:
        raise ValueError(f"non-standard JSON constant {value!r}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> JsonObject:
        result: JsonObject = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            raw,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ReviewError(f"{source} did not return valid JSON: {exc}") from exc


def _object(value: Any, source: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ReviewError(f"{source} must be a JSON object")
    return value


def _list(value: Any, source: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReviewError(f"{source} must be a JSON list")
    return value


def _field(obj: Mapping[str, Any], key: str, expected: type, source: str) -> Any:
    if key not in obj:
        raise ReviewError(f"{source} is missing {key!r}")
    value = obj[key]
    if expected is int:
        valid = isinstance(value, int) and not isinstance(value, bool)
    else:
        valid = isinstance(value, expected)
    if not valid:
        raise ReviewError(f"{source}.{key} must be {expected.__name__}")
    return value


def _nullable_string(obj: Mapping[str, Any], key: str, source: str) -> str | None:
    if key not in obj:
        raise ReviewError(f"{source} is missing {key!r}")
    value = obj[key]
    if value is not None and not isinstance(value, str):
        raise ReviewError(f"{source}.{key} must be string or null")
    return value


def _nonempty(value: Any, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(f"{source} must be a non-empty string")
    return value


def _positive_int(value: Any, source: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ReviewError(f"{source} must be a positive integer")
    return value


def _identity(value: Any, source: str) -> JsonObject:
    obj = _object(value, source)
    return {
        "login": _nonempty(obj.get("login"), f"{source}.login"),
        "id": _positive_int(obj.get("id"), f"{source}.id"),
        "type": _nonempty(obj.get("type"), f"{source}.type"),
    }


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _stable(items: list[JsonObject]) -> list[JsonObject]:
    return sorted(
        items,
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
    )


class GhClient:
    """Small injectable boundary around authenticated GitHub CLI calls."""

    def __init__(self, runner: Runner = run_command) -> None:
        self.runner = runner

    def _run(self, argv: list[str], source: str) -> str:
        try:
            return self.runner(argv)
        except CommandError as exc:
            raise ReviewError(f"GitHub request for {source} failed: {exc}") from exc

    def rest_json(self, endpoint: str) -> Any:
        raw = self._run(["gh", "api", endpoint], endpoint)
        return _parse_json(raw, endpoint)

    def rest_text(self, endpoint: str, accept: str) -> str:
        return self._run(["gh", "api", "-H", f"Accept: {accept}", endpoint], endpoint)

    def rest_pages(
        self,
        endpoint: str,
        *,
        wrapper: str | None = None,
        parameters: Mapping[str, str] | None = None,
    ) -> list[Any]:
        combined: list[Any] = []
        total_count: int | None = None
        page = 1
        while True:
            query = {**(parameters or {}), "per_page": "100", "page": str(page)}
            separator = "&" if "?" in endpoint else "?"
            encoded = "&".join(
                f"{quote(key)}={quote(value)}" for key, value in query.items()
            )
            source = f"{endpoint} page {page}"
            payload = self.rest_json(f"{endpoint}{separator}{encoded}")
            if wrapper is not None:
                wrapped = _object(payload, source)
                reported_total = wrapped.get("total_count")
                if not isinstance(reported_total, int) or isinstance(
                    reported_total, bool
                ):
                    raise ReviewError(f"{source}.total_count must be int")
                if total_count is None:
                    total_count = reported_total
                elif total_count != reported_total:
                    raise ReviewError(f"{source} total_count changed during pagination")
                payload = wrapped.get(wrapper)
                source = f"{source}.{wrapper}"
            values = _list(payload, source)
            combined.extend(values)
            if len(values) < 100:
                break
            page += 1
        if total_count is not None and len(combined) != total_count:
            raise ReviewError(
                f"{endpoint} pagination is incomplete: expected {total_count} items, "
                f"collected {len(combined)}"
            )
        return combined

    def graphql(self, query: str, variables: Mapping[str, Any]) -> JsonObject:
        argv = ["gh", "api", "graphql", "-f", f"query={query}"]
        for key, value in variables.items():
            if value is None:
                continue
            flag = "-F" if isinstance(value, int) else "-f"
            argv.extend([flag, f"{key}={value}"])
        raw = self._run(argv, "GraphQL")
        payload = _object(_parse_json(raw, "GraphQL"), "GraphQL")
        if payload.get("errors"):
            raise ReviewError(f"GraphQL returned errors: {payload['errors']}")
        return payload

    def graphql_connection(
        self,
        query: str,
        variables: Mapping[str, Any],
        connection: str,
    ) -> list[JsonObject]:
        nodes: list[JsonObject] = []
        cursor: str | None = None
        while True:
            payload = self.graphql(query, {**variables, "cursor": cursor})
            try:
                pull_request = payload["data"]["repository"]["pullRequest"]
                connection_value = pull_request[connection]
            except (KeyError, TypeError) as exc:
                raise ReviewError(
                    f"GraphQL response is missing pullRequest.{connection}"
                ) from exc
            obj = _object(connection_value, f"GraphQL {connection}")
            for node in _list(obj.get("nodes"), f"GraphQL {connection}.nodes"):
                nodes.append(_object(node, f"GraphQL {connection} node"))
            page_info = _object(obj.get("pageInfo"), f"GraphQL {connection}.pageInfo")
            has_next = _field(
                page_info, "hasNextPage", bool, f"GraphQL {connection}.pageInfo"
            )
            end_cursor = page_info.get("endCursor")
            if has_next:
                if not isinstance(end_cursor, str) or not end_cursor:
                    raise ReviewError(
                        f"GraphQL {connection} has a next page without an endCursor"
                    )
                cursor = end_cursor
            else:
                break
        return nodes


REVIEW_THREADS_QUERY = """
query($owner:String!,$name:String!,$number:Int!,$cursor:String){
  repository(owner:$owner,name:$name){pullRequest(number:$number){
    reviewThreads(first:100,after:$cursor){nodes{id isResolved comments(first:100){
      nodes{id author{login ... on User{id} ... on Bot{id} ... on Organization{id}}
      body createdAt url} pageInfo{hasNextPage endCursor}}}
      pageInfo{hasNextPage endCursor}}
  }}
}
"""
THREAD_COMMENTS_QUERY = """
query($thread:ID!,$cursor:String){node(id:$thread){... on PullRequestReviewThread{
  comments(first:100,after:$cursor){nodes{id author{login ... on User{id}
  ... on Bot{id} ... on Organization{id}} body createdAt url}
  pageInfo{hasNextPage endCursor}}}}}
"""
CLOSING_ISSUES_QUERY = """
query($owner:String!,$name:String!,$number:Int!,$cursor:String){
  repository(owner:$owner,name:$name){pullRequest(number:$number){
    closingIssuesReferences(first:100,after:$cursor){nodes{number url}
    pageInfo{hasNextPage endCursor}}
  }}
}
"""


def _graphql_identity(value: Any, source: str) -> JsonObject:
    obj = _object(value, source)
    login = _nonempty(obj.get("login"), f"{source}.login")
    account_id = obj.get("id")
    if account_id is None:
        # GraphQL node IDs are opaque; login remains the resolved identity.
        return {"login": login}
    return {"login": login, "id": account_id}


def _thread_comment(value: Any, source: str) -> JsonObject:
    obj = _object(value, source)
    return {
        "id": _nonempty(obj.get("id"), f"{source}.id"),
        "author": _graphql_identity(obj.get("author"), f"{source}.author"),
        "body": _field(obj, "body", str, source),
        "created_at": _nonempty(obj.get("createdAt"), f"{source}.createdAt"),
        "url": _nonempty(obj.get("url"), f"{source}.url"),
    }


def _remaining_thread_comments(
    client: GhClient, thread_id: str, cursor: str
) -> list[JsonObject]:
    comments: list[JsonObject] = []
    while True:
        payload = client.graphql(
            THREAD_COMMENTS_QUERY, {"thread": thread_id, "cursor": cursor}
        )
        try:
            connection = payload["data"]["node"]["comments"]
        except (KeyError, TypeError) as exc:
            raise ReviewError("GraphQL response is missing thread comments") from exc
        obj = _object(connection, "GraphQL thread comments")
        comments.extend(
            _thread_comment(value, "GraphQL thread comment")
            for value in _list(obj.get("nodes"), "GraphQL thread comments.nodes")
        )
        page_info = _object(obj.get("pageInfo"), "GraphQL thread comments.pageInfo")
        if not _field(page_info, "hasNextPage", bool, "thread comments pageInfo"):
            break
        cursor = _nonempty(
            page_info.get("endCursor"), "thread comments pageInfo.endCursor"
        )
    return comments


def _collect_review_threads(
    client: GhClient, owner: str, name: str, number: int
) -> list[JsonObject]:
    nodes = client.graphql_connection(
        REVIEW_THREADS_QUERY,
        {"owner": owner, "name": name, "number": number},
        "reviewThreads",
    )
    result: list[JsonObject] = []
    for index, node in enumerate(nodes):
        source = f"review thread {index}"
        thread_id = _nonempty(node.get("id"), f"{source}.id")
        comments_obj = _object(node.get("comments"), f"{source}.comments")
        comments = [
            _thread_comment(value, f"{source}.comment")
            for value in _list(comments_obj.get("nodes"), f"{source}.comments.nodes")
        ]
        page_info = _object(comments_obj.get("pageInfo"), f"{source}.comments.pageInfo")
        if _field(page_info, "hasNextPage", bool, f"{source}.comments.pageInfo"):
            cursor = _nonempty(
                page_info.get("endCursor"), f"{source}.comments.pageInfo.endCursor"
            )
            comments.extend(_remaining_thread_comments(client, thread_id, cursor))
        result.append(
            {
                "id": thread_id,
                "is_resolved": _field(node, "isResolved", bool, source),
                "comments": _stable(comments),
            }
        )
    return _stable(result)


def _normalize_commit(value: Any, index: int) -> JsonObject:
    obj = _object(value, f"commit {index}")
    raw_commit = _object(obj.get("commit"), f"commit {index}.commit")
    return {
        "sha": _nonempty(obj.get("sha"), f"commit {index}.sha"),
        "message": _field(raw_commit, "message", str, f"commit {index}.commit"),
        "author": _identity(obj.get("author"), f"commit {index}.author"),
        "committer": _identity(obj.get("committer"), f"commit {index}.committer"),
    }


def _normalize_file(value: Any, index: int) -> JsonObject:
    obj = _object(value, f"file {index}")
    return {
        "filename": _nonempty(obj.get("filename"), f"file {index}.filename"),
        "sha": _nonempty(obj.get("sha"), f"file {index}.sha"),
        "status": _nonempty(obj.get("status"), f"file {index}.status"),
        "additions": _field(obj, "additions", int, f"file {index}"),
        "deletions": _field(obj, "deletions", int, f"file {index}"),
        "changes": _field(obj, "changes", int, f"file {index}"),
    }


def _normalize_comment(value: Any, index: int, kind: str) -> JsonObject:
    obj = _object(value, f"{kind} {index}")
    result = {
        "id": _positive_int(obj.get("id"), f"{kind} {index}.id"),
        "author": _identity(obj.get("user"), f"{kind} {index}.user"),
        "body": _field(obj, "body", str, f"{kind} {index}"),
        "created_at": _nonempty(obj.get("created_at"), f"{kind} {index}.created_at"),
        "updated_at": _nonempty(obj.get("updated_at"), f"{kind} {index}.updated_at"),
    }
    if kind == "review comment":
        result.update(
            {
                "path": _nonempty(obj.get("path"), f"{kind} {index}.path"),
                "commit_id": _nonempty(
                    obj.get("commit_id"), f"{kind} {index}.commit_id"
                ),
            }
        )
    return result


def _normalize_review(value: Any, index: int) -> JsonObject:
    obj = _object(value, f"review {index}")
    return {
        "id": _positive_int(obj.get("id"), f"review {index}.id"),
        "author": _identity(obj.get("user"), f"review {index}.user"),
        "body": _field(obj, "body", str, f"review {index}"),
        "state": _nonempty(obj.get("state"), f"review {index}.state"),
        "commit_id": _nullable_string(obj, "commit_id", f"review {index}"),
        "submitted_at": _nullable_string(obj, "submitted_at", f"review {index}"),
    }


def _normalize_check(value: Any, index: int, head_sha: str) -> JsonObject:
    obj = _object(value, f"check run {index}")
    app = _object(obj.get("app"), f"check run {index}.app")
    check_head = _nonempty(obj.get("head_sha"), f"check run {index}.head_sha")
    return {
        "id": _positive_int(obj.get("id"), f"check run {index}.id"),
        "name": _nonempty(obj.get("name"), f"check run {index}.name"),
        "head_sha": check_head,
        "status": _nonempty(obj.get("status"), f"check run {index}.status"),
        "conclusion": _nullable_string(obj, "conclusion", f"check run {index}"),
        "app": {
            "id": _positive_int(app.get("id"), f"check run {index}.app.id"),
            "slug": _nonempty(app.get("slug"), f"check run {index}.app.slug"),
            "name": _nonempty(app.get("name"), f"check run {index}.app.name"),
        },
        "exact_head": check_head == head_sha,
    }


def _normalize_status(value: Any, index: int, head_sha: str) -> JsonObject:
    obj = _object(value, f"status {index}")
    sha = _nonempty(obj.get("sha"), f"status {index}.sha")
    return {
        "id": _positive_int(obj.get("id"), f"status {index}.id"),
        "context": _nonempty(obj.get("context"), f"status {index}.context"),
        "sha": sha,
        "state": _nonempty(obj.get("state"), f"status {index}.state"),
        "creator": _identity(obj.get("creator"), f"status {index}.creator"),
        "exact_head": sha == head_sha,
    }


def _normalize_workflow(value: Any, index: int, head_sha: str) -> JsonObject:
    obj = _object(value, f"workflow run {index}")
    workflow_head = _nonempty(obj.get("head_sha"), f"workflow run {index}.head_sha")
    return {
        "id": _positive_int(obj.get("id"), f"workflow run {index}.id"),
        "workflow_id": _positive_int(
            obj.get("workflow_id"), f"workflow run {index}.workflow_id"
        ),
        "path": _nonempty(obj.get("path"), f"workflow run {index}.path"),
        "name": _nonempty(obj.get("name"), f"workflow run {index}.name"),
        "head_sha": workflow_head,
        "status": _nonempty(obj.get("status"), f"workflow run {index}.status"),
        "conclusion": _nullable_string(obj, "conclusion", f"workflow run {index}"),
        "exact_head": workflow_head == head_sha,
    }


def _normalize_ruleset(value: Any, source: str) -> JsonObject:
    obj = _object(value, source)
    conditions = _object(obj.get("conditions"), f"{source}.conditions")
    ref_name = _object(conditions.get("ref_name"), f"{source}.conditions.ref_name")
    bypass_actors_visible = "bypass_actors" in obj
    bypass_actors_value = obj.get("bypass_actors", [])
    return {
        "id": _positive_int(obj.get("id"), f"{source}.id"),
        "name": _nonempty(obj.get("name"), f"{source}.name"),
        "target": _nonempty(obj.get("target"), f"{source}.target"),
        "enforcement": _nonempty(obj.get("enforcement"), f"{source}.enforcement"),
        "conditions": {
            "ref_name": {
                "include": sorted(
                    _nonempty(item, f"{source}.conditions.ref_name.include")
                    for item in _list(ref_name.get("include"), f"{source}.include")
                ),
                "exclude": sorted(
                    _nonempty(item, f"{source}.conditions.ref_name.exclude")
                    for item in _list(ref_name.get("exclude"), f"{source}.exclude")
                ),
            }
        },
        "rules": _stable(
            [
                _object(item, f"{source}.rule")
                for item in _list(obj.get("rules"), f"{source}.rules")
            ]
        ),
        "bypass_actors": _stable(
            [
                _object(item, f"{source}.bypass_actor")
                for item in _list(bypass_actors_value, f"{source}.bypass_actors")
            ]
        ),
        "bypass_actors_visible": bypass_actors_visible,
    }


def _normalize_protection(
    protection_value: Any,
    effective_rules_value: Any,
    rulesets: list[JsonObject],
) -> JsonObject:
    protection = _object(protection_value, "branch protection")
    required = _object(
        protection.get("required_status_checks"),
        "branch protection.required_status_checks",
    )
    required_checks = []
    for index, value in enumerate(
        _list(required.get("checks"), "required_status_checks.checks")
    ):
        item = _object(value, f"required check {index}")
        required_checks.append(
            {
                "context": _nonempty(
                    item.get("context"), f"required check {index}.context"
                ),
                "app_id": _positive_int(
                    item.get("app_id"), f"required check {index}.app_id"
                ),
            }
        )
    contexts = sorted(
        _nonempty(item, "required_status_checks.context")
        for item in _list(required.get("contexts"), "required_status_checks.contexts")
    )
    resolution = _object(
        protection.get("required_conversation_resolution"),
        "branch protection.required_conversation_resolution",
    )
    effective_rules = []
    for index, value in enumerate(_list(effective_rules_value, "effective rules")):
        item = _object(value, f"effective rule {index}")
        effective_rules.append(
            {
                "type": _nonempty(item.get("type"), f"effective rule {index}.type"),
                "ruleset_id": _positive_int(
                    item.get("ruleset_id"), f"effective rule {index}.ruleset_id"
                ),
                "ruleset_source_type": _nonempty(
                    item.get("ruleset_source_type"),
                    f"effective rule {index}.ruleset_source_type",
                ),
                "ruleset_source": _nonempty(
                    item.get("ruleset_source"), f"effective rule {index}.ruleset_source"
                ),
            }
        )
    return {
        "required_status_checks": {
            "strict": _field(required, "strict", bool, "required_status_checks"),
            "contexts": contexts,
            "checks": _stable(required_checks),
        },
        "required_conversation_resolution": _field(
            resolution, "enabled", bool, "required_conversation_resolution"
        ),
        "effective_rules": _stable(effective_rules),
        "rulesets": _stable(rulesets),
    }


def collect_snapshot(
    repo: str,
    number: int,
    *,
    runner: Runner = run_command,
    now: Callable[[], datetime] | None = None,
) -> JsonObject:
    """Collect one complete, normalized observation from GitHub."""
    if repo.count("/") != 1 or any(not part for part in repo.split("/")):
        raise ReviewError("repository must use OWNER/REPO form")
    if number <= 0:
        raise ReviewError("pull request number must be positive")
    owner, name = repo.split("/", 1)
    client = GhClient(runner)
    repository = _object(client.rest_json(f"repos/{repo}"), "repository")
    full_name = _nonempty(repository.get("full_name"), "repository.full_name")
    if full_name.casefold() != repo.casefold():
        raise ReviewError(f"resolved repository {full_name!r} does not match {repo!r}")
    default_branch = _nonempty(
        repository.get("default_branch"), "repository.default_branch"
    )
    branch = _object(
        client.rest_json(f"repos/{repo}/branches/{quote(default_branch, safe='')}"),
        "default branch",
    )
    default_sha = _nonempty(
        _object(branch.get("commit"), "default branch.commit").get("sha"),
        "default branch.commit.sha",
    )
    pr = _object(client.rest_json(f"repos/{repo}/pulls/{number}"), "pull request")
    if _field(pr, "number", int, "pull request") != number:
        raise ReviewError("GitHub returned a different pull request number")
    base = _object(pr.get("base"), "pull request.base")
    head = _object(pr.get("head"), "pull request.head")
    base_sha = _nonempty(base.get("sha"), "pull request.base.sha")
    head_sha = _nonempty(head.get("sha"), "pull request.head.sha")
    body = pr.get("body")
    if body is None:
        body = ""
    if not isinstance(body, str):
        raise ReviewError("pull request.body must be string or null")
    diff = client.rest_text(
        f"repos/{repo}/pulls/{number}", "application/vnd.github.diff"
    )

    commits = [
        _normalize_commit(value, index)
        for index, value in enumerate(
            client.rest_pages(f"repos/{repo}/pulls/{number}/commits")
        )
    ]
    files = [
        _normalize_file(value, index)
        for index, value in enumerate(
            client.rest_pages(f"repos/{repo}/pulls/{number}/files")
        )
    ]
    issue_comments = [
        _normalize_comment(value, index, "issue comment")
        for index, value in enumerate(
            client.rest_pages(f"repos/{repo}/issues/{number}/comments")
        )
    ]
    reviews = [
        _normalize_review(value, index)
        for index, value in enumerate(
            client.rest_pages(f"repos/{repo}/pulls/{number}/reviews")
        )
    ]
    review_comments = [
        _normalize_comment(value, index, "review comment")
        for index, value in enumerate(
            client.rest_pages(f"repos/{repo}/pulls/{number}/comments")
        )
    ]
    checks = [
        _normalize_check(value, index, head_sha)
        for index, value in enumerate(
            client.rest_pages(
                f"repos/{repo}/commits/{head_sha}/check-runs",
                wrapper="check_runs",
                parameters={"filter": "latest"},
            )
        )
    ]
    statuses = [
        _normalize_status(value, index, head_sha)
        for index, value in enumerate(
            client.rest_pages(f"repos/{repo}/commits/{head_sha}/statuses")
        )
    ]
    workflows = [
        _normalize_workflow(value, index, head_sha)
        for index, value in enumerate(
            client.rest_pages(
                f"repos/{repo}/actions/runs",
                wrapper="workflow_runs",
                parameters={"head_sha": head_sha},
            )
        )
    ]
    protection_raw = client.rest_json(
        f"repos/{repo}/branches/{quote(default_branch, safe='')}/protection"
    )
    effective_rules_raw = client.rest_pages(
        f"repos/{repo}/rules/branches/{quote(default_branch, safe='')}"
    )
    effective_rules = [
        _object(value, f"effective rule {index}")
        for index, value in enumerate(effective_rules_raw)
    ]
    effective_ruleset_ids = {
        _positive_int(value.get("ruleset_id"), "effective rule.ruleset_id")
        for value in effective_rules
    }
    ruleset_summaries = client.rest_pages(
        f"repos/{repo}/rulesets", parameters={"includes_parents": "true"}
    )
    summary_ids = {
        _positive_int(
            _object(value, f"ruleset summary {index}").get("id"),
            f"ruleset summary {index}.id",
        )
        for index, value in enumerate(ruleset_summaries)
    }
    if not effective_ruleset_ids.issubset(summary_ids):
        raise ReviewError("effective rules reference an undiscoverable ruleset")
    rulesets = []
    for ruleset_id in sorted(effective_ruleset_ids):
        detail = client.rest_json(
            f"repos/{repo}/rulesets/{ruleset_id}?includes_parents=true"
        )
        rulesets.append(_normalize_ruleset(detail, f"ruleset {ruleset_id}"))
    compare = _object(
        client.rest_json(f"repos/{repo}/compare/{default_sha}...{head_sha}"),
        "ancestry compare",
    )
    open_pr_values = client.rest_pages(
        f"repos/{repo}/pulls", parameters={"state": "open", "base": default_branch}
    )
    open_prs = []
    for index, value in enumerate(open_pr_values):
        item = _object(value, f"open pull request {index}")
        item_base = _object(item.get("base"), f"open pull request {index}.base")
        item_head = _object(item.get("head"), f"open pull request {index}.head")
        open_prs.append(
            {
                "number": _positive_int(item.get("number"), f"open PR {index}.number"),
                "base_ref": _nonempty(
                    item_base.get("ref"), f"open PR {index}.base.ref"
                ),
                "base_sha": _nonempty(
                    item_base.get("sha"), f"open PR {index}.base.sha"
                ),
                "head_ref": _nonempty(
                    item_head.get("ref"), f"open PR {index}.head.ref"
                ),
                "head_sha": _nonempty(
                    item_head.get("sha"), f"open PR {index}.head.sha"
                ),
                "author": _identity(item.get("user"), f"open PR {index}.user"),
            }
        )
    closing_nodes = client.graphql_connection(
        CLOSING_ISSUES_QUERY,
        {"owner": owner, "name": name, "number": number},
        "closingIssuesReferences",
    )
    closing_issues = []
    for index, value in enumerate(closing_nodes):
        closing_issues.append(
            {
                "number": _positive_int(
                    value.get("number"), f"closing issue {index}.number"
                ),
                "url": _nonempty(value.get("url"), f"closing issue {index}.url"),
            }
        )
    clock = now or (lambda: datetime.now(UTC))
    observed_at = clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": 1,
        "repository": {
            "full_name": full_name,
            "default_branch": default_branch,
            "default_sha": default_sha,
        },
        "observed_at": observed_at,
        "pull_request": {
            "number": number,
            "title": _nonempty(pr.get("title"), "pull request.title"),
            "url": _nonempty(pr.get("html_url"), "pull request.html_url"),
            "state": _nonempty(pr.get("state"), "pull request.state"),
            "draft": _field(pr, "draft", bool, "pull request"),
            "merged": _field(pr, "merged", bool, "pull request"),
            "mergeable_state": _nonempty(
                pr.get("mergeable_state"), "pull request.mergeable_state"
            ),
            "base_ref": _nonempty(base.get("ref"), "pull request.base.ref"),
            "base_sha": base_sha,
            "head_ref": _nonempty(head.get("ref"), "pull request.head.ref"),
            "head_sha": head_sha,
            "author": _identity(pr.get("user"), "pull request.user"),
            "merge_commit_sha": _nullable_string(
                pr, "merge_commit_sha", "pull request"
            ),
        },
        "body_sha256": _sha256(body),
        "diff_sha256": _sha256(diff),
        "commits": _stable(commits),
        "files": _stable(files),
        "issue_comments": _stable(issue_comments),
        "reviews": _stable(reviews),
        "review_comments": _stable(review_comments),
        "review_threads": _collect_review_threads(client, owner, name, number),
        "closing_issues": _stable(closing_issues),
        "checks": _stable(checks),
        "statuses": _stable(statuses),
        "workflows": _stable(workflows),
        "protection": _normalize_protection(protection_raw, effective_rules, rulesets),
        "ancestry": {
            "base": default_sha,
            "head": head_sha,
            "status": _nonempty(compare.get("status"), "ancestry compare.status"),
            "ahead_by": _field(compare, "ahead_by", int, "ancestry compare"),
            "behind_by": _field(compare, "behind_by", int, "ancestry compare"),
        },
        "open_prs": _stable(open_prs),
    }


def _validate_expected_collection(
    evidence: JsonObject, key: str, identity_key: str
) -> None:
    container = _object(evidence.get(key), key)
    items = _list(container.get("items"), f"{key}.items")
    empty_reason = container.get("empty_reason")
    if not items:
        _nonempty(empty_reason, f"{key}.empty_reason")
    elif empty_reason is not None and not isinstance(empty_reason, str):
        raise ReviewError(f"{key}.empty_reason must be string or null")
    for index, value in enumerate(items):
        item = _object(value, f"{key}[{index}]")
        _nonempty(item.get(identity_key), f"{key}[{index}].{identity_key}")
        if key == "expected_statuses":
            _identity(item.get("creator"), f"{key}[{index}].creator")
        else:
            _positive_int(item.get("workflow_id"), f"{key}[{index}].workflow_id")
            _nonempty(item.get("name"), f"{key}[{index}].name")


def validate_evidence(
    value: Any,
    *,
    repo: str | None = None,
    number: int | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> JsonObject:
    """Validate semantic evidence shape and optional evaluation binding."""
    evidence = _object(value, "semantic evidence")
    if evidence.get("schema_version") != 1:
        raise ReviewError("semantic evidence schema_version must be 1")
    evidence_repo = _nonempty(evidence.get("repository"), "evidence.repository")
    evidence_number = _positive_int(
        evidence.get("pull_request"), "evidence.pull_request"
    )
    evidence_base = _nonempty(evidence.get("base_sha"), "evidence.base_sha")
    evidence_head = _nonempty(evidence.get("head_sha"), "evidence.head_sha")
    if evidence.get("primary_verdict") != "Clean":
        raise ReviewError('semantic evidence primary_verdict must be exactly "Clean"')
    bindings = (
        (repo, evidence_repo, "repository"),
        (number, evidence_number, "pull request"),
        (base_sha, evidence_base, "base SHA"),
        (head_sha, evidence_head, "head SHA"),
    )
    for expected, actual, label in bindings:
        if expected is not None and expected != actual:
            raise ReviewError(f"semantic evidence {label} binding does not match")
    sources = _object(evidence.get("sources"), "evidence.sources")
    for category in SOURCE_CATEGORIES:
        records = _list(sources.get(category), f"evidence.sources.{category}")
        if not records:
            raise ReviewError(f"semantic evidence source {category} must not be empty")
        for index, value in enumerate(records):
            record = _object(value, f"sources.{category}[{index}]")
            if record.get("source") != "primary-agent":
                raise ReviewError(f"sources.{category}[{index}] must be primary-agent")
            reference = _nonempty(
                record.get("reference"), f"sources.{category}[{index}].reference"
            )
            if not reference.startswith(("https://", "http://")):
                raise ReviewError(
                    f"sources.{category}[{index}].reference must be an HTTP "
                    "URL or endpoint"
                )
            _nonempty(record.get("finding"), f"sources.{category}[{index}].finding")
    reviewers = _list(evidence.get("reviewers"), "evidence.reviewers")
    if not reviewers:
        raise ReviewError("semantic evidence reviewers must list considered reviewers")
    for index, value in enumerate(reviewers):
        reviewer = _object(value, f"reviewer {index}")
        _nonempty(reviewer.get("name"), f"reviewer {index}.name")
        required = _field(reviewer, "required", bool, f"reviewer {index}")
        _nonempty(reviewer.get("reason"), f"reviewer {index}.reason")
        if required and (
            reviewer.get("verdict") != "Clean"
            or reviewer.get("reviewed_head") != evidence_head
        ):
            raise ReviewError(
                f"required reviewer {reviewer['name']} must be Clean for "
                f"{evidence_head}"
            )
    expected_checks = _list(evidence.get("expected_checks"), "evidence.expected_checks")
    if not expected_checks:
        raise ReviewError("expected_checks must not be empty")
    for index, value in enumerate(expected_checks):
        item = _object(value, f"expected_checks[{index}]")
        _nonempty(item.get("name"), f"expected_checks[{index}].name")
        app = _object(item.get("app"), f"expected_checks[{index}].app")
        _positive_int(app.get("id"), f"expected_checks[{index}].app.id")
        _nonempty(app.get("slug"), f"expected_checks[{index}].app.slug")
        _nonempty(app.get("name"), f"expected_checks[{index}].app.name")
    _validate_expected_collection(evidence, "expected_statuses", "context")
    _validate_expected_collection(evidence, "expected_workflows", "path")
    return evidence


def _require_successful_check(check: JsonObject, label: str) -> None:
    if not check.get("exact_head", True):
        raise ReviewError(f"{label} is not attached to the exact head")
    if check.get("status") != "completed" or check.get("conclusion") != SUCCESS:
        raise ReviewError(f"{label} does not have a successful terminal result")


def evaluate_snapshot(snapshot_value: Any, evidence_value: Any) -> None:
    """Fail unless one observation satisfies every deterministic merge gate."""
    snapshot = _object(snapshot_value, "snapshot")
    repository = _object(snapshot.get("repository"), "snapshot.repository")
    pr = _object(snapshot.get("pull_request"), "snapshot.pull_request")
    _nonempty(pr.get("title"), "snapshot.pull_request.title")
    _nonempty(pr.get("url"), "snapshot.pull_request.url")
    repo = _nonempty(repository.get("full_name"), "snapshot.repository.full_name")
    number = _positive_int(pr.get("number"), "snapshot.pull_request.number")
    base_sha = _nonempty(pr.get("base_sha"), "snapshot.pull_request.base_sha")
    head_sha = _nonempty(pr.get("head_sha"), "snapshot.pull_request.head_sha")
    evidence = validate_evidence(
        evidence_value,
        repo=repo,
        number=number,
        base_sha=base_sha,
        head_sha=head_sha,
    )
    default_branch = _nonempty(
        repository.get("default_branch"), "snapshot.repository.default_branch"
    )
    default_sha = _nonempty(
        repository.get("default_sha"), "snapshot.repository.default_sha"
    )
    if pr.get("state") != "open" or pr.get("merged") is not False:
        raise ReviewError("pull request must be open and unmerged")
    if pr.get("draft") is not False:
        raise ReviewError("pull request must not be a draft")
    if pr.get("mergeable_state") != "clean":
        raise ReviewError("pull request merge state must be clean")
    if pr.get("base_ref") != default_branch:
        raise ReviewError("pull request does not target the current default branch")
    if base_sha != default_sha:
        raise ReviewError(
            "current default SHA does not equal the pull request base SHA"
        )
    author = pr.get("author")
    if not isinstance(author, dict):
        raise ReviewError("PR author identity is unresolved")
    normalized_author = _identity(author, "PR author identity")
    author_tuple = (
        normalized_author["login"],
        normalized_author["id"],
        normalized_author["type"],
    )
    if author_tuple != RENOVATE_IDENTITY:
        raise ReviewError("PR author identity is not the Renovate bot")
    commits = _list(snapshot.get("commits"), "snapshot.commits")
    if not commits:
        raise ReviewError("pull request has no commits")
    for index, value in enumerate(commits):
        commit = _object(value, f"commit {index}")
        if not isinstance(commit.get("author"), dict):
            raise ReviewError(
                f"commit author identity is unresolved for commit {index}"
            )
        commit_author = _identity(commit["author"], f"commit {index}.author")
        author_tuple = (
            commit_author["login"],
            commit_author["id"],
            commit_author["type"],
        )
        if author_tuple != RENOVATE_IDENTITY:
            raise ReviewError(
                f"commit author identity is not Renovate for commit {index}"
            )
        if not isinstance(commit.get("committer"), dict):
            raise ReviewError(
                f"commit committer identity is unresolved for commit {index}"
            )
        committer = _identity(commit["committer"], f"commit {index}.committer")
        identity_tuple = (committer["login"], committer["id"], committer["type"])
        if identity_tuple not in TRUSTED_COMMITTERS:
            raise ReviewError(f"commit {index} has an untrusted committer identity")
    ancestry = _object(snapshot.get("ancestry"), "snapshot.ancestry")
    if (
        ancestry.get("base") != default_sha
        or ancestry.get("head") != head_sha
        or ancestry.get("status") not in {"ahead", "identical"}
    ):
        raise ReviewError("current-base ancestry is not proven as ahead or identical")
    threads = _list(snapshot.get("review_threads"), "snapshot.review_threads")
    if any(
        _object(item, "review thread").get("is_resolved") is not True
        for item in threads
    ):
        raise ReviewError("pull request has an unresolved review thread")
    if _list(snapshot.get("closing_issues"), "snapshot.closing_issues"):
        raise ReviewError("pull request has a closing issue reference")

    checks = [
        _object(value, "check")
        for value in _list(snapshot.get("checks"), "snapshot.checks")
    ]
    statuses = [
        _object(value, "status")
        for value in _list(snapshot.get("statuses"), "snapshot.statuses")
    ]
    workflows = [
        _object(value, "workflow")
        for value in _list(snapshot.get("workflows"), "snapshot.workflows")
    ]
    expected_check_values = _list(evidence["expected_checks"], "expected_checks")
    expected_check_keys = {
        (
            _object(value, "expected check").get("name"),
            json.dumps(_object(value, "expected check").get("app"), sort_keys=True),
        )
        for value in expected_check_values
    }
    observed_check_keys = {
        (check.get("name"), json.dumps(check.get("app"), sort_keys=True))
        for check in checks
    }
    for expected_value in expected_check_values:
        expected = _object(expected_value, "expected check")
        matches = [
            check
            for check in checks
            if check.get("name") == expected.get("name")
            and check.get("app") == expected.get("app")
        ]
        if len(matches) != 1:
            if len(matches) > 1:
                raise ReviewError(
                    f"expected check {expected.get('name')!r} has duplicate or "
                    "ambiguous runs"
                )
            if any(check.get("name") == expected.get("name") for check in checks):
                raise ReviewError(
                    f"expected check {expected.get('name')!r} provider does not match"
                )
            raise ReviewError(f"expected check {expected.get('name')!r} is missing")
        _require_successful_check(matches[0], f"expected check {expected['name']!r}")
    if observed_check_keys != expected_check_keys:
        raise ReviewError("observed checks do not equal the expected evidence set")
    status_items = _object(evidence["expected_statuses"], "expected_statuses")["items"]
    expected_status_keys = {
        (
            _object(value, "expected status").get("context"),
            json.dumps(
                _object(value, "expected status").get("creator"), sort_keys=True
            ),
        )
        for value in status_items
    }
    observed_status_keys = {
        (status.get("context"), json.dumps(status.get("creator"), sort_keys=True))
        for status in statuses
    }
    for expected_value in status_items:
        expected = _object(expected_value, "expected status")
        matches = [
            status
            for status in statuses
            if status.get("context") == expected.get("context")
            and status.get("creator") == expected.get("creator")
        ]
        if len(matches) != 1:
            if any(
                status.get("context") == expected.get("context") for status in statuses
            ):
                raise ReviewError(
                    f"expected status {expected.get('context')!r} creator does "
                    "not match"
                )
            raise ReviewError(f"expected status {expected.get('context')!r} is missing")
        status = matches[0]
        if status.get("sha") != head_sha or status.get("state") != SUCCESS:
            raise ReviewError(
                f"expected status {expected.get('context')!r} is not successful "
                "on the exact head"
            )
    if observed_status_keys != expected_status_keys:
        raise ReviewError("observed statuses do not equal the expected evidence set")
    workflow_items = _object(evidence["expected_workflows"], "expected_workflows")[
        "items"
    ]
    expected_workflow_keys = {
        (
            _object(value, "expected workflow").get("path"),
            _object(value, "expected workflow").get("workflow_id"),
            _object(value, "expected workflow").get("name"),
        )
        for value in workflow_items
    }
    observed_workflow_keys = {
        (workflow.get("path"), workflow.get("workflow_id"), workflow.get("name"))
        for workflow in workflows
    }
    for expected_value in workflow_items:
        expected = _object(expected_value, "expected workflow")
        matches = [
            workflow
            for workflow in workflows
            if workflow.get("path") == expected.get("path")
            and workflow.get("workflow_id") == expected.get("workflow_id")
            and workflow.get("name") == expected.get("name")
        ]
        if len(matches) != 1:
            raise ReviewError(
                f"expected workflow {expected.get('path')!r} is missing or ambiguous"
            )
        if matches[0].get("head_sha") != head_sha:
            raise ReviewError(
                f"expected workflow {expected['path']!r} is not on the exact head"
            )
        _require_successful_check(matches[0], f"expected workflow {expected['path']!r}")
    if observed_workflow_keys != expected_workflow_keys:
        raise ReviewError("observed workflows do not equal the expected evidence set")

    protection = _object(snapshot.get("protection"), "snapshot.protection")
    required = _object(
        protection.get("required_status_checks"), "protection.required_status_checks"
    )
    required_checks = _list(required.get("checks"), "required_status_checks.checks")
    contexts = _list(required.get("contexts"), "required_status_checks.contexts")
    if not isinstance(protection.get("effective_rules"), list) or not isinstance(
        protection.get("rulesets"), list
    ):
        raise ReviewError("repository protection and rules evidence is incomplete")
    configured_contexts: set[str] = set()
    for required_value in required_checks:
        required_check = _object(required_value, "required check")
        context = _nonempty(required_check.get("context"), "required check.context")
        app_id = _positive_int(required_check.get("app_id"), "required check.app_id")
        configured_contexts.add(context)
        matches = [
            check
            for check in checks
            if check.get("name") == context
            and isinstance(check.get("app"), dict)
            and check["app"].get("id") == app_id
        ]
        if len(matches) != 1:
            raise ReviewError(
                f"required context {context!r} is missing or has the wrong provider"
            )
        _require_successful_check(matches[0], f"required context {context!r}")
    for context_value in contexts:
        context = _nonempty(context_value, "required context")
        if context in configured_contexts:
            continue
        expected_context_checks = [
            _object(value, "expected check")
            for value in expected_check_values
            if _object(value, "expected check").get("name") == context
        ]
        expected_context_statuses = [
            _object(value, "expected status")
            for value in status_items
            if _object(value, "expected status").get("context") == context
        ]
        if len(expected_context_checks) + len(expected_context_statuses) != 1:
            raise ReviewError(
                f"required context {context!r} has no unique expected provider binding"
            )
        # The exact provider, namespace, head, and terminal result were already
        # enforced by the expected-evidence loops above. This fallback only
        # proves that a legacy context without an API app binding maps to one
        # unambiguous provider-bound expected item.
    effective_ids = {
        _positive_int(
            _object(value, "effective rule").get("ruleset_id"),
            "effective rule.ruleset_id",
        )
        for value in protection["effective_rules"]
    }
    rulesets = {
        _positive_int(_object(value, "ruleset").get("id"), "ruleset.id"): _object(
            value, "ruleset"
        )
        for value in protection["rulesets"]
    }
    if not effective_ids.issubset(rulesets):
        raise ReviewError("effective repository ruleset details are incomplete")
    for ruleset_id in effective_ids:
        ruleset = rulesets[ruleset_id]
        ruleset_rules = _list(ruleset.get("rules"), "ruleset.rules")
        has_required_checks = any(
            _object(value, "ruleset rule").get("type") == "required_status_checks"
            for value in ruleset_rules
        )
        if has_required_checks and ruleset.get("bypass_actors_visible") is not True:
            raise ReviewError(
                "ruleset required-check bypass actors are not visible to the "
                "current GitHub credential"
            )
        for rule_value in ruleset_rules:
            rule = _object(rule_value, "ruleset rule")
            if rule.get("type") != "required_status_checks":
                continue
            parameters = _object(
                rule.get("parameters"), "ruleset required_status_checks.parameters"
            )
            for check_value in _list(
                parameters.get("required_status_checks"),
                "ruleset required_status_checks",
            ):
                required_check = _object(check_value, "ruleset required check")
                context = _nonempty(
                    required_check.get("context"), "ruleset required check.context"
                )
                app_id = _positive_int(
                    required_check.get("integration_id"),
                    "ruleset required check.integration_id",
                )
                matches = [
                    check
                    for check in checks
                    if check.get("name") == context
                    and isinstance(check.get("app"), dict)
                    and check["app"].get("id") == app_id
                ]
                if len(matches) != 1:
                    raise ReviewError(
                        f"ruleset-required context {context!r} is missing or "
                        "has the wrong provider"
                    )
                _require_successful_check(
                    matches[0], f"ruleset-required context {context!r}"
                )


def _without_timestamp(snapshot: JsonObject) -> JsonObject:
    normalized = copy.deepcopy(snapshot)
    normalized.pop("observed_at", None)
    return normalized


def _validate_snapshot_shape(snapshot: JsonObject) -> None:
    if snapshot.get("schema_version") != 1:
        raise ReviewError("snapshot schema_version must be 1")
    required_objects = ("repository", "pull_request", "protection", "ancestry")
    required_lists = (
        "commits",
        "files",
        "issue_comments",
        "reviews",
        "review_comments",
        "review_threads",
        "closing_issues",
        "checks",
        "statuses",
        "workflows",
        "open_prs",
    )
    for key in required_objects:
        _object(snapshot.get(key), f"snapshot.{key}")
    for key in required_lists:
        _list(snapshot.get(key), f"snapshot.{key}")
    _nonempty(snapshot.get("observed_at"), "snapshot.observed_at")
    _nonempty(snapshot.get("body_sha256"), "snapshot.body_sha256")
    _nonempty(snapshot.get("diff_sha256"), "snapshot.diff_sha256")


def stabilize(
    repo: str,
    number: int,
    evidence: JsonObject,
    collect: Collector,
    *,
    interval: int,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> JsonObject:
    """Require two equal, successful observations separated by the interval."""
    if interval < MINIMUM_INTERVAL:
        raise ReviewError(
            f"stability interval must be at least {MINIMUM_INTERVAL} seconds"
        )
    validate_evidence(evidence, repo=repo, number=number)
    first = collect()
    _validate_snapshot_shape(first)
    evaluate_snapshot(first, evidence)
    started = monotonic()
    sleeper(interval)
    second = collect()
    _validate_snapshot_shape(second)
    elapsed = monotonic() - started
    if elapsed < interval:
        raise ReviewError("monotonic stability interval was shorter than requested")
    if _without_timestamp(first) != _without_timestamp(second):
        raise ReviewError("merge-relevant evidence changed during stability interval")
    evaluate_snapshot(second, evidence)
    pr = _object(second["pull_request"], "second pull request")
    return {
        "schema_version": 1,
        "interval_seconds": interval,
        "elapsed_seconds": elapsed,
        "approved_identity": {
            "repository": repo,
            "pull_request": number,
            "base_sha": pr["base_sha"],
            "head_sha": pr["head_sha"],
        },
        "observations": [first, second],
    }


def validate_stability_bundle(
    value: Any, repo: str, number: int, evidence: JsonObject
) -> JsonObject:
    bundle = _object(value, "stability bundle")
    if bundle.get("schema_version") != 1:
        raise ReviewError("stability bundle schema_version must be 1")
    interval = bundle.get("interval_seconds")
    elapsed = bundle.get("elapsed_seconds")
    if not isinstance(interval, int) or interval < MINIMUM_INTERVAL:
        raise ReviewError("stability bundle interval is below 30 seconds")
    if not isinstance(elapsed, (int, float)) or elapsed < interval:
        raise ReviewError("stability bundle elapsed interval is insufficient")
    observations = _list(bundle.get("observations"), "stability observations")
    if len(observations) != 2:
        raise ReviewError("stability bundle must contain exactly two observations")
    first = _object(observations[0], "first observation")
    second = _object(observations[1], "second observation")
    _validate_snapshot_shape(first)
    _validate_snapshot_shape(second)
    evaluate_snapshot(first, evidence)
    evaluate_snapshot(second, evidence)
    if _without_timestamp(first) != _without_timestamp(second):
        raise ReviewError("stability observations are not equivalent")
    try:
        first_time = datetime.fromisoformat(first["observed_at"].replace("Z", "+00:00"))
        second_time = datetime.fromisoformat(
            second["observed_at"].replace("Z", "+00:00")
        )
    except (KeyError, AttributeError, ValueError) as exc:
        raise ReviewError("stability observation timestamps are invalid") from exc
    if first_time.tzinfo is None or second_time.tzinfo is None:
        raise ReviewError("stability observation timestamps must include UTC offsets")
    if (second_time - first_time).total_seconds() < interval:
        raise ReviewError("stability observation timestamps are too close")
    identity = _object(bundle.get("approved_identity"), "approved identity")
    second_pr = _object(second.get("pull_request"), "second pull request")
    expected_identity = {
        "repository": repo,
        "pull_request": number,
        "base_sha": second_pr.get("base_sha"),
        "head_sha": second_pr.get("head_sha"),
    }
    if identity != expected_identity:
        raise ReviewError(
            "stability approved identity does not match second observation"
        )
    validate_evidence(
        evidence,
        repo=repo,
        number=number,
        base_sha=identity["base_sha"],
        head_sha=identity["head_sha"],
    )
    return bundle


def merge_pull_request(
    repo: str,
    number: int,
    evidence: JsonObject,
    stability: JsonObject,
    collect: Collector,
    runner: Runner = run_command,
    *,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> JsonObject:
    """Restabilize live, merge the exact approved head, and prove reachability."""
    bundle = validate_stability_bundle(stability, repo, number, evidence)
    second = _object(bundle["observations"][1], "second observation")
    live_first = collect()
    _validate_snapshot_shape(live_first)
    evaluate_snapshot(live_first, evidence)
    if _without_timestamp(live_first) != _without_timestamp(second):
        raise ReviewError("merge-relevant evidence changed after stability")
    started = monotonic()
    sleeper(MINIMUM_INTERVAL)
    final = collect()
    _validate_snapshot_shape(final)
    elapsed = monotonic() - started
    if elapsed < MINIMUM_INTERVAL:
        raise ReviewError("live merge interval was shorter than 30 seconds")
    evaluate_snapshot(final, evidence)
    if _without_timestamp(final) != _without_timestamp(
        live_first
    ) or _without_timestamp(final) != _without_timestamp(second):
        raise ReviewError("merge-relevant evidence changed after stability")
    head_sha = _object(bundle["approved_identity"], "approved identity")["head_sha"]
    merge_argv = [
        "gh",
        "pr",
        "merge",
        str(number),
        "--repo",
        repo,
        "--squash",
        "--match-head-commit",
        head_sha,
    ]
    try:
        runner(merge_argv)
    except CommandError as exc:
        raise ReviewError(f"guarded merge failed and was not retried: {exc}") from exc
    client = GhClient(runner)
    merged_pr = _object(client.rest_json(f"repos/{repo}/pulls/{number}"), "merged PR")
    if merged_pr.get("merged") is not True or merged_pr.get("state") != "closed":
        raise ReviewError("merge command returned but pull request is not merged")
    merge_commit = _nonempty(
        merged_pr.get("merge_commit_sha"), "merged PR.merge_commit_sha"
    )
    default_branch = _object(second["repository"], "repository")["default_branch"]
    branch = _object(
        client.rest_json(f"repos/{repo}/branches/{quote(default_branch, safe='')}"),
        "post-merge default branch",
    )
    default_sha = _nonempty(
        _object(branch.get("commit"), "post-merge default branch.commit").get("sha"),
        "post-merge default branch.commit.sha",
    )
    comparison = _object(
        client.rest_json(f"repos/{repo}/compare/{merge_commit}...{default_sha}"),
        "post-merge comparison",
    )
    status = _nonempty(comparison.get("status"), "post-merge comparison.status")
    if status not in {"ahead", "identical"}:
        raise ReviewError(
            "merge commit is not reachable from the current default branch"
        )
    return {
        "schema_version": 1,
        "repository": repo,
        "pull_request": number,
        "approved_head_sha": head_sha,
        "merge_commit_sha": merge_commit,
        "default_branch": default_branch,
        "default_sha": default_sha,
        "reachability": status,
        "merged": True,
    }


def _load_json(path: Path, label: str) -> JsonObject:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReviewError(f"cannot read {label} {path}: {exc}") from exc
    return _object(_parse_json(raw, str(path)), label)


def _write_result(value: JsonObject, output: Path | None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    try:
        output.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        raise ReviewError(f"cannot write output {output}: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    snapshot_parser = subparsers.add_parser(
        "snapshot", help="collect a stable normalized GitHub observation"
    )
    stabilize_parser = subparsers.add_parser(
        "stabilize", help="gate two complete observations at least 30 seconds apart"
    )
    merge_parser = subparsers.add_parser(
        "merge", help="refresh, head-match squash merge, and prove reachability"
    )
    for subparser in (snapshot_parser, stabilize_parser, merge_parser):
        subparser.add_argument("--repo", required=True, metavar="OWNER/REPO")
        subparser.add_argument("--pr", required=True, type=int, metavar="NUMBER")
    snapshot_parser.add_argument("--output", type=Path)
    stabilize_parser.add_argument("--output", type=Path)
    stabilize_parser.add_argument("--evidence", required=True, type=Path)
    stabilize_parser.add_argument("--interval", type=int, default=30)
    merge_parser.add_argument("--evidence", required=True, type=Path)
    merge_parser.add_argument("--stability", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "snapshot":
            result = collect_snapshot(args.repo, args.pr)
        elif args.command == "stabilize":
            evidence = _load_json(args.evidence, "semantic evidence")
            result = stabilize(
                args.repo,
                args.pr,
                evidence,
                lambda: collect_snapshot(args.repo, args.pr),
                interval=args.interval,
            )
        elif args.command == "merge":
            evidence = _load_json(args.evidence, "semantic evidence")
            stability = _load_json(args.stability, "stability bundle")
            result = merge_pull_request(
                args.repo,
                args.pr,
                evidence,
                stability,
                lambda: collect_snapshot(args.repo, args.pr),
            )
        else:  # pragma: no cover - argparse enforces the command set.
            raise AssertionError(f"unexpected command: {args.command}")
        _write_result(result, getattr(args, "output", None))
    except ReviewError as exc:
        print(f"renovate-review: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
