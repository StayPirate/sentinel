"""Contract tests for the SMELT package maintainership endpoint.

Contract under test: docs/features/packages/package-maintainership.md
(SMELT Contract: Successful response, Missing and invalid responses) and
docs/data-sources.md (SMELT, Contract characteristics), verified against
sanitized live responses captured anonymously from the default
`SMELT_API_URL` on 2026-10-03 (docs/conventions.md, External Integration
Contract Verification). Every field the client validates or consumes is
asserted for name, nesting, type, and nullability.

The fixtures were chosen to cover direct users only, groups with members
only, both kinds across entries (with a cross-entry duplicate and a null
collective group email), a null individual email, an empty `data`, and
the HTTP 404 body for an unknown package. An omitted `email` and an
omitted `members` were not observable live (the SMELT serializer emits
their defaults); they are covered by the client unit tests only.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.support.smelt import (
    MAINTAINERSHIP_NOT_FOUND_FIXTURE,
    MAINTAINERSHIP_SUCCESS_FIXTURES,
    load_maintainership_fixture,
)

# Distinct lowercase non-null individual emails per fixture, counted on
# the raw capture before sanitization (the mapping preserves them).
_DISTINCT_EMAILS = {
    "users_only": 1,
    "groups_only": 4,
    "users_and_groups": 15,
    "null_email": 3,
    "empty": 0,
}


def _entries(name: str) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = load_maintainership_fixture(name)["data"]
    return data


def _people(entry: dict[str, Any]) -> list[dict[str, Any]]:
    members = [member for group in entry["groups"] for member in group["members"]]
    return [*entry["users"], *members]


def _individual_emails(name: str) -> list[str | None]:
    return [person["email"] for entry in _entries(name) for person in _people(entry)]


@pytest.mark.unit
class TestSuccessEnvelope:
    @pytest.mark.parametrize("name", MAINTAINERSHIP_SUCCESS_FIXTURES)
    def test_envelope_is_jsend_success_with_array_data(self, name: str) -> None:
        body = load_maintainership_fixture(name)

        assert isinstance(body, dict)
        assert set(body) == {"status", "data"}
        assert body["status"] == "success"
        assert isinstance(body["data"], list)

    def test_empty_package_returns_empty_data(self) -> None:
        assert load_maintainership_fixture("empty")["data"] == []


@pytest.mark.unit
class TestEntryShape:
    @pytest.mark.parametrize("name", MAINTAINERSHIP_SUCCESS_FIXTURES)
    def test_entries_are_objects_with_codestream_users_and_groups(
        self, name: str
    ) -> None:
        for entry in _entries(name):
            assert isinstance(entry, dict)
            assert set(entry) == {"codestream", "users", "groups"}
            assert isinstance(entry["codestream"], dict)
            assert isinstance(entry["users"], list)
            assert isinstance(entry["groups"], list)

    @pytest.mark.parametrize("name", MAINTAINERSHIP_SUCCESS_FIXTURES)
    def test_codestream_is_a_link_object(self, name: str) -> None:
        for entry in _entries(name):
            assert set(entry["codestream"]) == {"name", "url"}
            assert all(isinstance(v, str) for v in entry["codestream"].values())


@pytest.mark.unit
class TestPeopleShape:
    @pytest.mark.parametrize("name", MAINTAINERSHIP_SUCCESS_FIXTURES)
    def test_users_and_members_have_username_and_nullable_email(
        self, name: str
    ) -> None:
        for entry in _entries(name):
            for person in _people(entry):
                assert isinstance(person, dict)
                assert set(person) == {"username", "email"}
                assert isinstance(person["username"], str)
                assert person["email"] is None or isinstance(person["email"], str)

    @pytest.mark.parametrize("name", MAINTAINERSHIP_SUCCESS_FIXTURES)
    def test_groups_have_name_nullable_email_and_member_array(self, name: str) -> None:
        for entry in _entries(name):
            for group in entry["groups"]:
                assert isinstance(group, dict)
                assert set(group) == {"name", "email", "members"}
                assert isinstance(group["name"], str)
                assert group["email"] is None or isinstance(group["email"], str)
                assert isinstance(group["members"], list)

    @pytest.mark.parametrize("name", MAINTAINERSHIP_SUCCESS_FIXTURES)
    def test_distinct_lowercase_individual_emails_match_the_capture(
        self, name: str
    ) -> None:
        emails = {
            email.lower() for email in _individual_emails(name) if email is not None
        }

        assert len(emails) == _DISTINCT_EMAILS[name]


@pytest.mark.unit
class TestFixtureCoverage:
    """The captured set exercises every observable consumed variant."""

    def test_users_only_package_has_no_groups(self) -> None:
        entries = _entries("users_only")

        assert entries
        assert all(entry["users"] and not entry["groups"] for entry in entries)

    def test_groups_only_package_has_no_direct_users(self) -> None:
        entries = _entries("groups_only")

        assert entries
        assert all(entry["groups"] and not entry["users"] for entry in entries)

    def test_users_and_groups_package_has_both_kinds(self) -> None:
        entries = _entries("users_and_groups")

        assert any(entry["users"] for entry in entries)
        assert any(entry["groups"] for entry in entries)

    def test_an_email_repeats_across_entries_and_roles(self) -> None:
        emails = [e for e in _individual_emails("users_and_groups") if e is not None]

        assert len(emails) > len(set(emails))

    def test_collective_group_email_is_observed_null_and_string(self) -> None:
        group_emails = [
            group["email"]
            for name in MAINTAINERSHIP_SUCCESS_FIXTURES
            for entry in _entries(name)
            for group in entry["groups"]
        ]

        assert None in group_emails
        assert any(isinstance(email, str) for email in group_emails)

    def test_a_null_individual_email_is_observed(self) -> None:
        assert None in _individual_emails("null_email")


@pytest.mark.unit
class TestNotFoundEnvelope:
    def test_unknown_package_body_is_a_jsend_error_envelope(self) -> None:
        body = load_maintainership_fixture(MAINTAINERSHIP_NOT_FOUND_FIXTURE)

        assert isinstance(body, dict)
        assert set(body) == {"status", "data"}
        assert body["status"] == "error"
        assert isinstance(body["data"], str)
