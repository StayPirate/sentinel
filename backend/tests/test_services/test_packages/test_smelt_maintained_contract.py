"""Contract tests for the SMELT package-scoped maintained endpoint.

Contract under test: docs/features/packages/package-model.md (SMELT Query
for Package Resolution: Envelope and error handling, Entry validation,
Consumed fields) and docs/data-sources.md (SMELT, Contract
characteristics), verified against sanitized live responses captured
anonymously from the default `SMELT_API_URL` on 2026-10-03
(docs/conventions.md, External Integration Contract Verification). Every
field the client validates or consumes is asserted for name, nesting,
type, and nullability.

The fixtures cover an SLE 15-only package, an SLFO-only package, a package
with both maintenance processes, a package with Reactive LTSS targets
(proving `include_reactive_ltss=true`), an unknown package, and a case
variant of a known package (both HTTP 404). Not observable live, and
therefore covered by the client unit tests only: the `SLFO_IBS` and
`UNKNOWN` maintenance processes, HTTP 200 with an empty `data`, and an
absent, null, or empty `product.friendly_name`.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.support.smelt import (
    MAINTAINED_NOT_FOUND_FIXTURES,
    MAINTAINED_SUCCESS_FIXTURES,
    load_maintained_fixture,
)

# `MaintenanceProcessType` in the live `/api/experimental/v2/openapi.json`.
_DECLARED_TYPES = frozenset({"SLFO", "SLFO_IBS", "SLE_15", "UNKNOWN"})
_SUPPORTED_TYPES = frozenset({"SLFO", "SLE_15"})
# `TicketPackageTrack.reference` column length (docs/data-model.md).
_REFERENCE_LENGTH = 255
_FICTIONAL_URL_PREFIX = "https://build.example.invalid/"


def _entries(name: str) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = load_maintained_fixture(name)["data"]
    return data


def _types(name: str) -> set[str]:
    return {entry["codestream"]["type"] for entry in _entries(name)}


def _targets(name: str) -> list[dict[str, Any]]:
    return [target for entry in _entries(name) for target in entry["targets"]]


def _strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return [value] if isinstance(value, str) else []


@pytest.mark.unit
class TestSuccessEnvelope:
    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    def test_envelope_is_jsend_success_with_non_empty_array_data(
        self, name: str
    ) -> None:
        body = load_maintained_fixture(name)

        assert isinstance(body, dict)
        assert set(body) == {"status", "data"}
        assert body["status"] == "success"
        assert isinstance(body["data"], list)
        assert body["data"]


@pytest.mark.unit
class TestCodestreamShape:
    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    def test_entry_has_codestream_object_and_targets_array(self, name: str) -> None:
        for entry in _entries(name):
            assert isinstance(entry, dict)
            assert isinstance(entry["codestream"], dict)
            assert isinstance(entry["targets"], list)

    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    def test_codestream_name_is_a_bounded_non_empty_string(self, name: str) -> None:
        for entry in _entries(name):
            codestream_name = entry["codestream"]["name"]
            assert isinstance(codestream_name, str)
            assert 0 < len(codestream_name) <= _REFERENCE_LENGTH

    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    def test_codestream_names_are_unique_in_the_grouped_response(
        self, name: str
    ) -> None:
        names = [entry["codestream"]["name"] for entry in _entries(name)]

        assert len(names) == len(set(names))

    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    def test_codestream_type_is_a_declared_non_null_string(self, name: str) -> None:
        for entry in _entries(name):
            assert "type" in entry["codestream"]
            assert isinstance(entry["codestream"]["type"], str)
            assert entry["codestream"]["type"] in _DECLARED_TYPES


@pytest.mark.unit
class TestTargetShape:
    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    def test_supported_codestreams_have_non_empty_targets(self, name: str) -> None:
        for entry in _entries(name):
            assert entry["codestream"]["type"] in _SUPPORTED_TYPES
            assert entry["targets"]

    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    def test_target_product_cpe_is_a_non_empty_string(self, name: str) -> None:
        for target in _targets(name):
            assert isinstance(target, dict)
            assert isinstance(target["product"], dict)
            assert isinstance(target["product"]["cpe"], str)
            assert target["product"]["cpe"]

    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    def test_target_product_friendly_name_is_a_string(self, name: str) -> None:
        for target in _targets(name):
            assert isinstance(target["product"]["friendly_name"], str)

    @pytest.mark.parametrize("name", MAINTAINED_SUCCESS_FIXTURES)
    def test_unconsumed_fields_are_present_and_ignored(self, name: str) -> None:
        for entry in _entries(name):
            assert {"binary_packages", "support_status"} <= set(entry)
            assert "url" in entry["codestream"]
            for target in entry["targets"]:
                assert {"repository", "product_definition"} <= set(target)
                assert {"id", "support_status"} <= set(target["product"])


@pytest.mark.unit
class TestFixtureCoverage:
    """The captured set exercises every observable consumed variant."""

    def test_sle15_only_package_has_only_sle15_codestreams(self) -> None:
        assert _types("sle15_only") == {"SLE_15"}

    def test_slfo_only_package_has_only_slfo_codestreams(self) -> None:
        assert _types("slfo_only") == {"SLFO"}

    def test_mixed_package_has_both_supported_processes(self) -> None:
        assert _types("mixed") == {"SLFO", "SLE_15"}

    def test_reactive_ltss_targets_are_returned(self) -> None:
        statuses = {
            target["product"]["support_status"] for target in _targets("reactive_ltss")
        }

        assert "Reactive LTSS" in statuses

    def test_a_codestream_has_several_targets(self) -> None:
        assert any(len(entry["targets"]) > 1 for entry in _entries("reactive_ltss"))


@pytest.mark.unit
class TestNotFoundEnvelope:
    @pytest.mark.parametrize("name", MAINTAINED_NOT_FOUND_FIXTURES)
    def test_not_found_body_is_a_jsend_error_envelope(self, name: str) -> None:
        body = load_maintained_fixture(name)

        assert isinstance(body, dict)
        assert set(body) == {"status", "data"}
        assert body["status"] == "error"
        assert isinstance(body["data"], str)


@pytest.mark.unit
class TestSanitization:
    @pytest.mark.parametrize(
        "name", [*MAINTAINED_SUCCESS_FIXTURES, *MAINTAINED_NOT_FOUND_FIXTURES]
    )
    def test_fixture_retains_no_real_url_or_email(self, name: str) -> None:
        for value in _strings(load_maintained_fixture(name)):
            assert "@" not in value
            assert "suse.de" not in value
            if value.startswith(("http://", "https://")):
                assert value.startswith(_FICTIONAL_URL_PREFIX)
