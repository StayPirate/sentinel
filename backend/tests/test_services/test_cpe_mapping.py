"""Tests for the static CPE-to-package mapping parser, loader, and resolvers.

Owning specification: `docs/features/packages/cpe-package-mapping.md`
(Static Mapping File; CPE String Parsing; Resolution Function;
Verification) and the CPE canonical data row of
`docs/features/platform/testing-strategy.md` (Structural Tests). The
image suite separately asserts the resource is present in the final
image (`tests/image/test_image_build.py`).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import app
from app.services import cpe_mapping
from app.services.cpe_mapping import (
    CPEMappingLoadError,
    resolve_cpe_packages,
    resolve_vendor_product,
)
from tests.support.module_imports import APP_ROOT, imported_modules

pytestmark = pytest.mark.unit

_COMMITTED_MAPPING = APP_ROOT / "data" / "cpe-package-mapping.json"
_LOGGER_NAME = "app.services.cpe_mapping"
_TAIL = ":*:*:*:*:*:*:*:*"
"""The eight components following vendor and product in a wildcard CPE."""

_REWRITTEN_KEYS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "apache:xerces-c++": ("apache:xerces-c\\+\\+", "xerces-c++", ("xerces-c",)),
    "artsoft:rocks'n'diamonds": (
        "artsoft:rocks\\'n\\'diamonds",
        "rocks'n'diamonds",
        ("rocksndiamonds",),
    ),
    "cpan:file\\:\\:temp": ("cpan:file\\", "file::temp", ("perl-File-Temp",)),
    "criu:checkpoint/restore_in_userspace": (
        "criu:checkpoint\\/restore_in_userspace",
        "checkpoint/restore_in_userspace",
        ("criu",),
    ),
    "erlang:erlang/otp": ("erlang:erlang\\/otp", "erlang/otp", ("erlang", "erlang26")),
    "timidity++_project:timidity++": (
        "timidity\\\\+\\\\+_project:timidity\\\\+\\\\+",
        "timidity++",
        ("timidity",),
    ),
}
"""Canonical key -> (replaced committed key, decoded product, packages)."""

_ONE_SEPARATOR = "expected exactly one unescaped ':' separator"
_NOT_NORMALIZED = "vendor or product is not lowercase and trimmed"
_NOT_CANONICAL = "key is not in canonical serialization"
_MARKER = "secret-package-marker"
"""A package value that must never appear in a load-error message."""


def _cpe(vendor: str, product: str) -> str:
    """A wildcard CPE 2.3 string from already-encoded vendor/product fields."""
    return f"cpe:2.3:a:{vendor}:{product}{_TAIL}"


def _warnings(caplog: pytest.LogCaptureFixture, event: str) -> list[dict[str, Any]]:
    """Structured WARNING records of `event` emitted by the mapping module."""
    return [
        record.msg
        for record in caplog.records
        if record.name == _LOGGER_NAME
        and record.levelno == logging.WARNING
        and isinstance(record.msg, dict)
        and record.msg.get("event") == event
    ]


def _decode_key(key: str) -> tuple[str, str]:
    components = cpe_mapping._split_components(key)
    assert len(components) == 2
    return components[0].value, components[1].value


@pytest.fixture(autouse=True)
def _clear_mapping_cache() -> Iterator[None]:
    """Isolate the process-local mapping cache between tests."""
    cpe_mapping._load_mapping.cache_clear()
    yield
    cpe_mapping._load_mapping.cache_clear()


@pytest.fixture
def mapping_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[[bytes | str], Path]:
    """Point the loader at a temporary file with the given contents."""
    path = tmp_path / "cpe-package-mapping.json"
    monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: path)

    def _write(content: bytes | str) -> Path:
        data = content.encode() if isinstance(content, str) else content
        path.write_bytes(data)
        return path

    return _write


@pytest.fixture
def forbid_mapping_load(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if a resolver loads the mapping."""

    def _unexpected_load() -> dict[str, tuple[str, ...]]:
        raise AssertionError("the mapping must not be loaded")

    monkeypatch.setattr(cpe_mapping, "_load_mapping", _unexpected_load)


@pytest.fixture
def stub_mapping(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[str]]:
    """Replace the loader with an in-memory mapping and record lookups."""

    def _install(mapping: dict[str, tuple[str, ...]]) -> list[str]:
        requested: list[str] = []

        class _Recording(dict[str, tuple[str, ...]]):
            def get(self, key: str, default: Any = None) -> Any:
                requested.append(key)
                return super().get(key, default)

        recording = _Recording(mapping)
        monkeypatch.setattr(cpe_mapping, "_load_mapping", lambda: recording)
        return requested

    return _install


class _FailingResource:
    """A resource whose read raises the given exception."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.reads = 0

    def read_bytes(self) -> bytes:
        self.reads += 1
        raise self._exc

    def __str__(self) -> str:
        return "/fictional/app/data/cpe-package-mapping.json"


# --- Committed mapping file (CI validation) ---------------------------------


class TestCommittedMappingFile:
    def test_is_utf8_json_object_without_textual_duplicate_keys(self) -> None:
        pairs = json.loads(
            _COMMITTED_MAPPING.read_bytes().decode("utf-8"),
            object_pairs_hook=lambda items: items,
        )
        assert isinstance(pairs, list)
        keys = [key for key, _ in pairs]
        assert keys
        assert len(keys) == len(set(keys))

    def test_every_key_round_trips_canonically(self) -> None:
        mapping = json.loads(_COMMITTED_MAPPING.read_text(encoding="utf-8"))
        invalid = {
            key: violation
            for key in mapping
            if (violation := cpe_mapping._key_rule_violation(key)) is not None
        }
        assert invalid == {}
        for key in mapping:
            assert cpe_mapping._canonical_key(*_decode_key(key)) == key

    def test_no_two_keys_decode_to_the_same_pair(self) -> None:
        mapping = json.loads(_COMMITTED_MAPPING.read_text(encoding="utf-8"))
        pairs = [_decode_key(key) for key in mapping]
        assert len(pairs) == len(set(pairs))

    def test_keys_are_sorted_by_raw_canonical_text(self) -> None:
        mapping = json.loads(_COMMITTED_MAPPING.read_text(encoding="utf-8"))
        keys = list(mapping)
        assert keys == sorted(keys)

    def test_every_value_is_a_non_empty_list_of_trimmed_strings(self) -> None:
        mapping = json.loads(_COMMITTED_MAPPING.read_text(encoding="utf-8"))
        invalid = {
            key: violation
            for key, value in mapping.items()
            if (violation := cpe_mapping._package_rule_violation(value)) is not None
        }
        assert invalid == {}

    def test_loads_through_the_runtime_loader(self) -> None:
        raw = json.loads(_COMMITTED_MAPPING.read_text(encoding="utf-8"))
        loaded = cpe_mapping._load_mapping()
        assert loaded == {key: tuple(value) for key, value in raw.items()}
        assert all(isinstance(value, tuple) for value in loaded.values())

    def test_six_rewritten_keys_are_canonical_with_unchanged_packages(self) -> None:
        mapping = json.loads(_COMMITTED_MAPPING.read_text(encoding="utf-8"))
        for key, (replaced, product, packages) in _REWRITTEN_KEYS.items():
            assert replaced not in mapping
            assert tuple(mapping[key]) == packages
            vendor, decoded_product = _decode_key(key)
            assert decoded_product == product
            assert "\\" not in vendor
            assert "\\" not in decoded_product


# --- CPE string parsing -----------------------------------------------------


class TestParseCPE:
    @pytest.mark.parametrize(
        ("cpe", "expected"),
        [
            pytest.param(
                "cpe:2.3:a:apache:commons_compress:1.21:*:*:*:*:*:*:*",
                ("apache", "commons_compress"),
                id="standard",
            ),
            pytest.param(
                _cpe("apache", "xerces-c\\+\\+"),
                ("apache", "xerces-c++"),
                id="escaped-plus",
            ),
            pytest.param(
                _cpe("artsoft", "rocks\\'n\\'diamonds"),
                ("artsoft", "rocks'n'diamonds"),
                id="escaped-apostrophe",
            ),
            pytest.param(
                _cpe("criu", "checkpoint\\/restore_in_userspace"),
                ("criu", "checkpoint/restore_in_userspace"),
                id="escaped-slash",
            ),
            pytest.param(
                _cpe("cpan", "file\\:\\:temp"),
                ("cpan", "file::temp"),
                id="escaped-colon",
            ),
            pytest.param(
                _cpe("example", "path\\\\name"),
                ("example", "path\\name"),
                id="escaped-backslash",
            ),
            pytest.param(
                "cpe:2.3:a:example:product:1\\:2:*:*:*:*:*:*:*",
                ("example", "product"),
                id="escaped-colon-in-version-keeps-indexes",
            ),
            pytest.param(
                _cpe(" Example ", " Some Product "),
                ("example", "some product"),
                id="trim-lowercase-keep-internal-space",
            ),
            pytest.param(
                _cpe("\\*", "\\-"),
                ("*", "-"),
                id="escaped-any-and-na-are-literal",
            ),
            pytest.param(_cpe("*", "emacs"), (None, "emacs"), id="vendor-any"),
            pytest.param(_cpe("-", "emacs"), (None, "emacs"), id="vendor-na"),
            pytest.param(_cpe("", "emacs"), (None, "emacs"), id="vendor-empty"),
            pytest.param(_cpe("gnu", "*"), ("gnu", None), id="product-any"),
            pytest.param(_cpe("gnu", "-"), ("gnu", None), id="product-na"),
            pytest.param(_cpe("gnu", ""), ("gnu", None), id="product-empty"),
            pytest.param(_cpe("gnu", "  "), ("gnu", None), id="product-blank"),
        ],
    )
    def test_decodes_vendor_and_product(
        self, cpe: str, expected: tuple[str | None, str | None]
    ) -> None:
        assert cpe_mapping._parse_cpe(cpe) == expected

    @pytest.mark.parametrize(
        ("cpe", "reason"),
        [
            pytest.param(
                "cpe:/a:apache:commons_compress:1.21",
                "missing_cpe23_prefix",
                id="cpe-2.2",
            ),
            pytest.param("", "missing_cpe23_prefix", id="empty"),
            pytest.param(
                "CPE:2.3:a:gnu:emacs" + _TAIL, "missing_cpe23_prefix", id="uppercase"
            ),
            pytest.param(_cpe("gnu", "emacs") + "\\", "unpaired_escape", id="unpaired"),
            pytest.param(
                "cpe:2.3:a:cpan:file\\", "unpaired_escape", id="truncated-escape"
            ),
            pytest.param(
                "cpe:2.3:a:gnu:emacs:*:*:*:*:*:*:*",
                "wrong_component_count",
                id="ten-components",
            ),
            pytest.param(
                _cpe("gnu", "emacs") + ":*",
                "wrong_component_count",
                id="twelve-components",
            ),
        ],
    )
    def test_rejects_malformed_strings(self, cpe: str, reason: str) -> None:
        with pytest.raises(cpe_mapping._CPEParseError) as excinfo:
            cpe_mapping._parse_cpe(cpe)
        assert excinfo.value.reason == reason

    @pytest.mark.parametrize(
        ("vendor", "product", "key"),
        [
            ("apache", "xerces-c++", "apache:xerces-c++"),
            (
                "criu",
                "checkpoint/restore_in_userspace",
                "criu:checkpoint/restore_in_userspace",
            ),
            ("cpan", "file::temp", "cpan:file\\:\\:temp"),
            ("example", "path\\name", "example:path\\\\name"),
            ("a:b", "c\\:d", "a\\:b:c\\\\\\:d"),
        ],
    )
    def test_canonical_key_serialization_is_reversible(
        self, vendor: str, product: str, key: str
    ) -> None:
        assert cpe_mapping._canonical_key(vendor, product) == key
        assert _decode_key(key) == (vendor, product)


# --- Loader by file state ---------------------------------------------------


class TestLoaderFileStates:
    def test_absent_file_logs_absent_and_returns_empty(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        path = tmp_path / "missing.json"
        monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: path)
        with caplog.at_level(logging.WARNING):
            assert cpe_mapping._load_mapping() == {}
        records = _warnings(caplog, "cpe_mapping_absent")
        assert [record["path"] for record in records] == [str(path)]

    def test_not_a_directory_is_treated_as_absent(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        (tmp_path / "data").write_text("not a directory", encoding="utf-8")
        path = tmp_path / "data" / "cpe-package-mapping.json"
        monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: path)
        with caplog.at_level(logging.WARNING):
            assert cpe_mapping._load_mapping() == {}
        assert len(_warnings(caplog, "cpe_mapping_absent")) == 1

    @pytest.mark.parametrize(
        "content",
        [b"", b" ", b"\n", b" \t\r\n  \n"],
        ids=["zero-bytes", "space", "newline", "mixed-whitespace"],
    )
    def test_empty_or_whitespace_file_is_treated_as_absent(
        self,
        mapping_file: Callable[[bytes | str], Path],
        caplog: pytest.LogCaptureFixture,
        content: bytes,
    ) -> None:
        path = mapping_file(content)
        with caplog.at_level(logging.WARNING):
            assert cpe_mapping._load_mapping() == {}
        records = _warnings(caplog, "cpe_mapping_absent")
        assert [record["path"] for record in records] == [str(path)]
        assert _warnings(caplog, "cpe_mapping_empty") == []

    @pytest.mark.parametrize(
        "content",
        ["{}", "{ }", "{\n}\n", "  {}  "],
        ids=["compact", "space", "pretty", "padded"],
    )
    def test_empty_object_logs_empty_and_returns_empty(
        self,
        mapping_file: Callable[[bytes | str], Path],
        caplog: pytest.LogCaptureFixture,
        content: str,
    ) -> None:
        path = mapping_file(content)
        with caplog.at_level(logging.WARNING):
            assert cpe_mapping._load_mapping() == {}
        records = _warnings(caplog, "cpe_mapping_empty")
        assert [record["path"] for record in records] == [str(path)]
        assert _warnings(caplog, "cpe_mapping_absent") == []

    def test_valid_file_returns_tuples_and_accepts_unsorted_keys(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        mapping_file(
            '{"gnu:emacs": ["emacs"], "cpan:file\\\\:\\\\:temp": ["perl-File-Temp"],'
            ' "example:path\\\\\\\\name": ["alpha", "beta"]}'
        )
        assert cpe_mapping._load_mapping() == {
            "gnu:emacs": ("emacs",),
            "cpan:file\\:\\:temp": ("perl-File-Temp",),
            "example:path\\\\name": ("alpha", "beta"),
        }


class TestLoaderValidation:
    @pytest.mark.parametrize(
        ("content", "reason"),
        [
            pytest.param(
                b'{"gnu:emacs": ["\xff"]}',
                "rule 1 (valid UTF-8): invalid byte at offset 16",
                id="invalid-utf8",
            ),
            pytest.param(
                '{"gnu:emacs": [',
                "rule 2 (valid JSON): syntax error at line 1",
                id="truncated",
            ),
            pytest.param(
                '{"gnu:emacs": NaN}',
                "rule 2 (valid JSON): syntax error",
                id="nan-constant",
            ),
            pytest.param(
                '\ufeff{"gnu:emacs": ["emacs"]}', "rule 2 (valid JSON)", id="utf8-bom"
            ),
            pytest.param(
                "[]", "rule 3 (object root): root is a JSON array", id="array"
            ),
            pytest.param(
                '"x"', "rule 3 (object root): root is a JSON string", id="string"
            ),
            pytest.param(
                "null", "rule 3 (object root): root is a JSON null", id="null"
            ),
            pytest.param(
                "7", "rule 3 (object root): root is a JSON number", id="number"
            ),
            pytest.param(
                "true", "rule 3 (object root): root is a JSON boolean", id="bool"
            ),
        ],
    )
    def test_unparseable_content_raises(
        self,
        mapping_file: Callable[[bytes | str], Path],
        content: bytes | str,
        reason: str,
    ) -> None:
        path = mapping_file(content)
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        message = str(excinfo.value)
        assert message.startswith(f"CPE mapping load failed at {path}: {reason}")
        assert excinfo.value.path == str(path)
        assert "emacs" not in message

    def test_invalid_utf8_does_not_chain_the_decoder_error(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        mapping_file(b'{"gnu:emacs": ["\xff"]}')
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__

    def test_duplicate_textual_key_raises_rule_4(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        mapping_file('{"gnu:emacs": ["emacs"], "gnu:emacs": ["secret-package-marker"]}')
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        assert excinfo.value.reason == "rule 4 (duplicate key): 'gnu:emacs'"
        assert _MARKER not in str(excinfo.value)

    def test_duplicate_key_is_reported_before_a_non_canonical_key(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        mapping_file('{"Gnu:emacs": ["emacs"], "a:b": ["b"], "a:b": ["b"]}')
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        assert excinfo.value.reason.startswith("rule 4 ")

    @pytest.mark.parametrize(
        ("key", "detail"),
        [
            pytest.param("emacs", _ONE_SEPARATOR, id="no-separator"),
            pytest.param("gnu\\:emacs", _ONE_SEPARATOR, id="escaped-separator-only"),
            pytest.param("a:b:c", _ONE_SEPARATOR, id="two-separators"),
            pytest.param(":emacs", "empty vendor or product", id="empty-vendor"),
            pytest.param("gnu:", "empty vendor or product", id="empty-product"),
            pytest.param("cpan:file\\", "unpaired escape", id="unpaired-escape"),
            pytest.param("Gnu:emacs", _NOT_NORMALIZED, id="uppercase"),
            pytest.param(" gnu:emacs", _NOT_NORMALIZED, id="untrimmed"),
            pytest.param(
                "apache:xerces-c\\+\\+", _NOT_CANONICAL, id="formatted-string-escape"
            ),
        ],
    )
    def test_non_canonical_key_raises_rule_5(
        self,
        mapping_file: Callable[[bytes | str], Path],
        key: str,
        detail: str,
    ) -> None:
        mapping_file(json.dumps({"gnu:emacs": ["emacs"], key: [_MARKER]}))
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        assert excinfo.value.reason == (
            f"rule 5 (canonical key) failed for key {key!r}: {detail}"
        )
        assert _MARKER not in str(excinfo.value)

    def test_semantic_duplicate_spelling_is_rejected_by_rule_5(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        mapping_file(
            json.dumps(
                {
                    "apache:xerces-c++": ["xerces-c"],
                    "apache:xerces-c\\+\\+": ["xerces-c"],
                }
            )
        )
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        assert excinfo.value.reason.startswith(
            "rule 5 (canonical key) failed for key 'apache:xerces-c\\\\+\\\\+'"
        )

    def test_key_rule_is_checked_before_value_rule(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        mapping_file('{"gnu:emacs": [], "Bad:key": ["b"]}')
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        assert excinfo.value.reason.startswith("rule 5 ")

    @pytest.mark.parametrize(
        ("value", "detail"),
        [
            pytest.param(
                '"secret-package-marker"',
                "value is a JSON string, not an array",
                id="string",
            ),
            pytest.param(
                '{"secret-package-marker": []}',
                "value is a JSON object, not an array",
                id="object",
            ),
            pytest.param("null", "value is a JSON null, not an array", id="null"),
            pytest.param("[]", "array is empty", id="empty-array"),
            pytest.param(
                '["secret-package-marker", 7]',
                "element 1 is a JSON number",
                id="number-element",
            ),
            pytest.param(
                '["secret-package-marker", null]',
                "element 1 is a JSON null",
                id="null-element",
            ),
            pytest.param(
                '[["secret-package-marker"]]',
                "element 0 is a JSON array",
                id="nested-array",
            ),
            pytest.param(
                '["secret-package-marker", ""]', "element 1 is empty", id="empty-string"
            ),
            pytest.param('["  "]', "element 0 is empty", id="blank-string"),
            pytest.param(
                '[" secret-package-marker"]',
                "element 0 has leading or trailing whitespace",
                id="untrimmed",
            ),
        ],
    )
    def test_invalid_package_list_raises_rule_6(
        self,
        mapping_file: Callable[[bytes | str], Path],
        value: str,
        detail: str,
    ) -> None:
        mapping_file(f'{{"gnu:emacs": ["emacs"], "alsa-project:alsa": {value}}}')
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        assert excinfo.value.reason == (
            f"rule 6 (package list) failed for key 'alsa-project:alsa': {detail}"
        )
        assert _MARKER not in str(excinfo.value)


class TestLoaderIOErrors:
    @pytest.mark.parametrize(
        "exc",
        [PermissionError(13, "Permission denied"), OSError(5, "Input/output error")],
        ids=["permission", "generic-oserror"],
    )
    def test_os_error_is_wrapped(
        self, monkeypatch: pytest.MonkeyPatch, exc: OSError
    ) -> None:
        resource = _FailingResource(exc)
        monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: resource)
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        assert str(excinfo.value) == (
            f"CPE mapping load failed at {resource}: rule 1 (readable): "
            f"{type(exc).__name__}: {exc}"
        )
        assert excinfo.value.__cause__ is exc

    def test_directory_at_resource_path_is_wrapped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "cpe-package-mapping.json"
        path.mkdir()
        monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: path)
        with pytest.raises(CPEMappingLoadError) as excinfo:
            cpe_mapping._load_mapping()
        assert isinstance(excinfo.value.__cause__, IsADirectoryError)
        assert excinfo.value.reason.startswith("rule 1 (readable): IsADirectoryError")

    @pytest.mark.parametrize(
        "exc", [MemoryError(), KeyboardInterrupt()], ids=["memory", "interrupt"]
    )
    def test_non_os_errors_propagate_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, exc: BaseException
    ) -> None:
        resource = _FailingResource(exc)
        monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: resource)
        with pytest.raises(type(exc)) as excinfo:
            cpe_mapping._load_mapping()
        assert excinfo.value is exc


class TestLoaderCache:
    def test_successful_load_is_cached_without_further_io(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        path = mapping_file('{"gnu:emacs": ["emacs"]}')
        first = cpe_mapping._load_mapping()
        path.unlink()
        assert cpe_mapping._load_mapping() is first
        assert resolve_cpe_packages(_cpe("gnu", "emacs")) == {"emacs"}

    def test_empty_result_is_cached(
        self,
        mapping_file: Callable[[bytes | str], Path],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        path = mapping_file("{}")
        with caplog.at_level(logging.WARNING):
            assert cpe_mapping._load_mapping() == {}
            path.write_text('{"gnu:emacs": ["emacs"]}', encoding="utf-8")
            assert cpe_mapping._load_mapping() == {}
        assert len(_warnings(caplog, "cpe_mapping_empty")) == 1

    def test_absent_result_is_cached(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        path = tmp_path / "cpe-package-mapping.json"
        monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: path)
        with caplog.at_level(logging.WARNING):
            assert cpe_mapping._load_mapping() == {}
            path.write_text('{"gnu:emacs": ["emacs"]}', encoding="utf-8")
            assert cpe_mapping._load_mapping() == {}
        assert len(_warnings(caplog, "cpe_mapping_absent")) == 1

    def test_failure_is_not_cached_and_next_call_retries(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        path = mapping_file('{"gnu:emacs": []}')
        with pytest.raises(CPEMappingLoadError):
            cpe_mapping._load_mapping()
        path.write_text('{"gnu:emacs": ["emacs"]}', encoding="utf-8")
        assert cpe_mapping._load_mapping() == {"gnu:emacs": ("emacs",)}

    def test_os_error_is_not_cached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resource = _FailingResource(PermissionError(13, "Permission denied"))
        monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: resource)
        for _ in range(2):
            with pytest.raises(CPEMappingLoadError):
                cpe_mapping._load_mapping()
        assert resource.reads == 2

    def test_returned_sets_do_not_alias_the_cache(self) -> None:
        cpe = _cpe("erlang", "erlang\\/otp")
        first = resolve_cpe_packages(cpe)
        first.add("mutated")
        first_free_text = resolve_vendor_product("erlang", "erlang/otp")
        first_free_text.clear()
        assert resolve_cpe_packages(cpe) == {"erlang", "erlang26"}
        assert cpe_mapping._load_mapping()["erlang:erlang/otp"] == (
            "erlang",
            "erlang26",
        )


class TestPackageRelativeLoading:
    def test_resource_resolves_relative_to_the_installed_app_package(self) -> None:
        resource = cpe_mapping._mapping_resource()
        expected = (
            Path(app.__file__).resolve().parent / "data" / "cpe-package-mapping.json"
        )
        assert Path(str(resource)).resolve() == expected
        assert resource.is_file()

    def test_loads_from_a_working_directory_outside_the_source_tree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert not (Path.cwd() / "app").exists()
        assert len(cpe_mapping._load_mapping()) > 2000
        assert resolve_cpe_packages(
            _cpe("timidity\\+\\+_project", "timidity\\+\\+")
        ) == {"timidity"}


# --- Resolvers --------------------------------------------------------------


class TestResolveCPEPackages:
    def test_timidity_acceptance_example(self) -> None:
        assert resolve_cpe_packages(
            "cpe:2.3:a:timidity\\+\\+_project:timidity\\+\\+:*:*:*:*:*:*:*:*"
        ) == {"timidity"}

    def test_cpan_escaped_colon_acceptance_example(self) -> None:
        assert resolve_cpe_packages(
            "cpe:2.3:a:cpan:file\\:\\:temp:*:*:*:*:*:*:*:*"
        ) == {"perl-File-Temp"}

    def test_exact_hit(self) -> None:
        assert resolve_cpe_packages("cpe:2.3:a:gnu:emacs:29.1:*:*:*:*:*:*:*") == {
            "emacs"
        }

    def test_one_to_many_hit(self) -> None:
        packages = resolve_cpe_packages(_cpe("rust-lang", "rust"))
        assert packages == set(cpe_mapping._load_mapping()["rust-lang:rust"])
        assert len(packages) == 45

    @pytest.mark.parametrize(
        ("cpe", "expected"),
        [
            (_cpe("apache", "xerces-c\\+\\+"), {"xerces-c"}),
            (_cpe("artsoft", "rocks\\'n\\'diamonds"), {"rocksndiamonds"}),
            (_cpe("criu", "checkpoint\\/restore_in_userspace"), {"criu"}),
            (_cpe("erlang", "erlang\\/otp"), {"erlang", "erlang26"}),
        ],
    )
    def test_rewritten_keys_match_formatted_string_cpes(
        self, cpe: str, expected: set[str]
    ) -> None:
        assert resolve_cpe_packages(cpe) == expected

    def test_unmapped_product_falls_back_to_decoded_lowercase_product(
        self, stub_mapping: Callable[..., list[str]]
    ) -> None:
        requested = stub_mapping({"gnu:emacs": ("emacs",)})
        assert resolve_cpe_packages(_cpe("Example_Vendor", "Widget\\+\\+")) == {
            "widget++"
        }
        assert requested == ["example_vendor:widget++"]

    def test_escaped_colon_and_backslash_form_the_canonical_lookup_key(
        self, stub_mapping: Callable[..., list[str]]
    ) -> None:
        requested = stub_mapping({"example:path\\\\na\\:me": ("pkg",)})
        assert resolve_cpe_packages(_cpe("example", "path\\\\na\\:me")) == {"pkg"}
        assert requested == ["example:path\\\\na\\:me"]

    def test_escaped_literal_asterisk_is_a_concrete_lookup(
        self, stub_mapping: Callable[..., list[str]]
    ) -> None:
        requested = stub_mapping({})
        assert resolve_cpe_packages(_cpe("\\-", "\\*")) == {"*"}
        assert requested == ["-:*"]

    @pytest.mark.parametrize("product", ["*", "-", "", "  "])
    @pytest.mark.usefixtures("forbid_mapping_load")
    def test_non_concrete_product_returns_empty_without_loading(
        self, product: str
    ) -> None:
        assert resolve_cpe_packages(_cpe("gnu", product)) == set()
        assert resolve_cpe_packages(_cpe("*", product)) == set()

    @pytest.mark.parametrize("vendor", ["*", "-", "", "  "])
    @pytest.mark.usefixtures("forbid_mapping_load")
    def test_non_concrete_vendor_falls_back_without_loading(self, vendor: str) -> None:
        assert resolve_cpe_packages(_cpe(vendor, "Emacs")) == {"emacs"}

    @pytest.mark.usefixtures("forbid_mapping_load")
    def test_parse_failure_returns_empty_and_logs_without_the_cpe(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        cpe = "cpe:/a:untrusted-marker-vendor:untrusted-marker-product"
        with caplog.at_level(logging.WARNING):
            assert resolve_cpe_packages(cpe) == set()
        records = _warnings(caplog, "cpe_parse_failed")
        assert len(records) == 1
        assert records[0]["reason"] == "missing_cpe23_prefix"
        assert "untrusted-marker" not in caplog.text
        assert all("untrusted-marker" not in repr(r.msg) for r in caplog.records)

    @pytest.mark.parametrize(
        ("cpe", "reason"),
        [
            (_cpe("gnu", "emacs") + "\\", "unpaired_escape"),
            ("cpe:2.3:a:gnu:emacs", "wrong_component_count"),
        ],
    )
    @pytest.mark.usefixtures("forbid_mapping_load")
    def test_parse_failure_reason_is_logged(
        self, caplog: pytest.LogCaptureFixture, cpe: str, reason: str
    ) -> None:
        with caplog.at_level(logging.WARNING):
            assert resolve_cpe_packages(cpe) == set()
        assert [r["reason"] for r in _warnings(caplog, "cpe_parse_failed")] == [reason]

    def test_load_error_propagates_and_is_not_cached(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        path = mapping_file("[]")
        with pytest.raises(CPEMappingLoadError):
            resolve_cpe_packages(_cpe("gnu", "emacs"))
        path.write_text('{"gnu:emacs": ["emacs"]}', encoding="utf-8")
        assert resolve_cpe_packages(_cpe("gnu", "emacs")) == {"emacs"}

    def test_unexpected_loader_exception_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exc = MemoryError()
        monkeypatch.setattr(
            cpe_mapping, "_mapping_resource", lambda: _FailingResource(exc)
        )
        with pytest.raises(MemoryError) as excinfo:
            resolve_cpe_packages(_cpe("gnu", "emacs"))
        assert excinfo.value is exc

    def test_absent_mapping_keeps_raw_product_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        missing = tmp_path / "missing.json"
        monkeypatch.setattr(cpe_mapping, "_mapping_resource", lambda: missing)
        assert resolve_cpe_packages(_cpe("rust-lang", "rust")) == {"rust"}


class TestResolveVendorProduct:
    def test_normalizes_free_text_to_the_cpe_key(
        self, stub_mapping: Callable[..., list[str]]
    ) -> None:
        requested = stub_mapping(
            {"apache:commons_compress": ("apache-commons-compress",)}
        )
        free_text = resolve_vendor_product("  Apache ", " Commons Compress  ")
        cpe = resolve_cpe_packages(
            "cpe:2.3:a:apache:commons_compress:1.21:*:*:*:*:*:*:*"
        )
        assert free_text == cpe == {"apache-commons-compress"}
        assert requested == ["apache:commons_compress", "apache:commons_compress"]

    def test_exact_hit_against_committed_mapping(self) -> None:
        assert resolve_vendor_product("GNU", "Emacs") == {"emacs"}
        assert resolve_vendor_product("Erlang", "Erlang/OTP") == {"erlang", "erlang26"}

    def test_free_text_colon_is_serialized_canonically(self) -> None:
        assert resolve_vendor_product("CPAN", "File::Temp") == {"perl-File-Temp"}
        assert resolve_vendor_product("timidity++_project", "TiMidity++") == {
            "timidity"
        }

    def test_punctuation_is_preserved_and_only_spaces_become_underscores(
        self, stub_mapping: Callable[..., list[str]]
    ) -> None:
        requested = stub_mapping({})
        assert resolve_vendor_product("The Apache Foundation", "HTTP Server") == {
            "http_server"
        }
        assert resolve_vendor_product("acme", "Foo-Bar.js  X") == {"foo-bar.js__x"}
        assert requested == ["the_apache_foundation:http_server", "acme:foo-bar.js__x"]

    @pytest.mark.parametrize("product", ["", "   ", "*", "-", " * "])
    @pytest.mark.usefixtures("forbid_mapping_load")
    def test_non_concrete_product_returns_empty_without_loading(
        self, product: str
    ) -> None:
        assert resolve_vendor_product("gnu", product) == set()
        assert resolve_vendor_product("", product) == set()

    @pytest.mark.parametrize("vendor", ["", "   ", "*", "-", " - "])
    @pytest.mark.usefixtures("forbid_mapping_load")
    def test_non_concrete_vendor_falls_back_without_loading(self, vendor: str) -> None:
        assert resolve_vendor_product(vendor, "Commons Compress") == {
            "commons_compress"
        }

    def test_load_error_propagates(
        self, mapping_file: Callable[[bytes | str], Path]
    ) -> None:
        mapping_file('{"gnu:emacs": ["emacs"], "gnu:emacs": ["emacs"]}')
        with pytest.raises(CPEMappingLoadError):
            resolve_vendor_product("gnu", "emacs")


# --- Module boundaries ------------------------------------------------------


class TestModuleBoundaries:
    def test_imports_no_application_or_infrastructure_module(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "cpe_mapping.py", "app.services"
        )
        forbidden_prefixes = ("app", "sqlalchemy", "redis", "httpx", "celery")
        assert {
            m
            for m in modules
            if any(m == p or m.startswith(f"{p}.") for p in forbidden_prefixes)
        } == set()

    def test_generic_worker_startup_neither_imports_nor_loads_the_mapping(
        self,
    ) -> None:
        script = (
            "import sys\n"
            "import app.celery_app\n"
            "import app.tasks.worker_startup\n"
            "import app.tasks.beat_startup\n"
            "assert 'app.services.cpe_mapping' not in sys.modules, 'imported'\n"
            "import app.services.cpe_mapping as m\n"
            "assert m._load_mapping.cache_info().currsize == 0, 'loaded on import'\n"
            "print('CPE-STARTUP-OK')\n"
        )
        env = {
            **os.environ,
            "JWT_SECRET_KEY": "test-secret-key-not-for-production-min-32-chars",
        }
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=APP_ROOT.parent,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert "CPE-STARTUP-OK" in result.stdout
