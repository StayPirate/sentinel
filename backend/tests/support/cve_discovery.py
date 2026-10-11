"""Completeness assertion for production CVE fetcher discovery.

docs/features/platform/cve-fetcher-infrastructure.md (`__init_subclass__`
Validation, "Uniqueness tracking — `_CVE_SOURCE_TYPE_MAP`") and
docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
Discovery completeness): after production discovery, every `CVESourceType`
member maps to exactly one concrete production class registered in
`FETCHER_REGISTRY` under its `name`, and no test-only class appears in
either registry. A partial or contaminated registry is a test failure.

The module imports no fetcher module and defines no fetcher, so a fresh
interpreter may import it after a production entry module without changing
either registry.
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping

from app.core.enums import CVESourceType

PRODUCTION_CVE_FETCHER_PACKAGE = "app.services.tickets."
"""Module prefix of every production CVE fetcher (Domain Placement)."""


def is_test_only(cls: type) -> bool:
    """Whether `cls` is defined under the `tests` package."""
    return cls.__module__ == "tests" or cls.__module__.startswith("tests.")


def assert_complete_cve_discovery(
    cve_source_map: Mapping[CVESourceType, type],
    fetcher_registry: Mapping[str, type],
) -> None:
    """Raise `AssertionError` naming every way the two registries fall
    short of complete, uncontaminated production discovery."""
    problems = [
        f"CVESourceType.{member.name} has no owner"
        for member in CVESourceType
        if member not in cve_source_map
    ]
    problems += [
        f"unknown source key {key!r}"
        for key in cve_source_map
        if not isinstance(key, CVESourceType)
    ]
    for source, cls in cve_source_map.items():
        owner = f"{source!r} owner {cls.__module__}.{cls.__qualname__}"
        if cls.__dict__.get("abstract", False) or inspect.isabstract(cls):
            problems.append(f"{owner} is not concrete")
        if not cls.__module__.startswith(PRODUCTION_CVE_FETCHER_PACKAGE):
            problems.append(f"{owner} is not under {PRODUCTION_CVE_FETCHER_PACKAGE}")
        if getattr(cls, "cve_source_type", None) is not source:
            problems.append(f"{owner} does not declare that source")
        name = getattr(cls, "name", None)
        if not isinstance(name, str) or fetcher_registry.get(name) is not cls:
            problems.append(f"{owner} is not FETCHER_REGISTRY[{name!r}]")
    for registry, classes in (
        ("_CVE_SOURCE_TYPE_MAP", cve_source_map.values()),
        ("FETCHER_REGISTRY", fetcher_registry.values()),
    ):
        problems += [
            f"test-only class {cls.__module__}.{cls.__qualname__} in {registry}"
            for cls in classes
            if is_test_only(cls)
        ]
    if problems:
        raise AssertionError(
            "incomplete or contaminated CVE fetcher discovery:\n- "
            + "\n- ".join(problems)
        )
