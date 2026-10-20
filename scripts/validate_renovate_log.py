"""Fail when a Renovate JSON lookup log contains package warnings.

A lookup failure of a package listed in IP_ALLOW_LIST_EXEMPTIONS is tolerated,
and reported on stdout, only when the same log records GitHub's refusal of that
lookup by the IP allow list of the package's owning organization. See
docs/deployment.md (Workflow Conventions).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

PACKAGE_FILES_MESSAGE = "packageFiles with updates"

# (datasource, packageName) pairs owned by an organization whose GitHub IP
# allow list refuses this workflow's token on GitHub-hosted runners.
IP_ALLOW_LIST_EXEMPTIONS = frozenset(
    {
        ("github-tags", "aquasecurity/trivy-action"),
        ("github-releases", "aquasecurity/trivy"),
    }
)


class RenovateLogValidationError(ValueError):
    """Raised when a Renovate log cannot be validated safely."""


@dataclass
class PackageWarnings:
    """Formatted package warnings, split by whether they fail validation."""

    blocking: list[str] = field(default_factory=list)
    tolerated: list[str] = field(default_factory=list)


def _read_json_record(line: str, line_number: int) -> dict[str, Any]:
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise RenovateLogValidationError(
            f"line {line_number} is not valid JSON: {exc.msg}"
        ) from exc
    if not isinstance(record, dict):
        raise RenovateLogValidationError(
            f"line {line_number} must contain a JSON object"
        )
    return record


def _ip_allow_list_refusal(record: dict[str, Any]) -> tuple[str, str] | None:
    """Return the refused (datasource, packageName) pair logged by a record."""
    datasource = record.get("datasource")
    package_name = record.get("packageName")
    error = record.get("err")
    if not (
        isinstance(datasource, str)
        and isinstance(package_name, str)
        and isinstance(error, dict)
        and isinstance(error.get("message"), str)
    ):
        return None
    owner = package_name.partition("/")[0]
    refusal = f"the `{owner}` organization has an IP allow list enabled"
    if refusal not in error["message"]:
        return None
    return datasource, package_name


def _is_tolerated(
    datasource: Any,
    package_name: Any,
    message: str,
    refusals: set[tuple[str, str]],
) -> bool:
    if not (isinstance(datasource, str) and isinstance(package_name, str)):
        return False
    key = (datasource, package_name)
    lookup_failure = f"Failed to look up {datasource} package {package_name}: no-result"
    return (
        key in IP_ALLOW_LIST_EXEMPTIONS
        and key in refusals
        and message == lookup_failure
    )


def find_package_warnings(stream: TextIO) -> PackageWarnings:
    """Return formatted package warnings from Renovate's lookup summary."""
    summaries = 0
    refusals: set[tuple[str, str]] = set()
    found: list[tuple[Any, Any, str, str]] = []

    for line_number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        record = _read_json_record(line, line_number)
        refusal = _ip_allow_list_refusal(record)
        if refusal is not None:
            refusals.add(refusal)
        if record.get("msg") != PACKAGE_FILES_MESSAGE:
            continue

        summaries += 1
        config = record.get("config")
        if not isinstance(config, dict):
            raise RenovateLogValidationError(
                f"line {line_number} has no package-file configuration object"
            )

        for manager, package_files in config.items():
            if not isinstance(package_files, list):
                raise RenovateLogValidationError(
                    f"line {line_number} manager {manager!r} must contain a list"
                )
            for package_file in package_files:
                if not isinstance(package_file, dict):
                    raise RenovateLogValidationError(
                        f"line {line_number} manager {manager!r} has an invalid entry"
                    )
                file_name = package_file.get("packageFile", "<unknown file>")
                dependencies = package_file.get("deps")
                if not isinstance(dependencies, list):
                    raise RenovateLogValidationError(
                        f"line {line_number} package file {file_name!r} "
                        "has no deps list"
                    )

                for dependency in dependencies:
                    if not isinstance(dependency, dict):
                        raise RenovateLogValidationError(
                            f"line {line_number} package file {file_name!r} "
                            "has an invalid dependency"
                        )
                    package_name = dependency.get(
                        "packageName", dependency.get("depName", "<unknown package>")
                    )
                    datasource = dependency.get("datasource", "unknown datasource")
                    dependency_warnings = dependency.get("warnings", [])
                    if not isinstance(dependency_warnings, list):
                        raise RenovateLogValidationError(
                            f"line {line_number} package {package_name!r} "
                            "has no warnings list"
                        )
                    for warning in dependency_warnings:
                        if not isinstance(warning, dict) or not isinstance(
                            warning.get("message"), str
                        ):
                            raise RenovateLogValidationError(
                                f"line {line_number} package {package_name!r} "
                                "has an invalid warning"
                            )
                        found.append(
                            (
                                datasource,
                                package_name,
                                warning["message"],
                                f"{file_name}: {warning['message']} "
                                f"({datasource} package {package_name})",
                            )
                        )

    if summaries == 0:
        raise RenovateLogValidationError(
            f"log does not contain the {PACKAGE_FILES_MESSAGE!r} summary"
        )

    warnings = PackageWarnings()
    for datasource, package_name, message, formatted in found:
        if _is_tolerated(datasource, package_name, message, refusals):
            warnings.tolerated.append(formatted)
        else:
            warnings.blocking.append(formatted)
    return warnings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="Renovate debug log in NDJSON format")
    args = parser.parse_args()

    try:
        with args.log.open(encoding="utf-8") as stream:
            warnings = find_package_warnings(stream)
    except (OSError, RenovateLogValidationError) as exc:
        print(f"Cannot validate Renovate lookup log: {exc}", file=sys.stderr)
        return 2

    if warnings.tolerated:
        print(
            "Tolerated Renovate package lookup warnings "
            "(refused by the owning organization's GitHub IP allow list):"
        )
        for warning in warnings.tolerated:
            print(f"- {warning}")
        # Keep the tolerated list ahead of the blocking warnings written to
        # stderr when both streams end up in one log.
        sys.stdout.flush()

    if warnings.blocking:
        print("Renovate package lookup warnings found:", file=sys.stderr)
        for warning in warnings.blocking:
            print(f"- {warning}", file=sys.stderr)
        return 1

    if warnings.tolerated:
        print("Renovate lookup completed without other package warnings.")
    else:
        print("Renovate lookup completed without package warnings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
