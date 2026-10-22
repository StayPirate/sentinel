"""`sentinel example-data` command group: load.

See `docs/features/platform/example-dataset.md` (Command) for the
authoritative command contract (step report, messages, exit codes) this
module implements, and `docs/features/platform/cli-infrastructure.md` for
the shared bootstrap, session, and error-mapping mechanism it builds on.
The load commits one transaction per dataset operation inside
`app.services.example_dataset`, the documented exception to the
one-transaction rule of mutating CLI workflows (Database Session
Management).

Module-level imports are limited to Core-layer modules and third-party
libraries that do not instantiate `Settings`; the service module is
imported inside the command, after `bootstrap()` has validated `Settings`,
so `--help` never loads application settings or opens a connection.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

import click

from app.cli._runtime import bootstrap, get_session_factory
from app.core.exceptions import ServiceError

PARTIAL_DATASET_WARNING = (
    "Warning: The database holds part of the example dataset. "
    "Recreate the database before loading it again."
)


@click.group("example-data")
def example_data_group() -> None:
    """Fictional example dataset for local development and test environments
    only, never for staging or production."""


@example_data_group.command("load")
def load() -> None:
    """Load the fictional example dataset into a newly created database.

    Refuses a database that holds users, tickets, CVEs, or products. Every
    dataset user has the documented password `example-dataset-password`.
    """
    bootstrap()
    from app.services.example_dataset import STEPS, load_example_dataset

    report = _StepReport(STEPS)
    try:
        asyncio.run(load_example_dataset(get_session_factory(), progress=report))
    except Exception as exc:
        # The exception then reaches the shared exception mapper.
        report.failed(exc)
        raise
    click.echo("Loaded the example dataset.")


class _StepReport:
    """The fail-fast step report of the load (docs/conventions.md,
    Multi-Step Reporting); receives the service's progress."""

    def __init__(self, steps: Sequence[str]) -> None:
        self.steps = steps
        self.current: str | None = None
        self.committed = False

    def step_started(self, step: str) -> None:
        self.current = step

    def step_completed(self, step: str) -> None:
        click.echo(f"✓ {step}")
        self.current = None

    def operation_committed(self) -> None:
        self.committed = True

    def failed(self, exc: Exception) -> None:
        """Report the failed step, the steps not attempted, and a partial
        dataset. A failure outside a step, such as the Empty-Database Guard,
        reports nothing here."""
        if self.current is None:
            return
        reason = str(exc) if isinstance(exc, ServiceError) else ""
        click.echo(f"✗ {self.current}: {reason or type(exc).__name__}")
        for step in self.steps[self.steps.index(self.current) + 1 :]:
            click.echo(f"— {step} not attempted (aborted due to previous error)")
        if self.committed:
            click.echo(PARTIAL_DATASET_WARNING, err=True)
