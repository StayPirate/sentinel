"""Entry point of the IBS RabbitMQ consumer process role.

Run as `python -m app.ibs_consumer` (docs/deployment.md, Container Images;
docs/features/integrations/ibs-rabbitmq-integration.md, Runtime
Independence and Startup). Importing `app.config` loads and validates the
settings, so an invalid value fails startup before anything else; the
structured logging pipeline is then configured before the enabled check.
With `IBS_RABBITMQ_ENABLED=false` the process logs one INFO event and exits
0 without connecting to PostgreSQL, Redis, IBS, or RabbitMQ. Otherwise it
runs `IBSEventConsumer` in one `asyncio.run()` for the process lifetime and
exits with its code (0 after a graceful shutdown, 1 after a fatal
condition).

This is not a `sentinel` CLI command and imports no Celery application,
task module, or fetcher discovery.
"""

from __future__ import annotations

import asyncio
import sys

import structlog

from app.config import settings
from app.core.logging import configure_logging
from app.services.ibs_event_consumer import DISABLED_EVENT, IBSEventConsumer

logger = structlog.get_logger("app.ibs_consumer")


def main() -> int:
    """Run the consumer process and return its exit code."""
    configure_logging(settings)
    if not settings.ibs_rabbitmq_enabled:
        logger.info(DISABLED_EVENT)
        return 0
    return asyncio.run(IBSEventConsumer(settings).run())


if __name__ == "__main__":
    sys.exit(main())
