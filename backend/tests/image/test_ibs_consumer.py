"""OCI artifact probe for the IBS RabbitMQ consumer role.

Focused and system tests own the consumer's connection classification,
reconnect delays, delivery handling, heartbeat, signal handling, and log
sanitization. This check verifies only the artifact facts of the role: the
documented command `python -m app.ibs_consumer` starts from the candidate
image, passes its PostgreSQL verification, logs its startup event, and stays
in its reconnect loop against the smoke stack's refusing endpoint without
exposing the URL credentials.

See ``docs/features/platform/testing-strategy.md`` (Process Readiness;
Representative Gate Evidence) and
``docs/features/integrations/ibs-rabbitmq-integration.md`` (Startup;
Reconnection; Structured Logs).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

_SERVICE = "ibs-consumer"
# The fictional user information of IBS_RABBITMQ_URL in docker-compose.smoke.yml.
_URL_CREDENTIALS = "example:example"


def _json_records(logs: str) -> list[dict[str, Any]]:
    """The structured log records of a log stream; other lines are ignored."""
    records: list[dict[str, Any]] = []
    for line in logs.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


@pytest.mark.image
def test_ibs_consumer_starts_and_stays_in_its_reconnect_loop(
    compose_logs: Callable[[str], str],
    compose_service_state: Callable[[str], str],
) -> None:
    logs = compose_logs(_SERVICE)
    records = _json_records(logs)
    events = [record.get("event") for record in records]

    assert "ibs_consumer_started" in events, logs
    assert any(
        record.get("event") == "ibs_consumer_connection_failed"
        and record.get("reason_category") == "network_error"
        for record in records
    ), logs
    assert "ibs_consumer_reconnect_scheduled" in events, logs
    assert _URL_CREDENTIALS not in logs, "IBS_RABBITMQ_URL credentials were logged"
    assert not [record for record in records if "ibs_event_id" in record], logs

    state = compose_service_state(_SERVICE)
    assert state.startswith("running|"), state
