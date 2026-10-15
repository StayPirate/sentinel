"""IBS RabbitMQ consumer status endpoint.

See `docs/features/integrations/ibs-rabbitmq-integration.md` (Status API >
Get IBS Consumer Status) for the authoritative contract, and
`docs/api-spec.md` (Optional Authentication on Public Endpoints;
Infrastructure Dependency Errors > Status-reporting exception) for the
shared behavior.

The handler stays thin: it processes optional authentication, delegates the
observation to `ibs_consumer_status.get_ibs_consumer_status()`, and
serializes it. Every operational status, including a Redis failure, is
HTTP 200.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.dependencies import OptionalCurrentUser
from app.schemas.ibs_consumer import IBSConsumerStatusData, IBSConsumerStatusResponse
from app.services import ibs_consumer_status
from app.services.ibs_consumer_status import IBSConsumerStatusView

router = APIRouter(prefix="/api/v1", tags=["IBS Consumer"])


def serialize_ibs_consumer_status(view: IBSConsumerStatusView) -> IBSConsumerStatusData:
    """Map the observation to its schema: the heartbeat fields for a
    consumer-written status, otherwise `null` fields."""
    heartbeat = view.heartbeat
    if heartbeat is None:
        return IBSConsumerStatusData(
            status=view.status,
            heartbeat_at=None,
            process_started_at=None,
            status_since=None,
            events_received=None,
            events_relevant=None,
            events_processed=None,
            processing_failed=None,
            reconnect_attempts=None,
            next_retry_seconds=None,
            last_error=None,
            last_error_at=None,
        )
    return IBSConsumerStatusData(
        status=view.status,
        heartbeat_at=heartbeat.heartbeat_at,
        process_started_at=heartbeat.process_started_at,
        status_since=heartbeat.status_since,
        events_received=heartbeat.events_received,
        events_relevant=heartbeat.events_relevant,
        events_processed=heartbeat.events_processed,
        processing_failed=heartbeat.processing_failed,
        reconnect_attempts=heartbeat.reconnect_attempts,
        next_retry_seconds=heartbeat.next_retry_seconds,
        last_error=heartbeat.last_error,
        last_error_at=heartbeat.last_error_at,
    )


@router.get(
    "/ibs-consumer/status",
    response_model=IBSConsumerStatusResponse,
    summary="Get IBS consumer status",
    description=(
        "Reports the liveness and activity of the standalone IBS RabbitMQ "
        "consumer from its ephemeral Redis heartbeat: `connected`, "
        "`disconnected`, or `reconnecting` with the process timestamps, "
        "aggregate counters, and the latest bounded error category; "
        "`disabled` when the consumer is configured off; `unreachable` when "
        "the heartbeat is absent, invalid, stale, or unreadable. Always HTTP "
        "200 for an operational status; `disabled` and `unreachable` return "
        "every other field as `null`. Public; optional authentication."
    ),
)
async def get_ibs_consumer_status(
    principal: OptionalCurrentUser,
) -> IBSConsumerStatusResponse:
    """Get IBS Consumer Status — see
    `docs/features/integrations/ibs-rabbitmq-integration.md` (Status API).

    `principal` processes optional authentication (sliding session
    refresh, 401 for an invalid selected credential); the observation does
    not vary by caller.
    """
    del principal
    view = await ibs_consumer_status.get_ibs_consumer_status()
    return IBSConsumerStatusResponse(data=serialize_ibs_consumer_status(view))
