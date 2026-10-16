"""Response schema of the IBS consumer status endpoint.

See `docs/features/integrations/ibs-rabbitmq-integration.md` (Status API >
Get IBS Consumer Status, Response Schema) for the authoritative contract:
every field except `status` is `null` for `disabled` and `unreachable`, and
the heartbeat value for the consumer-written states. Datetimes are UTC with
the `Z` suffix (`docs/conventions.md`, Timestamps & Timezones).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.core.enums import IBSConsumerErrorCategory, IBSConsumerStatus


class IBSConsumerStatusData(BaseModel):
    """The observed status of the IBS RabbitMQ consumer process."""

    status: IBSConsumerStatus = Field(
        description=(
            "`connected`, `disconnected`, or `reconnecting` from a valid fresh "
            "heartbeat; `disabled` when the consumer is configured off; "
            "`unreachable` when liveness cannot be established from a valid "
            "fresh heartbeat."
        )
    )
    heartbeat_at: datetime | None = Field(
        description="Time the heartbeat was written; `null` without a heartbeat."
    )
    process_started_at: datetime | None = Field(
        description="Start time of the consumer process."
    )
    status_since: datetime | None = Field(
        description="Time the current consumer-written status began."
    )
    events_received: int | None = Field(
        description="Deliveries whose handling started in this process."
    )
    events_relevant: int | None = Field(
        description=(
            "Successful deliveries that selected at least one represented "
            "track scope, plus every delivery with a terminal application "
            "failure."
        )
    )
    events_processed: int | None = Field(
        description="Relevant deliveries completed successfully, including no-ops."
    )
    processing_failed: int | None = Field(
        description="Deliveries with a terminal application failure."
    )
    reconnect_attempts: int | None = Field(
        description="Reconnect attempts started after the initial attempt."
    )
    next_retry_seconds: int | None = Field(
        description=(
            "Currently scheduled reconnect delay; `null` when connected or no "
            "retry wait is scheduled."
        )
    )
    last_error: IBSConsumerErrorCategory | None = Field(
        description="Most recent bounded error category of this process."
    )
    last_error_at: datetime | None = Field(
        description="Time `last_error` was recorded."
    )


class IBSConsumerStatusResponse(BaseModel):
    """Single-resource envelope of `GET /api/v1/ibs-consumer/status`."""

    data: IBSConsumerStatusData
