"""Generic decoding of IBS RabbitMQ deliveries and the delivery outcome.

Implements docs/features/integrations/ibs-rabbitmq-integration.md (AMQP
Contract > Message Encoding; Per-Delivery Processing > Settlement Policy
outcomes; Structured Logs reason categories):

- `decode_delivery()` checks, in order, that the routing key is a bound
  key, that the content type is exactly `application/octet-stream`
  (case-sensitive, no parameters), that the body is strict UTF-8, that it
  is exactly one RFC 8259 JSON text, and that its root is an object. The
  content encoding and every other AMQP property are ignored. A failure
  raises `MalformedDeliveryError` with a bounded reason; raw bytes and
  parsed values never reach a log or an exception message.
- `EventObject` is the decoded root object together with the member names
  it repeats, so each routing key's parser can reject a duplicated member it
  consumes while accepting duplicated unconsumed members.
- `DeliveryOutcome` and `DeliveryResult` are the bounded per-delivery
  classification that drives settlement and the delivery log events.

Pure functions without I/O; `MemoryError` propagates.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

PACKAGE_COMMIT_ROUTING_KEY: Final = "suse.obs.package.commit"

BOUND_ROUTING_KEYS: Final = (PACKAGE_COMMIT_ROUTING_KEY,)
"""The fixed exact bindings of the consumer, in binding order."""

CONTENT_TYPE: Final = "application/octet-stream"
"""The only accepted AMQP content type, compared exactly."""


class MalformedReason(StrEnum):
    """Bounded reason categories of a malformed delivery."""

    UNSUPPORTED_ROUTING_KEY = "unsupported_routing_key"
    UNSUPPORTED_CONTENT_TYPE = "unsupported_content_type"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_JSON = "invalid_json"
    NON_OBJECT_ROOT = "non_object_root"
    INVALID_PROJECT = "invalid_project"
    INVALID_PACKAGE = "invalid_package"


class MalformedDeliveryError(Exception):
    """A delivery that violates the message encoding or its event schema.

    Carries only the bounded `reason`; never the payload.
    """

    def __init__(self, reason: MalformedReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class EventObject:
    """The decoded root object of one delivery.

    `members` maps each member name to its last value; `duplicated` holds
    the root member names that occur more than once.
    """

    routing_key: str
    members: Mapping[str, Any]
    duplicated: frozenset[str]


class DeliveryOutcome(StrEnum):
    """The terminal application outcome of one delivery (Settlement Policy)."""

    MALFORMED = "malformed"
    IRRELEVANT = "irrelevant"
    PROCESSED = "processed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """One delivery's outcome, its bounded reason, and its log fields.

    `fields` holds only bounded values allowed in the delivery log events
    (a sanitized identity and counts).
    """

    outcome: DeliveryOutcome
    reason_category: str | None = None
    fields: Mapping[str, str | int] = field(default_factory=dict)


class _JSONObject(dict[str, Any]):
    """A JSON object that remembers its repeated member names."""

    __slots__ = ("duplicated",)

    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        super().__init__(pairs)
        counts = Counter(name for name, _ in pairs) if len(self) < len(pairs) else {}
        self.duplicated: frozenset[str] = frozenset(
            name for name, count in counts.items() if count > 1
        )


def _reject_constant(_: str) -> Any:
    """Reject the non-standard `NaN`, `Infinity`, and `-Infinity`."""
    raise ValueError("non-standard JSON constant")


def decode_delivery(
    routing_key: str | None, content_type: str | None, body: bytes
) -> EventObject:
    """Decode one delivery into its root JSON object.

    Category: pure validation. Raises `MalformedDeliveryError` for an
    unbound routing key, a content type other than exactly
    `application/octet-stream`, invalid UTF-8, anything but exactly one
    RFC 8259 JSON text (including a byte order mark, non-standard
    constants, trailing content, and values the parser cannot represent),
    or a non-object root. `MemoryError` propagates.
    """
    if routing_key is None or routing_key not in BOUND_ROUTING_KEYS:
        raise MalformedDeliveryError(MalformedReason.UNSUPPORTED_ROUTING_KEY)
    if content_type != CONTENT_TYPE:
        raise MalformedDeliveryError(MalformedReason.UNSUPPORTED_CONTENT_TYPE)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise MalformedDeliveryError(MalformedReason.INVALID_UTF8) from None
    try:
        value = json.loads(
            text, object_pairs_hook=_JSONObject, parse_constant=_reject_constant
        )
    except ValueError, RecursionError:
        # JSONDecodeError, a rejected constant, the integer digit limit, or
        # nesting beyond the parser's recursion limit.
        raise MalformedDeliveryError(MalformedReason.INVALID_JSON) from None
    if not isinstance(value, _JSONObject):
        raise MalformedDeliveryError(MalformedReason.NON_OBJECT_ROOT)
    return EventObject(
        routing_key=routing_key, members=value, duplicated=value.duplicated
    )
