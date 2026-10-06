"""Tests for the CVSS recalculation lease codec and lease operations
(backend/app/services/cvss_recalculation_coordination.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Complete-Run
  Coordination; Run Identity, value constraints; Coordination Resources;
  Atomic Lease Operations);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner, Complete-run coordination; Redis Strategy; Application-Owned
  Redis Operations);
- issue #835 decisions T1 (operations receive a client) and T7 (no
  client-side retry).

The codec tests are unit tests. The operation tests use the worker Redis
database through `redis_client`, which redirects
`get_cvss_recalculation_redis_url()`; the operations run on a client from
`new_cvss_recalculation_redis_client()`, and `redis_client` only sets up
and observes the key. `RedisError` behavior replaces the URL provider or a
client method instead of stopping the shared server. Server-global
scenarios live in `test_cvss_recalculation_coordination_server_global.py`
and the execution fence in `test_cvss_recalculation_coordination_fence.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable
from typing import Any, Protocol

import pytest
import redis.asyncio as redis_asyncio
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.config import settings
from app.core.enums import CVSSVersion
from app.services import cvss_recalculation_coordination
from app.services.cvss_recalculation_coordination import (
    EXECUTION_FENCE_ID,
    LEASE_KEY,
    LEASE_RENEWAL_INTERVAL_SECONDS,
    LEASE_TTL_SECONDS,
    LeaseAcquireOutcome,
    LeaseDeleteOutcome,
    LeaseRenewOutcome,
    LeaseValue,
    acquire_lease,
    compare_and_delete_lease,
    compare_and_renew_lease,
    decode_lease_value,
    encode_lease_value,
    is_canonical_task_id,
)
from tests.support.redis import redis_url_from_client, unused_tcp_port

TASK_ID = "0b8f8c47-3e5d-4a21-9c6b-7d2e1f0a5b34"
OTHER_TASK_ID = "5d1e9a72-8c3f-4b60-a1d4-2e7f6c9b0a18"
TARGET = "3.1"
OTHER_TARGET = "4.0"
VALUE = f"v1:{TASK_ID}:{TARGET}"

_DISTINCT_TTL = 123
"""A TTL no operation sets, so an unchanged TTL is observable."""

_NON_CANONICAL_TASK_IDS = [
    pytest.param(TASK_ID.upper(), id="uppercase"),
    pytest.param("0190f1d2-3c4b-7a5e-9f12-3456789abcde", id="version-7"),
    pytest.param("6ba7b810-9dad-11d1-80b4-00c04fd430c8", id="version-1"),
    pytest.param("0b8f8c47-3e5d-4a21-cc6b-7d2e1f0a5b34", id="variant-microsoft"),
    pytest.param("0b8f8c47-3e5d-4a21-7c6b-7d2e1f0a5b34", id="variant-ncs"),
    pytest.param(TASK_ID.replace("-", ""), id="unhyphenated"),
    pytest.param(f"{{{TASK_ID}}}", id="braced"),
    pytest.param(f"urn:uuid:{TASK_ID}", id="urn"),
    pytest.param(f"{TASK_ID}\n", id="trailing-newline"),
    pytest.param(f" {TASK_ID}", id="leading-space"),
    pytest.param(TASK_ID[:-1], id="truncated"),
    pytest.param("", id="empty"),
]

_MALFORMED_VALUES = [
    pytest.param(f"v1:{TASK_ID.upper()}:{TARGET}", id="uppercase-uuid"),
    pytest.param(f"v1:0190f1d2-3c4b-7a5e-9f12-3456789abcde:{TARGET}", id="uuid-v7"),
    pytest.param(f"v1:6ba7b810-9dad-11d1-80b4-00c04fd430c8:{TARGET}", id="uuid-v1"),
    pytest.param(
        f"v1:0b8f8c47-3e5d-4a21-cc6b-7d2e1f0a5b34:{TARGET}", id="uuid-bad-variant"
    ),
    pytest.param(f"v1:{TASK_ID.replace('-', '')}:{TARGET}", id="unhyphenated-uuid"),
    pytest.param(f"v1:{{{TASK_ID}}}:{TARGET}", id="braced-uuid"),
    pytest.param(f"v1:urn:uuid:{TASK_ID}:{TARGET}", id="urn-uuid"),
    pytest.param(f"v1:{TASK_ID}:3.0", id="target-3.0"),
    pytest.param(f"v1:{TASK_ID}:4", id="target-4"),
    pytest.param(f"v1:{TASK_ID}:3.10", id="target-3.10"),
    pytest.param(f"v1:{TASK_ID}:", id="empty-target"),
    pytest.param(f"v2:{TASK_ID}:{TARGET}", id="schema-v2"),
    pytest.param(f"V1:{TASK_ID}:{TARGET}", id="schema-uppercase"),
    pytest.param(f":{TASK_ID}:{TARGET}", id="empty-schema"),
    pytest.param(f"{TASK_ID}:{TARGET}", id="missing-schema"),
    pytest.param(f"v1:{TASK_ID}", id="missing-target"),
    pytest.param(f"v1::{TARGET}", id="empty-task-id"),
    pytest.param(f"v1:{TASK_ID}:{TARGET}:1767225600", id="extra-timestamp"),
    pytest.param(f"v1:{TASK_ID}:{TARGET}:", id="extra-empty-field"),
    pytest.param(f"{VALUE}\n", id="trailing-newline"),
    pytest.param(f" {VALUE}", id="leading-space"),
    pytest.param(f"{VALUE} ", id="trailing-space"),
    pytest.param("", id="empty"),
    pytest.param("::", id="only-separators"),
]

_INVALID_INPUTS = [
    pytest.param(TASK_ID.upper(), TARGET, id="uppercase-task-id"),
    pytest.param("0190f1d2-3c4b-7a5e-9f12-3456789abcde", TARGET, id="v7-task-id"),
    pytest.param(f"{{{TASK_ID}}}", TARGET, id="braced-task-id"),
    pytest.param("", TARGET, id="empty-task-id"),
    pytest.param(TASK_ID, "3.0", id="target-3.0"),
    pytest.param(TASK_ID, "4", id="target-4"),
    pytest.param(TASK_ID, "", id="empty-target"),
]

_MISMATCHED_STORED_VALUES = [
    pytest.param(f"v1:{OTHER_TASK_ID}:{TARGET}", id="owner-mismatch"),
    pytest.param(f"v1:{TASK_ID}:{OTHER_TARGET}", id="target-mismatch"),
    pytest.param(f"v1:{OTHER_TASK_ID}:{OTHER_TARGET}", id="owner-and-target-mismatch"),
    pytest.param(f"v1:{TASK_ID}:3", id="malformed-prefix-of-value"),
    pytest.param(f"{VALUE}0", id="malformed-value-plus-suffix"),
    pytest.param(f"{VALUE}:1767225600", id="malformed-extra-field"),
    pytest.param(f"v1:{TASK_ID.upper()}:{TARGET}", id="malformed-uppercase"),
    pytest.param(f"V1:{TASK_ID}:{TARGET}", id="malformed-schema"),
    pytest.param("fictional-garbage", id="malformed-garbage"),
    pytest.param("", id="malformed-empty-string"),
]


class LeaseOperation(Protocol):
    def __call__(
        self, client: redis_asyncio.Redis, *, task_id: str, target_version: str
    ) -> Awaitable[object]: ...


_OPERATIONS = [
    pytest.param(acquire_lease, id="acquire"),
    pytest.param(compare_and_renew_lease, id="renew"),
    pytest.param(compare_and_delete_lease, id="delete"),
]


def _new_lease_client() -> redis_asyncio.Redis:
    """A client from the production factory, so every operation goes
    through the replaceable URL provider."""
    return cvss_recalculation_coordination.new_cvss_recalculation_redis_client()


@pytest.fixture
async def lease_client(
    redis_client: redis_asyncio.Redis,
) -> AsyncIterator[redis_asyncio.Redis]:
    client = _new_lease_client()
    try:
        yield client
    finally:
        await client.aclose()


async def _set_non_string_key(redis_client: redis_asyncio.Redis, kind: str) -> Any:
    """Store `cvss_recalc_active` as a non-string type; return its content.

    redis-py types these commands as sync-or-async; the client is async
    (the same `misc` ignore as `client.eval` in the module under test)."""
    if kind == "hash":
        await redis_client.hset(LEASE_KEY, "owner", VALUE)  # type: ignore[misc]
    elif kind == "list":
        await redis_client.rpush(LEASE_KEY, VALUE)  # type: ignore[misc]
    else:
        await redis_client.sadd(LEASE_KEY, VALUE)  # type: ignore[misc]
    return await _non_string_content(redis_client, kind)


async def _non_string_content(redis_client: redis_asyncio.Redis, kind: str) -> Any:
    if kind == "hash":
        return await redis_client.hgetall(LEASE_KEY)  # type: ignore[misc]
    if kind == "list":
        return await redis_client.lrange(LEASE_KEY, 0, -1)  # type: ignore[misc]
    return await redis_client.smembers(LEASE_KEY)  # type: ignore[misc]


async def _assert_ttl_seconds(redis_client: redis_asyncio.Redis, seconds: int) -> None:
    """The key's TTL was set to exactly `seconds` moments ago."""
    remaining = await redis_client.pttl(LEASE_KEY)
    assert (seconds - 1) * 1000 < remaining <= seconds * 1000


# ---------------------------------------------------------------------------
# Constants and codec (unit)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConstants:
    def test_lease_constants_equal_feature_values(self) -> None:
        assert LEASE_KEY == "cvss_recalc_active"
        assert LEASE_TTL_SECONDS == 900
        assert LEASE_RENEWAL_INTERVAL_SECONDS == 60

    def test_execution_fence_id_fits_signed_int64(self) -> None:
        assert isinstance(EXECUTION_FENCE_ID, int)
        assert -(2**63) <= EXECUTION_FENCE_ID < 2**63

    def test_outcome_enums_are_closed_sets(self) -> None:
        assert {outcome.value for outcome in LeaseAcquireOutcome} == {
            "acquired",
            "not_acquired",
        }
        assert {outcome.value for outcome in LeaseRenewOutcome} == {
            "renewed",
            "absent",
            "mismatch",
        }
        assert {outcome.value for outcome in LeaseDeleteOutcome} == {
            "deleted",
            "absent",
            "mismatch",
        }


@pytest.mark.unit
class TestIsCanonicalTaskId:
    def test_lowercase_hyphenated_uuid4_is_canonical(self) -> None:
        assert is_canonical_task_id(TASK_ID)
        assert is_canonical_task_id(str(uuid.uuid4()))

    @pytest.mark.parametrize("variant", ["8", "9", "a", "b"])
    def test_every_rfc_variant_nibble_is_canonical(self, variant: str) -> None:
        assert is_canonical_task_id(f"0b8f8c47-3e5d-4a21-{variant}c6b-7d2e1f0a5b34")

    @pytest.mark.parametrize("value", _NON_CANONICAL_TASK_IDS)
    def test_non_canonical_string_is_not_canonical(self, value: str) -> None:
        assert not is_canonical_task_id(value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(None, id="none"),
            pytest.param(uuid.UUID(TASK_ID), id="uuid-object"),
            pytest.param(TASK_ID.encode(), id="bytes"),
            pytest.param(42, id="int"),
        ],
    )
    def test_non_string_is_not_canonical(self, value: object) -> None:
        assert not is_canonical_task_id(value)


@pytest.mark.unit
class TestEncodeLeaseValue:
    @pytest.mark.parametrize("target", ["3.1", "4.0"])
    def test_canonical_input_encodes_exactly_three_fields(self, target: str) -> None:
        value = encode_lease_value(TASK_ID, target)

        assert value == f"v1:{TASK_ID}:{target}"
        assert value.split(":") == ["v1", TASK_ID, target]

    def test_value_carries_no_timestamp(self) -> None:
        """Encoding is a pure function of the two inputs: two encodings at
        different times are identical and contain only schema, owner, and
        target."""
        first = encode_lease_value(TASK_ID, TARGET)
        second = encode_lease_value(TASK_ID, TARGET)

        assert first == second == f"v1:{TASK_ID}:{TARGET}"
        assert len(first) == len("v1:") + 36 + len(":3.1")

    def test_enum_target_encodes_its_value(self) -> None:
        assert encode_lease_value(TASK_ID, CVSSVersion.V4_0) == f"v1:{TASK_ID}:4.0"

    @pytest.mark.parametrize("task_id", _NON_CANONICAL_TASK_IDS)
    def test_non_canonical_task_id_raises_value_error(self, task_id: str) -> None:
        with pytest.raises(ValueError, match="canonical"):
            encode_lease_value(task_id, TARGET)

    @pytest.mark.parametrize("target", ["3.0", "2.0", "4", "3.1 ", "", "v3.1"])
    def test_invalid_target_raises_value_error(self, target: str) -> None:
        with pytest.raises(ValueError, match="target"):
            encode_lease_value(TASK_ID, target)


@pytest.mark.unit
class TestDecodeLeaseValue:
    @pytest.mark.parametrize("target", ["3.1", "4.0"])
    def test_canonical_value_round_trips(self, target: str) -> None:
        task_id = str(uuid.uuid4())

        decoded = decode_lease_value(encode_lease_value(task_id, target))

        assert decoded == LeaseValue(
            task_id=task_id, target_version=CVSSVersion(target)
        )
        assert decoded is not None
        assert encode_lease_value(decoded.task_id, decoded.target_version) == (
            f"v1:{task_id}:{target}"
        )

    @pytest.mark.parametrize("value", _MALFORMED_VALUES)
    def test_malformed_value_returns_none(self, value: str) -> None:
        assert decode_lease_value(value) is None

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(None, id="none"),
            pytest.param(VALUE.encode(), id="bytes"),
            pytest.param(["v1", TASK_ID, TARGET], id="list"),
            pytest.param(1, id="int"),
        ],
    )
    def test_non_string_returns_none(self, value: object) -> None:
        assert decode_lease_value(value) is None


# ---------------------------------------------------------------------------
# Lease operations against the worker Redis database (integration)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRedisBoundary:
    async def test_redis_client_fixture_patches_url_provider(
        self,
        redis_client: redis_asyncio.Redis,
        _redis_test_url: str,  # noqa: PT019 — value compared below, not just setup
    ) -> None:
        provider = cvss_recalculation_coordination.get_cvss_recalculation_redis_url

        assert provider() == _redis_test_url
        assert provider() == redis_url_from_client(redis_client)

    async def test_factory_client_targets_fixture_database(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        assert redis_url_from_client(lease_client) == redis_url_from_client(
            redis_client
        )

        await acquire_lease(lease_client, task_id=TASK_ID, target_version=TARGET)

        assert await redis_client.get(LEASE_KEY) == VALUE


@pytest.mark.unit
class TestClientFactory:
    async def test_provider_returns_configured_redis_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        url = "redis://fictional-redis.example.invalid:6390/7"
        monkeypatch.setattr(settings, "redis_url", url)

        assert cvss_recalculation_coordination.get_cvss_recalculation_redis_url() == (
            url
        )
        client = _new_lease_client()
        try:
            assert redis_url_from_client(client) == url
        finally:
            await client.aclose()

    async def test_factory_client_has_bounded_timeouts_and_no_retry(self) -> None:
        """Decision T7: a timed-out command is never resent."""
        client = _new_lease_client()
        try:
            kwargs = client.connection_pool.connection_kwargs
            assert kwargs["socket_timeout"] == 2
            assert kwargs["socket_connect_timeout"] == 2
            assert kwargs["decode_responses"] is True
            assert kwargs["retry"].get_retries() == 0
            assert client.get_retry() is not None
            assert client.get_retry().get_retries() == 0  # type: ignore[union-attr]
        finally:
            await client.aclose()


@pytest.mark.integration
class TestAcquireLease:
    @pytest.mark.parametrize("target", ["3.1", "4.0"])
    async def test_absent_key_returns_acquired_and_writes_exact_value_with_ttl_900(
        self,
        redis_client: redis_asyncio.Redis,
        lease_client: redis_asyncio.Redis,
        target: str,
    ) -> None:
        outcome = await acquire_lease(
            lease_client, task_id=TASK_ID, target_version=target
        )

        assert outcome is LeaseAcquireOutcome.ACQUIRED
        assert await redis_client.get(LEASE_KEY) == f"v1:{TASK_ID}:{target}"
        assert await redis_client.ttl(LEASE_KEY) == LEASE_TTL_SECONDS
        await _assert_ttl_seconds(redis_client, LEASE_TTL_SECONDS)
        assert await redis_client.keys("*") == [LEASE_KEY]

    @pytest.mark.parametrize(
        "stored",
        [
            pytest.param(f"v1:{OTHER_TASK_ID}:{OTHER_TARGET}", id="other-owner"),
            pytest.param(VALUE, id="same-owner"),
            pytest.param("fictional-garbage", id="malformed"),
            pytest.param("", id="empty-string"),
        ],
    )
    async def test_existing_string_key_returns_not_acquired_and_changes_nothing(
        self,
        redis_client: redis_asyncio.Redis,
        lease_client: redis_asyncio.Redis,
        stored: str,
    ) -> None:
        await redis_client.set(LEASE_KEY, stored, ex=_DISTINCT_TTL)

        outcome = await acquire_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseAcquireOutcome.NOT_ACQUIRED
        assert await redis_client.get(LEASE_KEY) == stored
        await _assert_ttl_seconds(redis_client, _DISTINCT_TTL)

    async def test_existing_key_without_ttl_returns_not_acquired_and_keeps_no_ttl(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        await redis_client.set(LEASE_KEY, "fictional-garbage")

        outcome = await acquire_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseAcquireOutcome.NOT_ACQUIRED
        assert await redis_client.get(LEASE_KEY) == "fictional-garbage"
        assert await redis_client.ttl(LEASE_KEY) == -1

    @pytest.mark.parametrize("kind", ["hash", "list", "set"])
    async def test_existing_non_string_key_returns_not_acquired_and_changes_nothing(
        self,
        redis_client: redis_asyncio.Redis,
        lease_client: redis_asyncio.Redis,
        kind: str,
    ) -> None:
        content = await _set_non_string_key(redis_client, kind)
        await redis_client.expire(LEASE_KEY, _DISTINCT_TTL)

        outcome = await acquire_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseAcquireOutcome.NOT_ACQUIRED
        assert await redis_client.type(LEASE_KEY) == kind
        assert await _non_string_content(redis_client, kind) == content
        await _assert_ttl_seconds(redis_client, _DISTINCT_TTL)

    async def test_repeated_acquire_while_key_exists_returns_not_acquired(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        assert (
            await acquire_lease(lease_client, task_id=TASK_ID, target_version=TARGET)
            is LeaseAcquireOutcome.ACQUIRED
        )
        await redis_client.expire(LEASE_KEY, _DISTINCT_TTL)

        for _ in range(2):
            assert (
                await acquire_lease(
                    lease_client, task_id=TASK_ID, target_version=TARGET
                )
                is LeaseAcquireOutcome.NOT_ACQUIRED
            )
            assert (
                await acquire_lease(
                    lease_client, task_id=OTHER_TASK_ID, target_version=OTHER_TARGET
                )
                is LeaseAcquireOutcome.NOT_ACQUIRED
            )

        assert await redis_client.get(LEASE_KEY) == VALUE
        await _assert_ttl_seconds(redis_client, _DISTINCT_TTL)


@pytest.mark.integration
class TestCompareAndRenewLease:
    async def test_matching_value_returns_renewed_and_resets_ttl_to_900(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        await redis_client.set(LEASE_KEY, VALUE, ex=_DISTINCT_TTL)

        outcome = await compare_and_renew_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseRenewOutcome.RENEWED
        assert await redis_client.get(LEASE_KEY) == VALUE
        await _assert_ttl_seconds(redis_client, LEASE_TTL_SECONDS)

    async def test_matching_value_without_ttl_returns_renewed_and_sets_ttl_900(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        await redis_client.set(LEASE_KEY, VALUE)

        outcome = await compare_and_renew_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseRenewOutcome.RENEWED
        await _assert_ttl_seconds(redis_client, LEASE_TTL_SECONDS)

    async def test_absent_key_returns_absent_and_creates_nothing(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        outcome = await compare_and_renew_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseRenewOutcome.ABSENT
        assert await redis_client.exists(LEASE_KEY) == 0
        assert await redis_client.dbsize() == 0

    @pytest.mark.parametrize("stored", _MISMATCHED_STORED_VALUES)
    async def test_different_value_returns_mismatch_and_keeps_value_and_ttl(
        self,
        redis_client: redis_asyncio.Redis,
        lease_client: redis_asyncio.Redis,
        stored: str,
    ) -> None:
        await redis_client.set(LEASE_KEY, stored, ex=_DISTINCT_TTL)

        outcome = await compare_and_renew_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseRenewOutcome.MISMATCH
        assert await redis_client.get(LEASE_KEY) == stored
        await _assert_ttl_seconds(redis_client, _DISTINCT_TTL)

    async def test_malformed_value_without_ttl_returns_mismatch_and_sets_no_ttl(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        await redis_client.set(LEASE_KEY, "fictional-garbage")

        outcome = await compare_and_renew_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseRenewOutcome.MISMATCH
        assert await redis_client.get(LEASE_KEY) == "fictional-garbage"
        assert await redis_client.ttl(LEASE_KEY) == -1

    @pytest.mark.parametrize("kind", ["hash", "list", "set"])
    async def test_non_string_key_returns_mismatch_and_changes_nothing(
        self,
        redis_client: redis_asyncio.Redis,
        lease_client: redis_asyncio.Redis,
        kind: str,
    ) -> None:
        content = await _set_non_string_key(redis_client, kind)
        await redis_client.expire(LEASE_KEY, _DISTINCT_TTL)

        outcome = await compare_and_renew_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseRenewOutcome.MISMATCH
        assert await redis_client.type(LEASE_KEY) == kind
        assert await _non_string_content(redis_client, kind) == content
        await _assert_ttl_seconds(redis_client, _DISTINCT_TTL)


@pytest.mark.integration
class TestCompareAndDeleteLease:
    async def test_matching_value_returns_deleted_and_removes_key(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        await redis_client.set(LEASE_KEY, VALUE, ex=LEASE_TTL_SECONDS)

        outcome = await compare_and_delete_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseDeleteOutcome.DELETED
        assert await redis_client.exists(LEASE_KEY) == 0

    async def test_absent_key_returns_absent_and_deletes_nothing(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        await redis_client.set("fictional_unrelated_key", VALUE)

        outcome = await compare_and_delete_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseDeleteOutcome.ABSENT
        assert await redis_client.get("fictional_unrelated_key") == VALUE

    @pytest.mark.parametrize("stored", _MISMATCHED_STORED_VALUES)
    async def test_different_value_returns_mismatch_and_deletes_nothing(
        self,
        redis_client: redis_asyncio.Redis,
        lease_client: redis_asyncio.Redis,
        stored: str,
    ) -> None:
        await redis_client.set(LEASE_KEY, stored, ex=_DISTINCT_TTL)

        outcome = await compare_and_delete_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseDeleteOutcome.MISMATCH
        assert await redis_client.get(LEASE_KEY) == stored
        await _assert_ttl_seconds(redis_client, _DISTINCT_TTL)

    @pytest.mark.parametrize("kind", ["hash", "list", "set"])
    async def test_non_string_key_returns_mismatch_and_deletes_nothing(
        self,
        redis_client: redis_asyncio.Redis,
        lease_client: redis_asyncio.Redis,
        kind: str,
    ) -> None:
        content = await _set_non_string_key(redis_client, kind)
        await redis_client.expire(LEASE_KEY, _DISTINCT_TTL)

        outcome = await compare_and_delete_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseDeleteOutcome.MISMATCH
        assert await redis_client.type(LEASE_KEY) == kind
        assert await _non_string_content(redis_client, kind) == content
        await _assert_ttl_seconds(redis_client, _DISTINCT_TTL)

    async def test_old_owner_against_newer_lease_returns_mismatch_newer_survives(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        assert (
            await acquire_lease(lease_client, task_id=TASK_ID, target_version=TARGET)
            is LeaseAcquireOutcome.ACQUIRED
        )
        # The old lease is gone (for example expired); a newer run owns it.
        await redis_client.delete(LEASE_KEY)
        assert (
            await acquire_lease(
                lease_client, task_id=OTHER_TASK_ID, target_version=OTHER_TARGET
            )
            is LeaseAcquireOutcome.ACQUIRED
        )
        await redis_client.expire(LEASE_KEY, _DISTINCT_TTL)

        outcome = await compare_and_delete_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert outcome is LeaseDeleteOutcome.MISMATCH
        assert await redis_client.get(LEASE_KEY) == (
            f"v1:{OTHER_TASK_ID}:{OTHER_TARGET}"
        )
        await _assert_ttl_seconds(redis_client, _DISTINCT_TTL)
        assert (
            await compare_and_renew_lease(
                lease_client, task_id=OTHER_TASK_ID, target_version=OTHER_TARGET
            )
            is LeaseRenewOutcome.RENEWED
        )

    async def test_repeated_delete_returns_absent(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        assert (
            await acquire_lease(lease_client, task_id=TASK_ID, target_version=TARGET)
            is LeaseAcquireOutcome.ACQUIRED
        )

        first = await compare_and_delete_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )
        second = await compare_and_delete_lease(
            lease_client, task_id=TASK_ID, target_version=TARGET
        )

        assert first is LeaseDeleteOutcome.DELETED
        assert second is LeaseDeleteOutcome.ABSENT
        assert await redis_client.exists(LEASE_KEY) == 0


@pytest.mark.integration
class TestOperationInputValidation:
    @pytest.mark.parametrize("operation", _OPERATIONS)
    @pytest.mark.parametrize(("task_id", "target"), _INVALID_INPUTS)
    async def test_non_canonical_input_raises_value_error_before_any_command(
        self,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        operation: LeaseOperation,
        task_id: str,
        target: str,
    ) -> None:
        """The client targets a closed port: any command would raise
        `ConnectionError`, so `ValueError` proves none was sent."""
        port = unused_tcp_port()
        monkeypatch.setattr(
            cvss_recalculation_coordination,
            "get_cvss_recalculation_redis_url",
            lambda: f"redis://127.0.0.1:{port}/0",
        )
        client = _new_lease_client()
        try:
            with pytest.raises(ValueError, match=r"canonical|target"):
                await operation(client, task_id=task_id, target_version=target)
        finally:
            await client.aclose()
        assert await redis_client.dbsize() == 0


@pytest.mark.integration
class TestRedisErrorPropagation:
    """Application-Owned Redis Operations: every `RedisError` propagates
    unchanged; the shared server is never stopped."""

    @pytest.mark.parametrize("operation", _OPERATIONS)
    async def test_unreachable_server_raises_connection_error(
        self,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        operation: LeaseOperation,
    ) -> None:
        port = unused_tcp_port()
        monkeypatch.setattr(
            cvss_recalculation_coordination,
            "get_cvss_recalculation_redis_url",
            lambda: f"redis://127.0.0.1:{port}/0",
        )
        client = _new_lease_client()
        try:
            with pytest.raises(RedisConnectionError):
                await operation(client, task_id=TASK_ID, target_version=TARGET)
        finally:
            await client.aclose()
        assert await redis_client.ping()

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                ResponseError(
                    "OOM command not allowed when used memory > 'maxmemory'."
                ),
                id="oom",
            ),
            pytest.param(
                RedisTimeoutError("Timeout reading from fictional-redis:6379"),
                id="timeout",
            ),
            pytest.param(
                RedisConnectionError("Connection closed by server."),
                id="connection",
            ),
            pytest.param(RedisError("fictional failure"), id="base"),
        ],
    )
    @pytest.mark.parametrize(
        ("operation", "command"),
        [
            pytest.param(acquire_lease, "set", id="acquire"),
            pytest.param(compare_and_renew_lease, "eval", id="renew"),
            pytest.param(compare_and_delete_lease, "eval", id="delete"),
        ],
    )
    async def test_command_error_propagates_unchanged(
        self,
        redis_client: redis_asyncio.Redis,
        lease_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        operation: LeaseOperation,
        command: str,
        error: RedisError,
    ) -> None:
        await redis_client.set(LEASE_KEY, VALUE, ex=_DISTINCT_TTL)

        async def _fail(*args: object, **kwargs: object) -> object:
            raise error

        monkeypatch.setattr(lease_client, command, _fail)

        with pytest.raises(RedisError) as excinfo:
            await operation(lease_client, task_id=TASK_ID, target_version=TARGET)

        assert excinfo.value is error
        assert await redis_client.get(LEASE_KEY) == VALUE
        await _assert_ttl_seconds(redis_client, _DISTINCT_TTL)


@pytest.mark.integration
class TestOutcomeTypes:
    async def test_every_outcome_is_a_member_of_its_closed_enum(
        self, redis_client: redis_asyncio.Redis, lease_client: redis_asyncio.Redis
    ) -> None:
        kwargs = {"task_id": TASK_ID, "target_version": TARGET}
        other = {"task_id": OTHER_TASK_ID, "target_version": TARGET}

        acquire_outcomes = [
            await acquire_lease(lease_client, **kwargs),
            await acquire_lease(lease_client, **kwargs),
        ]
        renew_outcomes = [
            await compare_and_renew_lease(lease_client, **kwargs),
            await compare_and_renew_lease(lease_client, **other),
        ]
        delete_outcomes = [
            await compare_and_delete_lease(lease_client, **other),
            await compare_and_delete_lease(lease_client, **kwargs),
            await compare_and_delete_lease(lease_client, **kwargs),
        ]
        renew_outcomes.append(await compare_and_renew_lease(lease_client, **kwargs))

        assert acquire_outcomes == list(LeaseAcquireOutcome)
        assert all(type(o) is LeaseAcquireOutcome for o in acquire_outcomes)
        assert renew_outcomes == [
            LeaseRenewOutcome.RENEWED,
            LeaseRenewOutcome.MISMATCH,
            LeaseRenewOutcome.ABSENT,
        ]
        assert all(type(o) is LeaseRenewOutcome for o in renew_outcomes)
        assert delete_outcomes == [
            LeaseDeleteOutcome.MISMATCH,
            LeaseDeleteOutcome.DELETED,
            LeaseDeleteOutcome.ABSENT,
        ]
        assert all(type(o) is LeaseDeleteOutcome for o in delete_outcomes)
