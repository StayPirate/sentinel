#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = ["aio-pika==10.1.2"]
# ///
"""Capture IBS RabbitMQ events into an append-only JSONL file.

Developer utility for external contract verification of the IBS RabbitMQ
event bus. Connects to ``rabbit.suse.de``, declares a server-named
exclusive queue, binds the requested routing key, and writes every
received message (payload and AMQP metadata) to a JSONL file.

The output file is opened in append mode: multiple runs on the same path
add new sessions without overwriting previous data.

**Payloads are stored exactly as received.** They may contain real
usernames and other IBS-internal data. Output files must not be committed
to the repository or shared outside the local workstation.

Usage (from the repository root)::

    # All request/review events for 3 days
    uv run scripts/capture-ibs-rabbitmq.py \\
        --routing-key 'suse.obs.request.#' \\
        --duration 259200

    # Inventory of every event type for 1 hour, 5 samples per key
    uv run scripts/capture-ibs-rabbitmq.py \\
        --routing-key 'suse.obs.#' \\
        --duration 3600 \\
        --max-samples 5

    # Single event type until Ctrl+C
    uv run scripts/capture-ibs-rabbitmq.py \\
        --routing-key suse.obs.package.commit

Queue: server-named, exclusive, non-durable, auto-delete.
Exchange: ``pubsub``, declared passively. The script never publishes.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import json
import os
import signal
import ssl
import sys
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import aio_pika
from aio_pika import DeliveryMode, ExchangeType, IncomingMessage

DEFAULT_BROKER_URL = "amqps://suse:suse@rabbit.suse.de"


def _repo_root() -> Path:
    """Return the repository root (parent of the scripts/ directory)."""
    return Path(__file__).resolve().parent.parent


def _default_ca_cert() -> Path:
    return _repo_root() / "backend" / "certs" / "SUSE_Trust_Root.crt"


def _default_output_dir() -> Path:
    """Return the default output directory outside the worktree.

    Precedence: ``$XDG_RUNTIME_DIR/sentinel/ibs-rabbitmq/``, then
    ``/tmp/sentinel-<uid>/ibs-rabbitmq/``.
    """
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "sentinel" / "ibs-rabbitmq"
    return Path(f"/tmp/sentinel-{os.getuid()}/ibs-rabbitmq")


# -- Helpers -----------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def safe_broker_url(url: str) -> str:
    """Return the broker URL with embedded credentials removed."""
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def json_safe(value: Any) -> Any:
    """Convert AMQP metadata values to JSON-serializable form."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.isoformat()
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, Sequence):
        return [json_safe(v) for v in value]
    return {"python_type": type(value).__name__, "value": str(value)}


# -- I/O ---------------------------------------------------------------------


class JsonlWriter:
    """Append-only JSONL writer with per-record fsync."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        self._fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)

    def append(self, record: Mapping[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        os.write(self._fd, f"{line}\n".encode())
        os.fsync(self._fd)

    def close(self) -> None:
        os.close(self._fd)


# -- TLS ---------------------------------------------------------------------


def build_ssl_context(ca_cert: Path) -> ssl.SSLContext:
    if not ca_cert.is_file():
        raise FileNotFoundError(f"SUSE CA certificate not found: {ca_cert}")
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=ca_cert)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# -- AMQP helpers ------------------------------------------------------------


def delivery_mode_name(mode: DeliveryMode | None) -> str | None:
    return mode.name.lower() if mode is not None else None


def amqp_metadata(message: IncomingMessage) -> dict[str, Any]:
    return {
        "app_id": message.app_id,
        "cluster_id": message.cluster_id,
        "consumer_tag": message.consumer_tag,
        "content_encoding": message.content_encoding,
        "content_type": message.content_type,
        "correlation_id": message.correlation_id,
        "delivery_mode": delivery_mode_name(message.delivery_mode),
        "exchange": message.exchange,
        "expiration": message.expiration,
        "headers": json_safe(message.headers),
        "message_id": message.message_id,
        "priority": message.priority,
        "redelivered": message.redelivered,
        "reply_to": message.reply_to,
        "timestamp": json_safe(message.timestamp),
        "type": message.type,
        "user_id": message.user_id,
    }


def message_record(
    message: IncomingMessage,
    session_id: str,
) -> dict[str, Any]:
    """Build a complete capture record from one delivered message."""
    try:
        payload = json.loads(message.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return {
            "record_type": "message_unparseable",
            "captured_at": utc_now(),
            "session_id": session_id,
            "routing_key": message.routing_key,
            "body_size": len(message.body),
            "parse_error": type(error).__name__,
            "amqp": amqp_metadata(message),
        }

    return {
        "record_type": "message",
        "captured_at": utc_now(),
        "session_id": session_id,
        "routing_key": message.routing_key,
        "body_size": len(message.body),
        "payload": payload,
        "amqp": amqp_metadata(message),
    }


# -- Main loop ---------------------------------------------------------------


async def capture(args: argparse.Namespace) -> int:
    session_id = str(uuid.uuid4())
    output = args.output.resolve()
    writer = JsonlWriter(output)
    stop_event = asyncio.Event()
    message_count = 0
    connection: aio_pika.Connection | None = None

    # Per routing-key counters for inventory mode.
    key_counts: Counter[str] = Counter()
    key_samples: Counter[str] = Counter()
    max_samples: int = args.max_samples

    def request_stop() -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, request_stop)

    writer.append(
        {
            "record_type": "session_started",
            "captured_at": utc_now(),
            "session_id": session_id,
            "broker": safe_broker_url(args.broker_url),
            "exchange": args.exchange,
            "routing_key": args.routing_key,
            "duration_seconds": args.duration,
            "max_samples_per_key": max_samples,
            "output": str(output),
        }
    )

    async def on_message(message: IncomingMessage) -> None:
        nonlocal message_count
        rk = message.routing_key or "<none>"
        key_counts[rk] += 1

        save_full = max_samples == 0 or key_samples[rk] < max_samples
        try:
            if save_full:
                record = message_record(message, session_id)
                writer.append(record)
                key_samples[rk] += 1
            elif key_counts[rk] == max_samples + 1:
                writer.append(
                    {
                        "record_type": "samples_reached",
                        "captured_at": utc_now(),
                        "session_id": session_id,
                        "routing_key": rk,
                        "max_samples": max_samples,
                    }
                )
        except Exception as error:
            writer.append(
                {
                    "record_type": "capture_error",
                    "captured_at": utc_now(),
                    "session_id": session_id,
                    "routing_key": rk,
                    "error_type": type(error).__name__,
                    "error": str(error),
                }
            )
            await message.nack(requeue=True)
            raise
        else:
            await message.ack()
            message_count += 1

    exit_code = 0
    reconnect_attempt = 0
    started_at = loop.time()
    deadline = started_at + args.duration if args.duration else None
    try:
        ssl_context = build_ssl_context(args.ca_cert)
        print(
            f"Capturing {args.routing_key} -> {output} (session {session_id})",
            flush=True,
        )

        while not stop_event.is_set():
            if deadline is not None and loop.time() >= deadline:
                break
            writer.append(
                {
                    "record_type": "connection_attempt",
                    "captured_at": utc_now(),
                    "session_id": session_id,
                    "attempt": reconnect_attempt + 1,
                }
            )
            try:
                connection = await aio_pika.connect(
                    args.broker_url,
                    ssl_context=ssl_context,
                    heartbeat=args.heartbeat,
                    client_properties={"connection_name": "sentinel-contract-capture"},
                )
                channel = await connection.channel()
                await channel.set_qos(prefetch_count=1)
                exchange = await channel.declare_exchange(
                    args.exchange,
                    type=ExchangeType.TOPIC,
                    durable=True,
                    passive=True,
                )
                queue = await channel.declare_queue(
                    name="",
                    durable=False,
                    exclusive=True,
                    auto_delete=True,
                )
                await queue.bind(exchange, routing_key=args.routing_key)
                consumer_tag = await queue.consume(
                    on_message,
                    no_ack=False,
                    exclusive=True,
                )
                transport_conn = (
                    connection.transport.connection
                    if connection.transport is not None
                    else None
                )
                writer.append(
                    {
                        "record_type": "consumer_ready",
                        "captured_at": utc_now(),
                        "session_id": session_id,
                        "queue": queue.name,
                        "consumer_tag": consumer_tag,
                        "routing_key": args.routing_key,
                        "heartbeat_requested": args.heartbeat,
                        "heartbeat_negotiated": getattr(
                            transport_conn, "heartbeat_timeout", None
                        ),
                        "server_properties": json_safe(
                            getattr(transport_conn, "server_properties", None)
                        ),
                    }
                )
                reconnect_attempt = 0

                stop_task = asyncio.create_task(stop_event.wait())
                remaining = (
                    max(0.0, deadline - loop.time()) if deadline is not None else None
                )
                done, _ = await asyncio.wait(
                    {stop_task, connection.closed()},
                    timeout=remaining,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not stop_task.done():
                    stop_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await stop_task

                if stop_task in done or not done:
                    with contextlib.suppress(Exception):
                        await queue.cancel(consumer_tag)
                    break

                writer.append(
                    {
                        "record_type": "connection_lost",
                        "captured_at": utc_now(),
                        "session_id": session_id,
                        "note": (
                            "Exclusive queue deleted; events lost "
                            "until next consumer_ready."
                        ),
                    }
                )
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - reconnect boundary
                writer.append(
                    {
                        "record_type": "connection_error",
                        "captured_at": utc_now(),
                        "session_id": session_id,
                        "attempt": reconnect_attempt + 1,
                        "error_type": type(error).__name__,
                        "error": str(error),
                    }
                )
                print(
                    f"Connection error: {type(error).__name__}: {error}",
                    file=sys.stderr,
                    flush=True,
                )
            finally:
                if connection is not None and not connection.is_closed:
                    with contextlib.suppress(Exception):
                        await connection.close()
                connection = None

            if stop_event.is_set() or (
                deadline is not None and loop.time() >= deadline
            ):
                break

            delay = min(
                args.reconnect_initial * (2**reconnect_attempt),
                args.reconnect_max,
            )
            reconnect_attempt += 1
            if deadline is not None:
                delay = min(delay, max(0.0, deadline - loop.time()))
            writer.append(
                {
                    "record_type": "reconnect_scheduled",
                    "captured_at": utc_now(),
                    "session_id": session_id,
                    "delay_seconds": delay,
                    "attempt": reconnect_attempt + 1,
                }
            )
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=delay)
            except TimeoutError:
                continue
    except asyncio.CancelledError:
        raise
    except Exception as error:  # noqa: BLE001 - terminal capture boundary
        writer.append(
            {
                "record_type": "session_failed",
                "captured_at": utc_now(),
                "session_id": session_id,
                "messages_captured": message_count,
                "error_type": type(error).__name__,
                "error": str(error),
            }
        )
        print(f"Capture failed: {type(error).__name__}: {error}", file=sys.stderr)
        exit_code = 1
    finally:
        if connection is not None and not connection.is_closed:
            with contextlib.suppress(Exception):
                await connection.close()
        if exit_code == 0:
            writer.append(
                {
                    "record_type": "session_ended",
                    "captured_at": utc_now(),
                    "session_id": session_id,
                    "messages_captured": message_count,
                    "routing_key_counts": dict(key_counts.most_common()),
                    "routing_key_samples_saved": dict(key_samples.most_common()),
                }
            )
        writer.close()

    if exit_code == 0:
        print(f"Captured {message_count} message(s).", flush=True)
        if key_counts:
            print("Routing key distribution:", flush=True)
            for rk, count in key_counts.most_common():
                saved = key_samples[rk]
                print(f"  {rk}: {count} received, {saved} saved", flush=True)
    return exit_code


# -- CLI ---------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    default_output = _default_output_dir() / "events.jsonl"
    parser.add_argument(
        "--routing-key",
        required=True,
        help=(
            "AMQP topic routing key to bind. Supports RabbitMQ wildcards: "
            "'*' matches one word, '#' matches zero or more words. "
            "Examples: suse.obs.request.#, suse.obs.package.commit, suse.obs.#"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_output,
        help=f"Append-only JSONL output path (default: {default_output}).",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Capture duration in seconds; 0 = run until SIGINT/SIGTERM (default: 0).",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=0,
        help=(
            "Max full message records saved per routing key; 0 = unlimited. "
            "Use >0 for inventory mode on high-volume wildcard captures."
        ),
    )
    parser.add_argument(
        "--broker-url",
        default=DEFAULT_BROKER_URL,
        help=f"AMQP broker URL (default: {DEFAULT_BROKER_URL}).",
    )
    parser.add_argument(
        "--exchange",
        default="pubsub",
        help="Exchange name to bind (default: pubsub).",
    )
    parser.add_argument(
        "--ca-cert",
        type=Path,
        default=_default_ca_cert(),
        help="Path to the SUSE Trust Root CA certificate.",
    )
    parser.add_argument(
        "--heartbeat",
        type=int,
        default=60,
        help="AMQP heartbeat interval in seconds (default: 60).",
    )
    parser.add_argument(
        "--reconnect-initial",
        type=int,
        default=5,
        help="Initial reconnect delay in seconds (default: 5).",
    )
    parser.add_argument(
        "--reconnect-max",
        type=int,
        default=300,
        help="Maximum reconnect delay in seconds (default: 300).",
    )
    args = parser.parse_args(argv)
    if args.duration < 0:
        parser.error("--duration must be zero or positive")
    if args.max_samples < 0:
        parser.error("--max-samples must be zero or positive")
    if args.heartbeat <= 0:
        parser.error("--heartbeat must be positive")
    if args.reconnect_initial <= 0:
        parser.error("--reconnect-initial must be positive")
    if args.reconnect_max < args.reconnect_initial:
        parser.error("--reconnect-max must be >= --reconnect-initial")
    return args


def main() -> int:
    return asyncio.run(capture(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
