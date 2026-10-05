"""Scripted terminal stdin for interactive CLI prompt tests.

`CliRunner` decodes its whole scripted stdin buffer at the first read and
echoes every visible answer itself, so it cannot reproduce a terminal that
delivers input one line at a time, nor carry lone surrogates. The stream
built here behaves like a TTY in canonical mode: every read returns at
most one scripted line, decoded with the requested error handler
(`strict` raises `UnicodeDecodeError` for that line only; `surrogateescape`
yields lone surrogates — docs/features/platform/cli-infrastructure.md,
Interactive Input Helpers — Input encoding). Exhausted input reads as EOF.
A `signal.Signals` entry raises that signal from the pending read, as an
operator's Ctrl+C or a process manager would while the prompt waits.

Tests install the stream with `monkeypatch.setattr(sys, "stdin", ...)`;
Click's `confirm()` then reads it through the builtin `input()`.
"""

from __future__ import annotations

import io
import signal
from collections import deque
from typing import Any

TerminalEntry = bytes | signal.Signals


class _CanonicalModeTerminal(io.RawIOBase):
    def __init__(self, entries: tuple[TerminalEntry, ...]) -> None:
        self._entries = deque(entries)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        if not self._entries:
            return 0
        entry = self._entries.popleft()
        if isinstance(entry, signal.Signals):
            signal.raise_signal(entry)
            return 0
        memoryview(buffer)[: len(entry)] = entry
        return len(entry)


def terminal_stdin(*entries: TerminalEntry, errors: str = "strict") -> io.TextIOWrapper:
    """A text stdin delivering each bytes entry (one `\\n`-terminated line)
    per read, then EOF; `errors` is `"strict"` or `"surrogateescape"`."""
    return io.TextIOWrapper(
        io.BufferedReader(_CanonicalModeTerminal(entries)),
        encoding="utf-8",
        errors=errors,
    )
