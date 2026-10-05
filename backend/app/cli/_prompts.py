"""Shared interactive input helpers for CLI commands.

See `docs/features/platform/cli-infrastructure.md` (Interactive Input
Helpers). These are Category B (no side effects beyond terminal I/O)
utility functions: each signals its outcome via a return value, never by
raising or printing — the calling command owns its own exact error
message, output channel, and exit code.
"""

from __future__ import annotations

import sys
from enum import Enum

import click


class PasswordPromptFailure(Enum):
    """Why `prompt_password_with_confirmation()` returned no password."""

    MISMATCH = "mismatch"
    """The two entries differ."""

    INVALID_ENCODING = "invalid_encoding"
    """An entry is not valid UTF-8 (Interactive Input Helpers — Input
    encoding)."""


def is_interactive_terminal() -> bool:
    """Return whether stdin is attached to an interactive terminal.

    A thin, patchable wrapper around `sys.stdin.isatty()` — tests
    monkeypatch this function directly rather than reaching into Click's
    own internals to simulate a TTY or non-TTY invocation.
    """
    return sys.stdin.isatty()


def _prompt_hidden_utf8(prompt: str) -> str | None:
    """Read one hidden entry, or return `None` when it is not valid UTF-8.

    Such input arrives either as a `UnicodeDecodeError` (strict decoding)
    or as lone surrogates (`surrogateescape`). Both are discarded here:
    neither the entry nor the decoder message, which names the offending
    byte, may reach the caller or the shared exception mapper.
    """
    try:
        entry = str(click.prompt(prompt, hide_input=True))
    except UnicodeDecodeError:
        # The interrupted hidden read never echoed its line break; end the
        # prompt line as Click itself does when a hidden prompt is aborted.
        click.echo()
        return None
    try:
        entry.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return entry


def prompt_password_with_confirmation(
    prompt: str = "Password", confirm_prompt: str = "Confirm password"
) -> str | PasswordPromptFailure:
    """Prompt twice via hidden (non-echoed) input and compare the entries.

    Returns the entered password when both entries are valid UTF-8 and
    match. Returns `PasswordPromptFailure.INVALID_ENCODING` as soon as an
    entry is not valid UTF-8 (without prompting further), and
    `PasswordPromptFailure.MISMATCH` when the entries differ. Never prints
    an error itself — the calling command prints its own exact message and
    chooses its own exit code.
    """
    password = _prompt_hidden_utf8(prompt)
    if password is None:
        return PasswordPromptFailure.INVALID_ENCODING
    confirmation = _prompt_hidden_utf8(confirm_prompt)
    if confirmation is None:
        return PasswordPromptFailure.INVALID_ENCODING
    if password != confirmation:
        return PasswordPromptFailure.MISMATCH
    return password


def confirm(text: str, *, default: bool) -> bool:
    """Ask a yes/no question through Click's native `click.confirm()`.

    The calling command owns `text` and `default`. An unrecognized answer
    repeats the prompt after Click's `Error: invalid input` feedback on
    stdout. An answer that is not valid UTF-8 is an unrecognized answer
    (Interactive Input Helpers — Input encoding): Click itself rejects lone
    surrogates (`surrogateescape`), while a strict-decoding failure, raised
    before Click receives any answer, is caught here and answered with the
    same feedback. The answer is never echoed, and the decoder message,
    which names the offending byte, never reaches the shared exception
    mapper. EOF still ends the prompt through `click.Abort`.
    """
    while True:
        try:
            return click.confirm(text, default=default)
        except UnicodeDecodeError:
            click.echo("Error: invalid input")
