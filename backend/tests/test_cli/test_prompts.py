"""Tests for `app.cli._prompts` (Interactive Input Helpers).

See docs/features/platform/cli-infrastructure.md (Interactive Input
Helpers): these are Category B helpers — no side effects beyond terminal
I/O, no exceptions of their own. Tests exercise them directly, using
Click's `CliRunner.isolation()` to supply scripted stdin for the
prompt-based helper.
"""

from __future__ import annotations

import click
import pytest
from click.testing import CliRunner

from app.cli._prompts import (
    PasswordPromptFailure,
    is_interactive_terminal,
    prompt_password_with_confirmation,
)


@pytest.mark.unit
def test_is_interactive_terminal_reflects_stdin_isatty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert is_interactive_terminal() is True

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert is_interactive_terminal() is False


@pytest.mark.unit
def test_prompt_password_with_confirmation_matching_returns_password() -> None:
    runner = CliRunner()
    with runner.isolation(input="a-very-strong-password-1\na-very-strong-password-1\n"):
        result = prompt_password_with_confirmation()

    assert result == "a-very-strong-password-1"


@pytest.mark.unit
def test_prompt_password_with_confirmation_mismatch_signals_mismatch() -> None:
    runner = CliRunner()
    with runner.isolation(input="a-very-strong-password-1\na-different-password-2\n"):
        result = prompt_password_with_confirmation()

    assert result is PasswordPromptFailure.MISMATCH


# Input encoding (cli-infrastructure.md, Interactive Input Helpers): strict
# decoding raises `UnicodeDecodeError` — reproduced by `CliRunner`, which
# decodes scripted stdin strictly — while `surrogateescape` yields lone
# surrogates, reproduced by replacing `click.prompt`.


@pytest.mark.unit
def test_undecodable_first_entry_signals_invalid_encoding_without_second_prompt() -> (
    None
):
    runner = CliRunner()
    with runner.isolation(
        input=b"secr\xe9t-password-123\nsecr\xe9t-password-123\n"
    ) as outstreams:
        result = prompt_password_with_confirmation()
        output = outstreams[0].getvalue()

    assert result is PasswordPromptFailure.INVALID_ENCODING
    assert b"Confirm password" not in output
    assert b"secr" not in output
    assert b"\xe9" not in output


@pytest.mark.unit
def test_undecodable_confirmation_entry_signals_invalid_encoding() -> None:
    runner = CliRunner()
    with runner.isolation(
        input=b"a-very-strong-password-1\na-very-strong-passw\xe9rd-1\n"
    ) as outstreams:
        result = prompt_password_with_confirmation()
        output = outstreams[0].getvalue()

    assert result is PasswordPromptFailure.INVALID_ENCODING
    assert b"a-very-strong" not in output


@pytest.mark.unit
@pytest.mark.parametrize(
    "entries",
    [
        pytest.param(["secr\udce9t-password-123", "unused"], id="first-entry"),
        pytest.param(
            ["a-very-strong-password-1", "a-very-strong-passw\udce9rd-1"],
            id="confirmation-entry",
        ),
        pytest.param(
            ["secr\udce9t-password-123", "secr\udce9t-password-123"],
            id="both-entries-equal",
        ),
    ],
)
def test_surrogate_escaped_entry_signals_invalid_encoding(
    monkeypatch: pytest.MonkeyPatch, entries: list[str]
) -> None:
    """Lone surrogates are rejected even when both entries are identical,
    so they never reach the caller as a password."""
    remaining = iter(entries)
    monkeypatch.setattr(click, "prompt", lambda *args, **kwargs: next(remaining))

    assert prompt_password_with_confirmation() is PasswordPromptFailure.INVALID_ENCODING


@pytest.mark.unit
def test_valid_non_ascii_password_is_returned() -> None:
    password = "contraseña-muy-segura-ñ"
    runner = CliRunner()
    with runner.isolation(input=f"{password}\n{password}\n"):
        result = prompt_password_with_confirmation()

    assert result == password


@pytest.mark.unit
def test_prompt_password_with_confirmation_never_echoes_to_output() -> None:
    runner = CliRunner()
    with runner.isolation(
        input="a-very-strong-password-1\na-very-strong-password-1\n"
    ) as outstreams:
        prompt_password_with_confirmation()
        output = outstreams[0].getvalue().decode()

    assert "a-very-strong-password-1" not in output
