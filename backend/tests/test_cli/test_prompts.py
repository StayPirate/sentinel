"""Tests for `app.cli._prompts` (Interactive Input Helpers).

See docs/features/platform/cli-infrastructure.md (Interactive Input
Helpers): these are Category B helpers — no side effects beyond terminal
I/O, no exceptions of their own. Tests exercise them directly, using
Click's `CliRunner.isolation()` to supply scripted stdin for the
prompt-based helpers, and `tests.support.terminal.terminal_stdin()` where
a confirmation answer must arrive line by line, as from a real terminal.
"""

from __future__ import annotations

import sys

import click
import pytest
from click.testing import CliRunner

from app.cli._prompts import (
    PasswordPromptFailure,
    confirm,
    is_interactive_terminal,
    prompt_password_with_confirmation,
)
from tests.support.terminal import terminal_stdin


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


# ---------------------------------------------------------------------------
# confirm(): Click's native yes/no semantics (Confirmation prompt)
# ---------------------------------------------------------------------------

_PROMPT_NO_DEFAULT = "Proceed? [y/N]: "
_PROMPT_YES_DEFAULT = "Proceed? [Y/n]: "
_RETRY_FEEDBACK = "Error: invalid input\n"


def _confirm_with_scripted_input(answers: str, *, default: bool) -> tuple[bool, str]:
    """Run `confirm()` against `CliRunner`'s scripted stdin, returning the
    answer and the captured stdout (which includes `CliRunner`'s simulated
    terminal echo of each visible answer)."""
    with CliRunner().isolation(input=answers) as outstreams:
        result = confirm("Proceed?", default=default)
        sys.stdout.flush()
        output = outstreams[0].getvalue().decode()
    return result, output


@pytest.mark.unit
@pytest.mark.parametrize("answer", ["y", "yes", "Y", "YES", "Yes", " y "])
def test_confirm_affirmative_answer_returns_true(answer: str) -> None:
    result, output = _confirm_with_scripted_input(f"{answer}\n", default=False)

    assert result is True
    assert output.startswith(_PROMPT_NO_DEFAULT)
    assert _RETRY_FEEDBACK not in output


@pytest.mark.unit
@pytest.mark.parametrize("answer", ["n", "no", "N", "NO"])
@pytest.mark.parametrize("default", [False, True])
def test_confirm_negative_answer_returns_false(answer: str, default: bool) -> None:
    result, output = _confirm_with_scripted_input(f"{answer}\n", default=default)

    assert result is False
    assert _RETRY_FEEDBACK not in output


@pytest.mark.unit
@pytest.mark.parametrize(
    ("default", "prompt"),
    [(False, _PROMPT_NO_DEFAULT), (True, _PROMPT_YES_DEFAULT)],
)
def test_confirm_enter_accepts_caller_default(default: bool, prompt: str) -> None:
    result, output = _confirm_with_scripted_input("\n", default=default)

    assert result is default
    assert output == f"{prompt}\n"


@pytest.mark.unit
def test_confirm_unrecognized_answer_reprompts_with_feedback_on_stdout() -> None:
    with CliRunner().isolation(input="maybe\ny\n") as outstreams:
        result = confirm("Proceed?", default=False)
        sys.stdout.flush()
        stdout = outstreams[0].getvalue().decode()
        stderr = outstreams[1].getvalue().decode()

    assert result is True
    assert stdout == (
        f"{_PROMPT_NO_DEFAULT}maybe\n{_RETRY_FEEDBACK}{_PROMPT_NO_DEFAULT}y\n"
    )
    assert stderr == ""


@pytest.mark.unit
@pytest.mark.parametrize("answers", ["", "maybe\n"], ids=["immediate", "after-retry"])
def test_confirm_eof_raises_click_abort(answers: str) -> None:
    with CliRunner().isolation(input=answers), pytest.raises(click.Abort):
        confirm("Proceed?", default=False)


# Input encoding (cli-infrastructure.md, Interactive Input Helpers): an
# answer that is not valid UTF-8 is an unrecognized answer. The terminal
# stdin below delivers one line per read, so the line after an invalid one
# is still read; with `surrogateescape` the invalid byte arrives as a lone
# surrogate that Click itself rejects.


@pytest.mark.unit
@pytest.mark.parametrize("errors", ["strict", "surrogateescape"])
@pytest.mark.parametrize(
    ("answer", "expected"), [(b"y\n", True), (b"no\n", False), (b"\n", False)]
)
def test_confirm_invalid_utf8_answer_reprompts_then_accepts_next_answer(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    errors: str,
    answer: bytes,
    expected: bool,
) -> None:
    monkeypatch.setattr(sys, "stdin", terminal_stdin(b"\xe9\n", answer, errors=errors))

    assert confirm("Proceed?", default=False) is expected

    captured = capsys.readouterr()
    assert captured.out == f"{_PROMPT_NO_DEFAULT}{_RETRY_FEEDBACK}{_PROMPT_NO_DEFAULT}"
    assert captured.err == ""


@pytest.mark.unit
@pytest.mark.parametrize("errors", ["strict", "surrogateescape"])
def test_confirm_mixed_unrecognized_answers_each_reprompt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], errors: str
) -> None:
    monkeypatch.setattr(
        sys,
        "stdin",
        terminal_stdin(b"maybe\n", b"y\xe9s\n", b"yes\n", errors=errors),
    )

    assert confirm("Proceed?", default=False) is True

    captured = capsys.readouterr()
    assert captured.out == (f"{_PROMPT_NO_DEFAULT}{_RETRY_FEEDBACK}" * 2) + (
        _PROMPT_NO_DEFAULT
    )


@pytest.mark.unit
@pytest.mark.parametrize("errors", ["strict", "surrogateescape"])
def test_confirm_repeated_invalid_utf8_answers_then_eof_raise_click_abort(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], errors: str
) -> None:
    """Neither the decoding error nor the answer escapes: the only
    outcome is Click's EOF `Abort`, and the output holds only prompts and
    retry feedback — no invalid byte, surrogate, or decoder message."""
    monkeypatch.setattr(
        sys,
        "stdin",
        terminal_stdin(b"\xe9\n", b"secr\xe9t\n", errors=errors),
    )

    with pytest.raises(click.Abort) as exc_info:
        confirm("Proceed?", default=False)

    assert not isinstance(exc_info.value.__context__, UnicodeDecodeError)
    captured = capsys.readouterr()
    assert captured.out == (f"{_PROMPT_NO_DEFAULT}{_RETRY_FEEDBACK}" * 2) + (
        _PROMPT_NO_DEFAULT
    )
    assert captured.err == ""
    for leaked in ("\udce9", "\xe9", "secr", "decode", "0xe9"):
        assert leaked not in captured.out


@pytest.mark.unit
def test_confirm_strict_invalid_answer_from_scripted_buffer_ends_at_eof() -> None:
    """`CliRunner` decodes its whole buffer at the first read, so the
    strict failure discards every scripted line: the helper re-prompts and
    the next read is EOF. The byte never reaches the output."""
    with CliRunner().isolation(input=b"\xe9\ny\n") as outstreams:
        with pytest.raises(click.Abort):
            confirm("Proceed?", default=False)
        sys.stdout.flush()
        output = outstreams[0].getvalue()

    assert output == (
        f"{_PROMPT_NO_DEFAULT}{_RETRY_FEEDBACK}{_PROMPT_NO_DEFAULT}".encode()
    )
