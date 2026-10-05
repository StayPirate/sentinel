"""Structural tests verifying relative reference integrity across tracked
documentation files: Markdown links, HTML `href`/`src`/`srcset`
attributes, and heading anchors in `.md` targets.

See `docs/features/platform/testing-strategy.md` (Structural Tests)
for scope and governing principle. This test only detects and reports
broken references — resolving a broken reference (fixing the path,
creating the missing file or heading, or removing the reference) is a
judgement call left to whoever introduces or reviews the change; the
test does not attempt to guess the correct resolution.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterable
from html.parser import HTMLParser
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# `[text](target)` and `![alt](target)`. Matched against text whose code
# blocks and code spans are already blanked out (see `_mask_code`).
_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

# Opening or closing fence of a fenced code block, at any indentation so
# fences nested in list items are recognized too.
_FENCE_RE = re.compile(r"^[ \t]*(`{3,}|~{3,})")

# An inline code span: a backtick run closed by the next run of the same
# length. Applied per paragraph, so a stray backtick cannot mask text
# beyond a blank line.
_CODE_SPAN_RE = re.compile(r"(?<!`)(`+)(?!`)(.*?[^`])\1(?!`)", re.DOTALL)
_PARAGRAPH_BREAK_RE = re.compile(r"(\n[ \t]*\n)")

_ATX_HEADING_RE = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+(.*?))??(?:[ \t]+#+)?[ \t]*$")
_INLINE_LINK_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_SLUG_DISCARD_RE = re.compile(r"[^\w\- ]")


def _tracked_markdown_files() -> list[Path]:
    """Every existing `.md` file tracked by git, repository-wide."""
    result = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    paths = [REPO_ROOT / line for line in result.stdout.splitlines() if line]
    return [path for path in paths if path.exists()]


def _fenced_line_flags(lines: list[str]) -> list[bool]:
    """For each line, whether it belongs to a fenced code block (fence
    lines included). An unclosed fence extends to the end of the file.
    """
    flags: list[bool] = []
    open_fence: str | None = None
    for line in lines:
        match = _FENCE_RE.match(line)
        if open_fence is None:
            if match:
                open_fence = match.group(1)
            flags.append(open_fence is not None)
            continue
        flags.append(True)
        if (
            match
            and match.group(1)[0] == open_fence[0]
            and len(match.group(1)) >= len(open_fence)
            and not line[match.end() :].strip()
        ):
            open_fence = None
    return flags


def _blank(text: str) -> str:
    """Replace every character except newlines with a space, preserving
    offsets and line numbers.
    """
    return re.sub(r"[^\n]", " ", text)


def _mask_code(content: str) -> str:
    """Blank out fenced code blocks and inline code spans, whose content
    is literal text rather than a reference.
    """
    lines = content.splitlines(keepends=True)
    flags = _fenced_line_flags(lines)
    unfenced = "".join(
        _blank(line) if fenced else line
        for line, fenced in zip(lines, flags, strict=True)
    )
    return "".join(
        _CODE_SPAN_RE.sub(lambda match: _blank(match.group(0)), part)
        for part in _PARAGRAPH_BREAK_RE.split(unfenced)
    )


def _heading_slug(heading: str) -> str:
    text = _INLINE_LINK_RE.sub(r"\1", heading).replace("`", "")
    text = _SLUG_DISCARD_RE.sub("", text.strip().lower())
    return text.replace(" ", "-")


def _heading_anchors(content: str) -> set[str]:
    """GitHub-style anchors of every ATX heading outside fenced code
    blocks and YAML front matter.
    """
    lines = content.splitlines()
    flags = _fenced_line_flags(lines)
    start = 0
    if lines and lines[0].strip() == "---":
        closing = next(
            (
                index
                for index, line in enumerate(lines[1:], start=1)
                if line.strip() == "---"
            ),
            None,
        )
        if closing is not None:
            start = closing + 1

    anchors: set[str] = set()
    suffixes: dict[str, int] = {}
    for line, fenced in zip(lines[start:], flags[start:], strict=True):
        match = None if fenced else _ATX_HEADING_RE.match(line)
        if match is None:
            continue
        base = _heading_slug(match.group(1) or "")
        anchor = base
        while anchor in anchors:
            suffixes[base] = suffixes.get(base, 0) + 1
            anchor = f"{base}-{suffixes[base]}"
        anchors.add(anchor)
    return anchors


class _HtmlReferenceCollector(HTMLParser):
    """Collects `(line, value)` for every `href`/`src` attribute and every
    `srcset` candidate URL.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[int, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        line = self.getpos()[0]
        for name, value in attrs:
            if value is None:
                continue
            if name in ("href", "src"):
                self.references.append((line, value))
            elif name == "srcset":
                for candidate in value.split(","):
                    url = candidate.split()
                    if url:
                        self.references.append((line, url[0]))


def _iter_references(content: str) -> list[tuple[int, str]]:
    """Every Markdown link target and HTML reference outside code, with
    its 1-based line number.
    """
    masked = _mask_code(content)
    references = [
        (masked.count("\n", 0, match.start()) + 1, match.group(1))
        for match in _LINK_RE.finditer(masked)
    ]
    collector = _HtmlReferenceCollector()
    collector.feed(masked)
    collector.close()
    references.extend(collector.references)
    return sorted(references)


def _is_out_of_scope(target: str) -> bool:
    """`http(s)://` and `mailto:` references are out of scope — see the
    Structural Tests section of the testing strategy.
    """
    return target.startswith(("http://", "https://", "mailto:"))


def _iter_broken_references(root: Path, md_files: Iterable[Path]) -> list[str]:
    broken: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}
    for md_file in md_files:
        location = md_file.relative_to(root)
        for line_number, target in _iter_references(
            md_file.read_text(encoding="utf-8")
        ):
            if _is_out_of_scope(target):
                continue
            path_part, _, anchor = target.partition("#")
            # An anchor-only reference (`#section`) targets its own file.
            resolved = (md_file.parent / path_part if path_part else md_file).resolve()
            if not resolved.exists():
                broken.append(
                    f"{location}:{line_number}: reference '{target}' does not "
                    f"resolve to an existing file or directory "
                    f"(resolved: {resolved})"
                )
                continue
            if not anchor or resolved.suffix != ".md" or not resolved.is_file():
                continue
            if resolved not in anchor_cache:
                anchor_cache[resolved] = _heading_anchors(
                    resolved.read_text(encoding="utf-8")
                )
            if anchor not in anchor_cache[resolved]:
                broken.append(
                    f"{location}:{line_number}: reference '{target}' names "
                    f"anchor '#{anchor}', which matches no heading in "
                    f"{resolved}"
                )
    return broken


@pytest.mark.unit
class TestDocumentationLinkIntegrity:
    """Every relative reference in a tracked `.md` file must resolve to
    an existing file or directory and, for a `.md` target, to an
    existing heading anchor.
    """

    def test_no_broken_relative_references(self) -> None:
        broken = _iter_broken_references(REPO_ROOT, _tracked_markdown_files())
        assert not broken, "Broken documentation references found:\n" + "\n".join(
            broken
        )


def _check(root: Path, files: dict[str, str]) -> list[str]:
    """Write `files` (relative path -> content) under `root` and return the
    broken references found in its `.md` files.
    """
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return _iter_broken_references(
        root, sorted(root / name for name in files if name.endswith(".md"))
    )


@pytest.mark.unit
class TestFileResolution:
    def test_markdown_link_missing_file_is_reported(self, tmp_path: Path) -> None:
        broken = _check(tmp_path, {"a.md": "intro\n\nsee [b](missing.md)\n"})
        assert len(broken) == 1
        assert broken[0].startswith("a.md:3: reference 'missing.md'")

    def test_markdown_link_existing_file_or_directory_passes(
        self, tmp_path: Path
    ) -> None:
        broken = _check(
            tmp_path,
            {
                "a.md": "[b](sub/b.md) [dir](sub) ![img](sub/logo.svg)\n",
                "sub/b.md": "# B\n",
                "sub/logo.svg": "<svg/>\n",
            },
        )
        assert broken == []

    @pytest.mark.parametrize(
        "html",
        [
            '<a href="LICENSE">license</a>',
            '<img src="assets/banner.svg" alt="banner">',
            '<source srcset="assets/banner-dark.svg">',
        ],
    )
    def test_html_reference_missing_file_is_reported(
        self, tmp_path: Path, html: str
    ) -> None:
        broken = _check(tmp_path, {"a.md": f"<p>\n{html}\n</p>\n"})
        assert len(broken) == 1
        assert broken[0].startswith("a.md:2: reference ")

    def test_html_reference_existing_file_passes(self, tmp_path: Path) -> None:
        broken = _check(
            tmp_path,
            {
                "a.md": (
                    '<picture><source srcset="dark.svg 1x, dark@2x.svg 2x">'
                    '<img src="light.svg"></picture> <a href="LICENSE">l</a>\n'
                ),
                "dark.svg": "",
                "dark@2x.svg": "",
                "light.svg": "",
                "LICENSE": "",
            },
        )
        assert broken == []

    def test_srcset_one_missing_candidate_is_reported(self, tmp_path: Path) -> None:
        broken = _check(
            tmp_path,
            {
                "a.md": '<source srcset="dark.svg 1x, missing@2x.svg 2x">\n',
                "dark.svg": "",
            },
        )
        assert len(broken) == 1
        assert "'missing@2x.svg'" in broken[0]

    def test_external_references_are_ignored(self, tmp_path: Path) -> None:
        broken = _check(
            tmp_path,
            {
                "a.md": (
                    "[web](https://example.com/x.md#nope) "
                    "[plain](http://example.com) [mail](mailto:dev@example.com)\n"
                    '<a href="https://example.com"><img '
                    'src="https://example.com/badge.svg"></a>\n'
                ),
            },
        )
        assert broken == []

    def test_references_in_code_are_ignored(self, tmp_path: Path) -> None:
        content = (
            "Example: `[spec-name](path/to/spec.md#anchor)` and "
            '``<img src="missing.svg">``.\n'
            "\n"
            "```xml\n"
            '<source href="missing.xml"/>\n'
            "[x](missing.md)\n"
            "```\n"
            "\n"
            "- item\n"
            "\n"
            "    ~~~~\n"
            "    [y](missing.md)\n"
            "    ~~~~\n"
        )
        assert _check(tmp_path, {"a.md": content}) == []

    def test_unmatched_backtick_does_not_hide_later_paragraph(
        self, tmp_path: Path
    ) -> None:
        broken = _check(
            tmp_path,
            {"a.md": "a stray ` backtick\n\n[x](missing.md) and `code`\n"},
        )
        assert len(broken) == 1
        assert broken[0].startswith("a.md:3: reference 'missing.md'")

    def test_reference_after_code_block_reports_correct_line(
        self, tmp_path: Path
    ) -> None:
        broken = _check(
            tmp_path,
            {"a.md": '```\ncode\n```\n\n<img src="missing.svg">\n'},
        )
        assert len(broken) == 1
        assert broken[0].startswith("a.md:5: reference 'missing.svg'")


@pytest.mark.unit
class TestAnchorResolution:
    def test_missing_anchor_in_other_file_is_reported(self, tmp_path: Path) -> None:
        broken = _check(
            tmp_path,
            {"a.md": "[b](b.md#nonexistent-anchor)\n", "b.md": "# Title\n"},
        )
        assert len(broken) == 1
        assert "anchor '#nonexistent-anchor'" in broken[0]

    def test_missing_same_file_anchor_is_reported(self, tmp_path: Path) -> None:
        broken = _check(tmp_path, {"a.md": "# Title\n\n[x](#nonexistent)\n"})
        assert len(broken) == 1
        assert broken[0].startswith("a.md:3: reference '#nonexistent' names anchor")

    def test_missing_anchor_in_html_href_is_reported(self, tmp_path: Path) -> None:
        broken = _check(
            tmp_path,
            {"a.md": '<a href="b.md#gone">b</a>\n', "b.md": "# Title\n"},
        )
        assert len(broken) == 1
        assert "anchor '#gone'" in broken[0]

    def test_existing_anchors_pass(self, tmp_path: Path) -> None:
        broken = _check(
            tmp_path,
            {
                "a.md": (
                    "# Title\n"
                    "[self](#title) [b](b.md#setup) [b2](b.md#setup-1)\n"
                    '<a href="#title">t</a> [top](b.md#) [hash](#)\n'
                ),
                "b.md": "## Setup\n\n### Setup\n",
            },
        )
        assert broken == []

    @pytest.mark.parametrize(
        ("heading", "anchor"),
        [
            ("## Structural Tests", "structural-tests"),
            (
                "## `invalidate_session(db, id) -> UUID`",
                "invalidate_sessiondb-id---uuid",
            ),
            ("### Tier 1 — Unit Tests", "tier-1--unit-tests"),
            (
                "### First Run and >120-day Gap Handling",
                "first-run-and-120-day-gap-handling",
            ),
            ("## See [the spec](a.md) here", "see-the-spec-here"),
            ("## Closing sequence ##", "closing-sequence"),
            ("   ## Indented Heading", "indented-heading"),
            ("## Café Über", "café-über"),
        ],
    )
    def test_heading_slug_matches_github_anchor(
        self, tmp_path: Path, heading: str, anchor: str
    ) -> None:
        broken = _check(
            tmp_path,
            {"a.md": "[x](b.md#" + anchor + ")\n", "b.md": heading + "\n"},
        )
        assert broken == []

    def test_duplicate_headings_receive_numeric_suffixes(self) -> None:
        anchors = _heading_anchors("# Foo\n## Foo\n### Foo-1\n#### Foo\n")
        assert anchors == {"foo", "foo-1", "foo-1-1", "foo-2"}

    def test_heading_in_code_block_or_front_matter_is_not_an_anchor(
        self, tmp_path: Path
    ) -> None:
        broken = _check(
            tmp_path,
            {
                "a.md": "[x](b.md#comment) [y](b.md#name)\n",
                "b.md": "---\n# name\n---\n# Real\n\n```bash\n# comment\n```\n",
            },
        )
        assert len(broken) == 2
        assert "anchor '#comment'" in broken[0]
        assert "anchor '#name'" in broken[1]

    def test_four_space_indented_hash_line_is_not_a_heading(self) -> None:
        assert _heading_anchors("    # not a heading\n#nospace\n") == set()

    def test_anchor_on_non_markdown_target_checks_existence_only(
        self, tmp_path: Path
    ) -> None:
        broken = _check(
            tmp_path,
            {"a.md": "[src](script.py#L10) [d](sub#x)\n", "script.py": "", "sub/f": ""},
        )
        assert broken == []

    def test_anchor_on_missing_markdown_file_reports_missing_file(
        self, tmp_path: Path
    ) -> None:
        broken = _check(tmp_path, {"a.md": "[x](gone.md#section)\n"})
        assert len(broken) == 1
        assert "does not resolve to an existing file" in broken[0]
