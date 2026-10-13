"""Tests for the shared incremental XML parsing safety boundary.

Contract under test: docs/features/packages/ibs-product-release-detection.md
(Resource and XML Safety: incremental parsing, rejected DTDs and entity
declarations, only predefined character entities, no resolver, depth and
element counts enforced while parsing, and finalization of the complete
document) and docs/conventions.md (External String Admissibility: an XML
1.0 document cannot contain U+0000 or a surrogate code point, raw or as a
character reference, so the parse failure is the outcome). The helper
reports bounded failure reasons (`malformed`, `forbidden_construct`,
`resource_limit`) whose message never carries document content.

Every document is synthetic; no network, database, or Redis is used.
"""

from __future__ import annotations

import itertools
import random
from typing import Final

import pytest

from app.services.xml_safety import (
    NAMESPACE_SEPARATOR,
    SafeXMLParser,
    XMLLimits,
    XMLSafetyError,
)
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS

pytestmark = pytest.mark.unit

Event = tuple[str, str, tuple[tuple[str, str], ...]]

_NS_A: Final = "urn:example:a"
_NS_B: Final = "urn:example:b"


class _Recorder:
    """Records events; consecutive character data is merged on read."""

    def __init__(self) -> None:
        self.raw: list[Event] = []

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        self.raw.append(("start", name, tuple(sorted(attributes.items()))))

    def end_element(self, name: str) -> None:
        self.raw.append(("end", name, ()))

    def character_data(self, data: str) -> None:
        self.raw.append(("text", data, ()))

    @property
    def events(self) -> list[Event]:
        merged: list[Event] = []
        for event in self.raw:
            if event[0] == "text" and merged and merged[-1][0] == "text":
                merged[-1] = ("text", merged[-1][1] + event[1], ())
            else:
                merged.append(event)
        return merged


class _BoomError(Exception):
    pass


class _ExplodingHandler(_Recorder):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    def start_element(self, name: str, attributes: dict[str, str]) -> None:
        if name == "boom":
            raise self.error
        super().start_element(name, attributes)


def _parse(
    document: bytes, *, limits: XMLLimits | None = None, chunks: list[int] | None = None
) -> list[Event]:
    """Parse `document` (optionally split at `chunks` offsets) and close."""
    recorder = _Recorder()
    parser = SafeXMLParser(recorder, limits=limits)
    offsets = [0, *(chunks or []), len(document)]
    for start, end in itertools.pairwise(offsets):
        parser.feed(document[start:end])
    parser.close()
    return recorder.events


def _rejected(document: bytes, *, limits: XMLLimits | None = None) -> XMLSafetyError:
    with pytest.raises(XMLSafetyError) as caught:
        _parse(document, limits=limits)
    return caught.value


def _qualified(namespace: str, local: str) -> str:
    return f"{namespace}{NAMESPACE_SEPARATOR}{local}"


# --- Well-formed documents ------------------------------------------------


def test_parse_well_formed_document_reports_namespace_qualified_events() -> None:
    document = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<r xmlns="urn:example:a" xmlns:b="urn:example:b">'
        b'<b:c b:x="1" y="2">t</b:c><d xmlns="">u</d></r>'
    )

    assert _parse(document) == [
        ("start", _qualified(_NS_A, "r"), ()),
        (
            "start",
            _qualified(_NS_B, "c"),
            ((_qualified(_NS_B, "x"), "1"), ("y", "2")),
        ),
        ("text", "t", ()),
        ("end", _qualified(_NS_B, "c"), ()),
        ("start", "d", ()),
        ("text", "u", ()),
        ("end", "d", ()),
        ("end", _qualified(_NS_A, "r"), ()),
    ]


def test_parse_predefined_entities_and_character_references_are_accepted() -> None:
    document = (
        b'<r a="&quot;&apos;&amp;&#65;">&amp;&lt;&gt;&quot;&apos;&#65;&#x42;'
        b"&#x1F600;</r>"
    )

    assert _parse(document) == [
        ("start", "r", (("a", "\"'&A"),)),
        ("text", "&<>\"'AB\U0001f600", ()),
        ("end", "r", ()),
    ]


def test_parse_raw_supplementary_character_is_accepted() -> None:
    document = '<r a="\U0001f600">\U0001f600</r>'.encode()

    assert _parse(document) == [
        ("start", "r", (("a", "\U0001f600"),)),
        ("text", "\U0001f600", ()),
        ("end", "r", ()),
    ]


# --- Incremental feeding ----------------------------------------------------

_CHUNKED_DOCUMENT: Final = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<r xmlns="urn:example:a" xmlns:b="urn:example:b">'
    '<b:c b:x="caf\u00e9" y="&amp;">h\u00e9llo \U0001f600 &lt;w&gt;</b:c>'
    "<d>\u4e2d\u6587</d><e/></r>\n"
).encode()


def test_parse_split_at_every_byte_boundary_yields_the_same_events() -> None:
    expected = _parse(_CHUNKED_DOCUMENT)

    for offset in range(1, len(_CHUNKED_DOCUMENT)):
        assert _parse(_CHUNKED_DOCUMENT, chunks=[offset]) == expected, offset


def test_parse_byte_by_byte_and_random_chunkings_yield_the_same_events() -> None:
    expected = _parse(_CHUNKED_DOCUMENT)
    size = len(_CHUNKED_DOCUMENT)

    assert _parse(_CHUNKED_DOCUMENT, chunks=list(range(1, size))) == expected
    generator = random.Random(922)
    for _ in range(50):
        count = generator.randint(1, 20)
        offsets = sorted(set(generator.sample(range(1, size), count)))
        assert _parse(_CHUNKED_DOCUMENT, chunks=offsets) == expected, offsets


def test_parse_split_inside_multibyte_sequence_decodes_the_character() -> None:
    document = "<r>\U0001f600</r>".encode()
    start = document.index(b"\xf0")

    for offset in range(start + 1, start + 4):
        assert _parse(document, chunks=[offset]) == [
            ("start", "r", ()),
            ("text", "\U0001f600", ()),
            ("end", "r", ()),
        ]


# --- Forbidden constructs ---------------------------------------------------

_BILLION_LAUGHS: Final = (
    b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
    + b"".join(
        b'<!ENTITY lol%d "%s">' % (level, (b"&lol%d;" % (level - 1)) * 10)
        if level > 1
        else b'<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        for level in range(1, 10)
    )
    + b"]><lolz>&lol9;</lolz>"
)


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(
            b"<!DOCTYPE r [<!ELEMENT r (#PCDATA)>]><r/>", id="internal-subset"
        ),
        pytest.param(
            b'<!DOCTYPE r SYSTEM "https://example.test/r.dtd"><r/>', id="external-id"
        ),
        pytest.param(
            b'<!DOCTYPE r PUBLIC "-//Example//DTD//EN" "r.dtd"><r/>',
            id="public-id",
        ),
        pytest.param(b"<!DOCTYPE r><r/>", id="empty-doctype"),
        pytest.param(
            b'<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>', id="entity-declaration"
        ),
        pytest.param(
            b"<!DOCTYPE r [<!ENTITY % p \"<!ENTITY e 'x'>\"> %p;]><r>&e;</r>",
            id="parameter-entity",
        ),
        pytest.param(
            b'<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/hostname">]><r>&e;</r>',
            id="external-entity",
        ),
        pytest.param(
            b'<!DOCTYPE r [<!NOTATION n SYSTEM "viewer">]><r/>', id="notation"
        ),
        pytest.param(
            b'<!DOCTYPE r [<!NOTATION n SYSTEM "viewer">'
            b'<!ENTITY u SYSTEM "data.bin" NDATA n>]><r/>',
            id="unparsed-entity",
        ),
        pytest.param(_BILLION_LAUGHS, id="billion-laughs"),
    ],
)
def test_parse_dtd_or_declaration_raises_forbidden_construct(document: bytes) -> None:
    recorder = _Recorder()
    parser = SafeXMLParser(recorder)

    with pytest.raises(XMLSafetyError) as caught:
        parser.feed(document)

    assert caught.value.reason == "forbidden_construct"
    assert recorder.events == []


def test_parse_undefined_entity_without_dtd_raises_malformed() -> None:
    assert _rejected(b"<r>&undefined;</r>").reason == "malformed"


# --- Well-formedness and finalization ---------------------------------------


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"<r><a></r>", id="mismatched-tag"),
        pytest.param(b"<r a='1' a='2'/>", id="duplicate-attribute"),
        pytest.param(b"<r>&amp</r>", id="unterminated-reference"),
        pytest.param(b"not xml", id="text-only"),
        pytest.param(b"<r/>junk", id="junk-after-root"),
        pytest.param(b"<r/><r/>", id="two-roots"),
        pytest.param(b"<r><a>", id="truncated"),
        pytest.param(b'<r a="1', id="truncated-attribute"),
        pytest.param(b"<r>\xff</r>", id="invalid-utf8"),
    ],
)
def test_parse_not_well_formed_document_raises_malformed(document: bytes) -> None:
    assert _rejected(document).reason == "malformed"


def test_close_truncated_document_feed_succeeds_and_close_raises_malformed() -> None:
    recorder = _Recorder()
    parser = SafeXMLParser(recorder)

    parser.feed(b"<r><a>text")

    with pytest.raises(XMLSafetyError) as caught:
        parser.close()
    assert caught.value.reason == "malformed"


def test_feed_complete_document_without_close_is_not_final() -> None:
    # The root's end event alone does not finalize: later bytes are still
    # parsed and can make the document malformed; only close() accepts it.
    recorder = _Recorder()
    parser = SafeXMLParser(recorder)
    parser.feed(b"<r/>")
    assert recorder.events[-1] == ("end", "r", ())

    with pytest.raises(XMLSafetyError) as caught:
        parser.feed(b"<extra/>")

    assert caught.value.reason == "malformed"


def test_close_complete_document_succeeds() -> None:
    recorder = _Recorder()
    parser = SafeXMLParser(recorder)
    parser.feed(b"<r/>")

    parser.close()

    assert recorder.events == [("start", "r", ()), ("end", "r", ())]


# --- Inadmissible characters --------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(b"\x00", id="nul"),
        pytest.param(b"\xed\xa0\x80", id="high-surrogate"),
        pytest.param(b"\xed\xbf\xbf", id="low-surrogate"),
        pytest.param(b"\xed\xa0\xbd\xed\xb8\x80", id="paired-surrogates"),
    ],
)
@pytest.mark.parametrize("position", ["text", "attribute"])
def test_parse_raw_inadmissible_bytes_raise_malformed(
    raw: bytes, position: str
) -> None:
    if position == "text":
        document = b"<r>a" + raw + b"b</r>"
    else:
        document = b'<r a="a' + raw + b'b"/>'

    assert _rejected(document).reason == "malformed"


@pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
@pytest.mark.parametrize("encoding", ["raw", "decimal", "hexadecimal"])
@pytest.mark.parametrize("position", ["text", "attribute"])
def test_parse_inadmissible_character_raises_malformed(
    character: str, encoding: str, position: str
) -> None:
    if encoding == "raw":
        injected = character.encode("utf-8", "surrogatepass")
    elif encoding == "decimal":
        injected = f"&#{ord(character)};".encode()
    else:
        injected = f"&#x{ord(character):X};".encode()
    if position == "text":
        document = b"<r>a" + injected + b"b</r>"
    else:
        document = b'<r a="a' + injected + b'b"/>'

    assert _rejected(document).reason == "malformed"


@pytest.mark.parametrize(
    "reference",
    [
        pytest.param("&#x0;", id="hex-nul"),
        pytest.param("&#xDFFF;", id="hex-low-surrogate"),
        pytest.param("&#xD83D;&#xDE00;", id="paired-surrogate-references"),
    ],
)
@pytest.mark.parametrize("position", ["text", "attribute"])
def test_parse_inadmissible_character_reference_raises_malformed(
    reference: str, position: str
) -> None:
    if position == "text":
        document = f"<r>{reference}</r>".encode()
    else:
        document = f'<r a="{reference}"/>'.encode()

    assert _rejected(document).reason == "malformed"


# --- Limits -----------------------------------------------------------------


def _nested(depth: int) -> bytes:
    return b"<a>" * depth + b"</a>" * depth


def _siblings(count: int, name: bytes = b"x") -> bytes:
    return b"<r>" + (b"<" + name + b"/>") * count + b"</r>"


def test_parse_depth_at_limit_is_accepted() -> None:
    events = _parse(_nested(5), limits=XMLLimits(max_depth=5))

    assert len(events) == 10


def test_parse_depth_over_limit_raises_resource_limit() -> None:
    error = _rejected(_nested(6), limits=XMLLimits(max_depth=5))

    assert error.reason == "resource_limit"


def test_parse_depth_counts_root_as_one() -> None:
    _parse(b"<r/>", limits=XMLLimits(max_depth=1))

    assert _rejected(b"<r><a/></r>", limits=XMLLimits(max_depth=1)).reason == (
        "resource_limit"
    )


def test_parse_element_count_at_limit_is_accepted() -> None:
    # One root plus four children: five elements.
    events = _parse(_siblings(4), limits=XMLLimits(max_elements=5))

    assert sum(1 for event in events if event[0] == "start") == 5


def test_parse_element_count_over_limit_raises_resource_limit() -> None:
    error = _rejected(_siblings(5), limits=XMLLimits(max_elements=5))

    assert error.reason == "resource_limit"


def test_parse_named_element_count_at_limit_is_accepted() -> None:
    document = b"<r>" + b"<x/>" * 3 + b"<y/>" * 50 + b"</r>"

    _parse(document, limits=XMLLimits(max_element_counts={"x": 3}))


def test_parse_named_element_count_over_limit_raises_resource_limit() -> None:
    document = b"<r>" + b"<x/>" * 4 + b"</r>"

    error = _rejected(document, limits=XMLLimits(max_element_counts={"x": 3}))

    assert error.reason == "resource_limit"


def test_parse_named_element_count_uses_the_namespace_qualified_name() -> None:
    limits = XMLLimits(max_element_counts={_qualified(_NS_A, "x"): 1})
    accepted = (
        b'<r xmlns:p="urn:example:a"><p:x/><x/><x/><x xmlns="urn:example:b"/></r>'
    )
    rejected = b'<r xmlns:p="urn:example:a"><p:x/><x xmlns="urn:example:a"/></r>'

    _parse(accepted, limits=limits)
    assert _rejected(rejected, limits=limits).reason == "resource_limit"


def test_parse_no_namespace_limit_does_not_count_namespaced_elements() -> None:
    document = b'<r xmlns:p="urn:example:a">' + b"<p:x/>" * 5 + b"<x/></r>"

    _parse(document, limits=XMLLimits(max_element_counts={"x": 1}))


@pytest.mark.parametrize("limits", [None, XMLLimits()], ids=["none", "default"])
def test_parse_without_limits_is_unlimited(limits: XMLLimits | None) -> None:
    _parse(_nested(300), limits=limits)
    _parse(_siblings(20_000), limits=limits)


# --- Failure handling -------------------------------------------------------


def test_feed_handler_exception_propagates_unchanged() -> None:
    error = _BoomError("handler failure")
    parser = SafeXMLParser(_ExplodingHandler(error))

    with pytest.raises(_BoomError) as caught:
        parser.feed(b"<r><boom/></r>")

    assert caught.value is error


def test_feed_handler_exception_in_later_chunk_propagates_unchanged() -> None:
    error = _BoomError("handler failure")
    parser = SafeXMLParser(_ExplodingHandler(error))
    # Split inside the start tag so the handler runs for the second chunk.
    parser.feed(b"<r><boom")

    with pytest.raises(_BoomError) as caught:
        parser.feed(b"/></r>")

    assert caught.value is error


@pytest.mark.parametrize(
    "encoding",
    ["x-fictional-SECRET-TOKEN-7f3a9c", "utf-7", "rot13", "idna"],
    ids=["unknown", "multi-byte", "not-a-text-encoding", "unsupported-errors"],
)
def test_parse_unusable_declared_encoding_raises_malformed(encoding: str) -> None:
    """expat raises `LookupError`/`ValueError` for these declarations; they
    are the `malformed` outcome and the declared name is discarded."""
    error = _rejected(f'<?xml version="1.0" encoding="{encoding}"?><r/>'.encode())

    assert error.reason == "malformed"
    assert encoding not in str(error)
    assert error.__cause__ is None
    assert error.__context__ is None


@pytest.mark.parametrize(
    "error",
    [ValueError("handler value error"), LookupError("handler lookup error")],
    ids=["value-error", "lookup-error"],
)
def test_handler_value_and_lookup_errors_propagate_unchanged(
    error: Exception,
) -> None:
    parser = SafeXMLParser(_ExplodingHandler(error))

    with pytest.raises(type(error)) as caught:
        parser.feed(b"<r><boom/></r>")

    assert caught.value is error


@pytest.mark.parametrize("callback", ["end_element", "character_data"])
def test_end_and_character_handler_errors_propagate_unchanged(callback: str) -> None:
    error = ValueError("handler value error")

    class _Failing(_Recorder):
        def end_element(self, name: str) -> None:
            if callback == "end_element":
                raise error

        def character_data(self, data: str) -> None:
            if callback == "character_data":
                raise error

    with pytest.raises(ValueError, match="handler value error") as caught:
        _parse_with(_Failing(), b"<r>text</r>")

    assert caught.value is error


def _parse_with(handler: _Recorder, document: bytes) -> None:
    parser = SafeXMLParser(handler)
    parser.feed(document)
    parser.close()


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(b"<r><boom/></r>", id="handler-exception"),
        pytest.param(b"<r></x>", id="malformed"),
        pytest.param(b"<!DOCTYPE r><r/>", id="forbidden-construct"),
        pytest.param(b"<r><a><a/></a></r>", id="resource-limit"),
    ],
)
def test_parser_after_failure_raises_runtime_error(document: bytes) -> None:
    parser = SafeXMLParser(
        _ExplodingHandler(_BoomError("handler failure")),
        limits=XMLLimits(max_depth=2),
    )
    with pytest.raises((_BoomError, XMLSafetyError)):
        parser.feed(document)

    with pytest.raises(RuntimeError):
        parser.feed(b"<r/>")
    with pytest.raises(RuntimeError):
        parser.close()


def test_close_after_failed_close_raises_runtime_error() -> None:
    parser = SafeXMLParser(_Recorder())
    parser.feed(b"<r>")
    with pytest.raises(XMLSafetyError):
        parser.close()

    with pytest.raises(RuntimeError):
        parser.close()


def test_close_twice_raises_runtime_error() -> None:
    parser = SafeXMLParser(_Recorder())
    parser.feed(b"<r/>")
    parser.close()

    with pytest.raises(RuntimeError):
        parser.close()
    with pytest.raises(RuntimeError):
        parser.feed(b"")


# --- Bounded error message ------------------------------------------------

_MARKER: Final = "SECRET-TOKEN-7f3a9c"


@pytest.mark.parametrize(
    ("document", "limits", "reason"),
    [
        pytest.param(
            f"<r>{_MARKER}</r><{_MARKER}/>".encode(), None, "malformed", id="malformed"
        ),
        pytest.param(
            f'<!DOCTYPE {_MARKER} [<!ENTITY e "{_MARKER}">]><r/>'.encode(),
            None,
            "forbidden_construct",
            id="forbidden-construct",
        ),
        pytest.param(
            f'<r><{_MARKER} a="{_MARKER}"/></r>'.encode(),
            XMLLimits(max_depth=1),
            "resource_limit",
            id="resource-limit",
        ),
    ],
)
def test_xml_safety_error_message_excludes_document_content(
    document: bytes, limits: XMLLimits | None, reason: str
) -> None:
    error = _rejected(document, limits=limits)

    assert error.reason == reason
    assert _MARKER not in str(error)
    assert _MARKER not in repr(error)
    assert error.__cause__ is None
