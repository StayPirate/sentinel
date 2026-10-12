"""Incremental XML parsing safety boundary for untrusted upstream documents.

Shared by the IBS Product repository download boundary
(docs/features/packages/ibs-product-release-detection.md, Resource and XML
Safety) and the IBS API client (docs/features/integrations/
ibs-integration.md, Service Layer > IBSClient, and Security). Both
specifications require the same restrictions:

- documents are parsed incrementally with the standard-library expat
  parser, and no result is accepted until the complete document has
  parsed: `close()` finalizes the parser, and a document that ends early,
  or a caller that never calls `close()`, yields no result;
- a document type declaration (DTD) and every entity or notation
  declaration are rejected, so only the predefined XML character entities
  and character references can be used; parameter-entity parsing is
  disabled and no external entity, schema, XInclude, XSLT, file, or
  network resolver is installed;
- optional limits on element depth, total element count, and the count of
  elements with a given name are enforced while parsing.

U+0000 and surrogate code points cannot occur in a well-formed XML 1.0
document, raw or as a character reference; expat rejects both as not
well-formed, so the parser-failure outcome satisfies External String
Admissibility (docs/conventions.md) without an additional check.

Byte, decompression, and ratio limits belong to the caller's transport
layer. Element names are reported with namespace processing: a name in a
namespace is `"{uri} {local}"` and a name in no namespace is `"{local}"`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Literal, Protocol
from xml.parsers import expat

XMLFailureReason = Literal["malformed", "forbidden_construct", "resource_limit"]

NAMESPACE_SEPARATOR: Final = " "
"""Separator between namespace URI and local name in reported names."""


class XMLSafetyError(Exception):
    """The document is not accepted.

    `reason` is bounded: `malformed` (not well-formed, or incomplete when
    finalized), `forbidden_construct` (DTD, entity or notation declaration,
    external reference), or `resource_limit` (a configured limit was
    exceeded). The message never contains document content.
    """

    def __init__(self, reason: XMLFailureReason) -> None:
        super().__init__(f"XML document rejected: {reason}")
        self.reason: XMLFailureReason = reason


@dataclass(frozen=True, slots=True)
class XMLLimits:
    """Optional parsing limits; `None` means unlimited.

    `max_depth` counts the root element as depth 1. `max_element_counts`
    bounds the number of elements with an exact reported name anywhere in
    the document.
    """

    max_depth: int | None = None
    max_elements: int | None = None
    max_element_counts: Mapping[str, int] = field(default_factory=dict)


class XMLContentHandler(Protocol):
    """Receives parsing events in document order.

    An exception raised by a handler method propagates from `feed()` or
    `close()` unchanged, and the parser is unusable afterwards.
    """

    def start_element(self, name: str, attributes: dict[str, str]) -> None: ...

    def end_element(self, name: str) -> None: ...

    def character_data(self, data: str) -> None: ...


class SafeXMLParser:
    """Incremental expat parser enforcing the restrictions above.

    Feed the document in any chunking with `feed()`, then call `close()`
    exactly once. Any failure raises `XMLSafetyError` (or the handler's own
    exception) and leaves the parser unusable.
    """

    def __init__(
        self, handler: XMLContentHandler, *, limits: XMLLimits | None = None
    ) -> None:
        self._handler = handler
        self._limits = limits or XMLLimits()
        self._depth = 0
        self._elements = 0
        self._name_counts: dict[str, int] = {}
        self._failed = False
        self._closed = False

        parser = expat.ParserCreate(namespace_separator=NAMESPACE_SEPARATOR)
        parser.buffer_text = True
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        parser.StartDoctypeDeclHandler = self._forbidden
        parser.EntityDeclHandler = self._forbidden
        parser.UnparsedEntityDeclHandler = self._forbidden
        parser.NotationDeclHandler = self._forbidden
        parser.ExternalEntityRefHandler = self._forbidden_external
        parser.StartElementHandler = self._start
        parser.EndElementHandler = self._end
        parser.CharacterDataHandler = handler.character_data
        self._parser = parser

    def feed(self, data: bytes) -> None:
        """Parse the next chunk of the document."""
        self._parse(data, final=False)

    def close(self) -> None:
        """Finalize the document; incomplete documents are `malformed`."""
        self._parse(b"", final=True)
        self._closed = True

    def _parse(self, data: bytes, *, final: bool) -> None:
        if self._failed or self._closed:
            raise RuntimeError("SafeXMLParser is no longer usable")
        try:
            self._parser.Parse(data, final)
        except expat.ExpatError:
            self._failed = True
            raise XMLSafetyError("malformed") from None
        except BaseException:
            self._failed = True
            raise

    def _forbidden(self, *_: object) -> None:
        raise XMLSafetyError("forbidden_construct")

    def _forbidden_external(self, *_: object) -> int:
        raise XMLSafetyError("forbidden_construct")

    def _start(self, name: str, attributes: dict[str, str]) -> None:
        limits = self._limits
        self._depth += 1
        self._elements += 1
        if limits.max_depth is not None and self._depth > limits.max_depth:
            raise XMLSafetyError("resource_limit")
        if limits.max_elements is not None and self._elements > limits.max_elements:
            raise XMLSafetyError("resource_limit")
        maximum = limits.max_element_counts.get(name)
        if maximum is not None:
            count = self._name_counts.get(name, 0) + 1
            if count > maximum:
                raise XMLSafetyError("resource_limit")
            self._name_counts[name] = count
        self._handler.start_element(name, attributes)

    def _end(self, name: str) -> None:
        self._depth -= 1
        self._handler.end_element(name)
