"""Shared SMELT Product listing fixtures for contract and fetcher tests.

The files under `backend/tests/fixtures/smelt/` are live
`v1/basic/products/` pages (first, middle, and final) captured from the
default `SMELT_API_URL` with `page_size=100`, stored as served. They
contain Product catalog data only; no personal identifier was present
(docs/conventions.md, External Integration Contract Verification).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "smelt"

# Page numbers of the captured live pages.
FIXTURE_PAGES = (1, 2, 6)


def load_products_page(page: int) -> dict[str, Any]:
    """Return one captured live Product listing page as parsed JSON."""
    path = FIXTURE_DIR / f"products_page_{page}.json"
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data
