"""Tests for the interactive API documentation page
(`app/api/interactive_docs.py`).

See `docs/api-spec.md` (OpenAPI Document and Interactive Documentation).
That the pinned release is the GitHub Pages site's and stays in the form
Renovate tracks is checked in `tests/test_workflow_tool_pins.py`.
"""

from __future__ import annotations

import re
from typing import Final

import pytest
from httpx import AsyncClient
from starlette.requests import Request

from app.api.interactive_docs import SWAGGER_UI_DIST, swagger_ui_html
from app.main import app

_ROUTE_NOT_FOUND: Final = {
    "code": "ROUTE_NOT_FOUND",
    "detail": "No endpoint matches the request path.",
}
# Every URL the page loads: its stylesheet, icon, and scripts.
_LOADED_URL: Final = re.compile(r'(?:href|src)="([^"]+)"')


@pytest.mark.e2e
class TestInteractiveDocumentation:
    async def test_docs_page_loads_only_the_pinned_swagger_ui_release(
        self, client: AsyncClient
    ) -> None:
        response = await client.get("/docs")

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        assert sorted(_LOADED_URL.findall(response.text)) == [
            f"{SWAGGER_UI_DIST}favicon-32x32.png",
            f"{SWAGGER_UI_DIST}swagger-ui-bundle.js",
            f"{SWAGGER_UI_DIST}swagger-ui.css",
        ]
        assert "url: '/openapi.json'" in response.text
        assert '"filter": true' in response.text

    async def test_openapi_document_is_served(self, client: AsyncClient) -> None:
        response = await client.get("/openapi.json")

        assert response.status_code == 200
        assert response.json()["info"]["title"] == "Sentinel"

    @pytest.mark.parametrize("path", ["/redoc", "/docs/oauth2-redirect"])
    async def test_framework_documentation_pages_are_not_served(
        self, client: AsyncClient, path: str
    ) -> None:
        response = await client.get(path)

        assert response.status_code == 404
        assert response.json() == _ROUTE_NOT_FOUND


@pytest.mark.unit
async def test_document_url_keeps_the_root_path() -> None:
    """Behind a proxy that mounts the API under a path prefix, the page
    requests the document under the same prefix."""
    request = Request({"type": "http", "app": app, "root_path": "/sentinel/"})

    response = await swagger_ui_html(request)

    assert "url: '/sentinel/openapi.json'" in bytes(response.body).decode()
