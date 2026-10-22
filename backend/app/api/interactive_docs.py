"""The interactive API documentation page, `GET /api/docs`.

See `docs/api-spec.md` (OpenAPI Document and Interactive Documentation).
FastAPI's own `/docs` and `/redoc` pages load the latest release of their
viewer from a CDN on every request; `app.main` disables them and serves
this page instead, which loads one exact Swagger UI release. The page runs
in the API's origin, where the session cookie is valid, so a viewer
release that changed without review would run with the access of every
user who opens it.
"""

from __future__ import annotations

from typing import Final

from fastapi import Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse

SWAGGER_UI_DIST: Final = "https://unpkg.com/swagger-ui-dist@5.34.0/"
"""The Swagger UI release the page loads. Renovate's unpkg custom manager
(`renovate.jsonc`) matches this literal URL and updates it together with
the copy of the GitHub Pages site (`.github/workflows/deploy-api-docs.yml`);
`tests/test_workflow_tool_pins.py` keeps both copies in that form and on
the same version."""


async def swagger_ui_html(request: Request) -> HTMLResponse:
    """Render Swagger UI over the application's OpenAPI document, with the
    operation filter enabled. The document URL keeps the request's
    `root_path`, as FastAPI's own page does. The response forbids framing,
    so that a page on another host of the same site cannot display it with
    the user's session cookie."""
    root_path = request.scope.get("root_path", "").rstrip("/")
    response = get_swagger_ui_html(
        openapi_url=root_path + request.app.openapi_url,
        title=f"{request.app.title} - Swagger UI",
        swagger_js_url=f"{SWAGGER_UI_DIST}swagger-ui-bundle.js",
        swagger_css_url=f"{SWAGGER_UI_DIST}swagger-ui.css",
        swagger_favicon_url=f"{SWAGGER_UI_DIST}favicon-32x32.png",
        swagger_ui_parameters={"filter": True},
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return response
