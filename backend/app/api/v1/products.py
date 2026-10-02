"""Product catalog endpoints.

See `docs/features/packages/product-catalog.md` (List Products, Product
Query Service, Security) for the authoritative endpoint contract, and
`docs/api-spec.md` (Optional Authentication on Public Endpoints; Request
Conventions; Product Identifier Resolution) for the shared behavior.

The handler stays thin: it processes optional authentication, captures the
one UTC `evaluation_date` of the request, removes invalid repeatable enum
filter values, delegates the query to `product_service.list_products()`,
and serializes the semantic projection. No database query lives here.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import OptionalCurrentUser
from app.core.enums import (
    CatalogPresence,
    LifecyclePhaseFilter,
    ProductSortField,
    SortOrder,
)
from app.database import DatabaseSession
from app.schemas.common import PaginationMeta
from app.schemas.product import ProductListItem, ProductListQuery, ProductListResponse
from app.services import product_service
from app.services.product_service import ProductListItemProjection

router = APIRouter(prefix="/api/v1", tags=["Products"])

_CATALOG_PRESENCE_FILTER: Final[Mapping[str, CatalogPresence]] = {
    member.value: member for member in CatalogPresence
}
_LIFECYCLE_PHASE_FILTER: Final[Mapping[str, LifecyclePhaseFilter]] = {
    member.value: member for member in LifecyclePhaseFilter
}


def _utc_now() -> datetime:
    """The current instant in UTC (patched by controlled-clock tests)."""
    return datetime.now(UTC)


def _valid_values[T](raw: list[str], members: Mapping[str, T]) -> tuple[T, ...]:
    """The valid members of a supplied repeatable enum filter, in request
    order and without duplicates. Invalid values, including
    comma-separated lists, are silently dropped, so an all-invalid filter
    yields an empty tuple, which the service turns into an empty page
    (`docs/api-spec.md`, Enum Filter Validation)."""
    return tuple(dict.fromkeys(members[value] for value in raw if value in members))


def _product_list_query(
    *,
    search: Annotated[
        str | None,
        Query(
            description=(
                "Case-insensitive substring match against `name`, "
                "`display_name`, `version`, or `cpe`; a Product matches when "
                "any of those fields matches. `%`, `_`, and backslash are "
                "literal."
            )
        ),
    ] = None,
    cpe: Annotated[
        str | None,
        Query(description="Exact, case-sensitive match against the canonical CPE."),
    ] = None,
    catalog_presence: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "Filter by membership in the latest complete SMELT snapshot: "
                "`current` (observed in it) or `historical` (retained, not "
                "observed in it). Repeatable; OR semantics; both values select "
                "every retained Product. Default when absent: `current`. "
                "Invalid values are ignored; only invalid values yield an "
                "empty page."
            ),
        ),
    ],
    lifecycle_phase: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "Filter by current lifecycle phase: `pre_release`, "
                "`general_support`, `extended_support`, `reactive_support`, "
                "`eol`, or the filter-only `unavailable` (no phase can be "
                "established; never emitted in a response). Repeatable; OR "
                "semantics. Invalid values are ignored; only invalid values "
                "yield an empty page."
            ),
        ),
    ],
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
    sort_by: Annotated[
        ProductSortField,
        Query(
            description=(
                "Sort field (default `name`): `name`, `display_name`, "
                "`version`, `cpe` (Unicode code-point lexical order), "
                "`catalog_last_seen_at`, or `created_at`."
            )
        ),
    ] = ProductSortField.NAME,
    sort_order: Annotated[
        SortOrder, Query(description="`asc` or `desc` (default `asc`).")
    ] = SortOrder.ASC,
) -> ProductListQuery:
    """Collect the List Products query parameters.

    Declared as individual `Query()` parameters so each one is visible to
    the shared query-length-limit dependency (`app.core.query_limits`).
    """
    return ProductListQuery(
        search=search,
        cpe=cpe,
        catalog_presence=catalog_presence,
        lifecycle_phase=lifecycle_phase,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )


def serialize_product_list_item(item: ProductListItemProjection) -> ProductListItem:
    """Map a Product list projection to its `ProductListItem` schema."""
    return ProductListItem.model_validate(
        {
            "name": item.name,
            "version": item.version,
            "display_name": item.display_name,
            "cpe": item.cpe,
            "catalog_presence": item.catalog_presence.value,
            "catalog_last_seen_at": item.catalog_last_seen_at,
            "first_customer_ship_date": item.first_customer_ship_date,
            "general_support_end_date": item.general_support_end_date,
            "extended_support_end_date": item.extended_support_end_date,
            "reactive_support_end_date": item.reactive_support_end_date,
            "lifecycle_phase": (
                item.lifecycle_phase.value if item.lifecycle_phase is not None else None
            ),
            "cvss_threshold": (
                float(item.cvss_threshold) if item.cvss_threshold is not None else None
            ),
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        }
    )


@router.get(
    "/products",
    response_model=ProductListResponse,
    summary="List Products",
    description=(
        "Returns a paginated list of the Products synchronized from SMELT, "
        "identified by their canonical CPE, with AIMAAS lifecycle dates, the "
        "derived lifecycle phase, and the CVSS threshold. By default only "
        "Products of the latest complete catalog snapshot are listed; "
        "retained historical Products are selected through "
        "`catalog_presence`. Supports search, exact CPE, repeatable catalog "
        "presence and lifecycle filters, and sorting. Before the first "
        "complete snapshot, the list is empty. Public; optional "
        "authentication."
    ),
)
async def list_products(
    db: DatabaseSession,
    principal: OptionalCurrentUser,
    query: Annotated[ProductListQuery, Depends(_product_list_query)],
) -> ProductListResponse:
    """List Products — see `docs/features/packages/product-catalog.md`
    (List Products).

    `principal` processes optional authentication (sliding session
    refresh, 401 for an invalid selected credential); the listing itself
    does not vary by caller. Captures one UTC evaluation date for the
    complete response; the service derives rows, total, catalog presence,
    and lifecycle phases from one snapshot in one statement.
    """
    del principal
    result = await product_service.list_products(
        db,
        evaluation_date=_utc_now().astimezone(UTC).date(),
        search=query.search,
        cpe=query.cpe,
        catalog_presence=(
            _valid_values(query.catalog_presence, _CATALOG_PRESENCE_FILTER)
            if query.catalog_presence
            else (CatalogPresence.CURRENT,)
        ),
        lifecycle_phase=(
            _valid_values(query.lifecycle_phase, _LIFECYCLE_PHASE_FILTER)
            if query.lifecycle_phase
            else None
        ),
        sort_by=query.sort_by,
        sort_order=query.sort_order,
        page=query.page,
        per_page=query.per_page,
    )
    return ProductListResponse(
        data=[serialize_product_list_item(item) for item in result.items],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )
