"""Schemas for the Product catalog list endpoint.

See `docs/features/packages/product-catalog.md` (List Products: query
parameters, response, Product list item) and `docs/api-spec.md` (Product
Identifier Resolution): the canonical CPE is the public Product identity,
and the internal `Product.id` is never serialized.

Every enumerated value is serialized in lowercase.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.core.enums import ProductSortField, SortOrder
from app.schemas.common import PaginationMeta

type CatalogPresenceValue = Literal["current", "historical"]
type LifecyclePhaseValue = Literal[
    "pre_release", "general_support", "extended_support", "reactive_support", "eol"
]


class ProductListQuery(BaseModel):
    """Query parameters of `GET /api/v1/products` (product-catalog.md,
    List Products > Query parameters).

    `catalog_presence` and `lifecycle_phase` are intentionally raw
    repeatable strings: an invalid value is silently dropped rather than
    rejected (`docs/api-spec.md`, Enum Filter Validation), and an empty
    list means the filter was omitted. `sort_by` and `sort_order` are
    typed, so an invalid value is the global `422 VALIDATION_ERROR` (Sort
    Parameter Validation). String parameters share the global
    500-character limit, applied to the raw values before this model is
    built.
    """

    search: str | None = None
    cpe: str | None = None
    catalog_presence: list[str] = Field(default_factory=list)
    lifecycle_phase: list[str] = Field(default_factory=list)
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)
    sort_by: ProductSortField = ProductSortField.NAME
    sort_order: SortOrder = SortOrder.ASC


class ProductListItem(BaseModel):
    """One catalog Product in `GET /api/v1/products` (product-catalog.md,
    List Products > Product list item). All four lifecycle-date fields and
    `lifecycle_phase` are always present, `null` when unavailable."""

    name: str = Field(description="Descriptive SMELT name.")
    version: str = Field(description="Descriptive SMELT version.")
    display_name: str = Field(description="Human-readable SMELT name.")
    cpe: str = Field(description="Canonical Product CPE: the public Product identity.")
    catalog_presence: CatalogPresenceValue = Field(
        description=(
            "Derived: `current` when the Product belongs to the selected latest "
            "complete SMELT snapshot; otherwise `historical`."
        )
    )
    catalog_last_seen_at: datetime = Field(
        description=(
            "UTC timestamp of the latest complete SMELT snapshot that observed "
            "this Product."
        )
    )
    first_customer_ship_date: date | None = Field(
        description="AIMAAS first-customer-ship date."
    )
    general_support_end_date: date | None = Field(
        description="AIMAAS General Support end date."
    )
    extended_support_end_date: date | None = Field(
        description="Latest AIMAAS LTSS or ESPOS end date."
    )
    reactive_support_end_date: date | None = Field(
        description="AIMAAS Reactive LTSS end date."
    )
    lifecycle_phase: LifecyclePhaseValue | None = Field(
        description=(
            "Derived current lifecycle phase on the request's UTC date; `null` "
            "when it cannot be established (absent, incomplete, or inconsistent "
            "AIMAAS dates)."
        )
    )
    cvss_threshold: float | None = Field(
        description="AIMAAS CVSS threshold; `null` means the implicit threshold of 0."
    )
    created_at: datetime = Field(description="Product-record creation timestamp (UTC).")
    updated_at: datetime = Field(
        description="Timestamp of the latest persisted Product change (UTC)."
    )


class ProductListResponse(BaseModel):
    """Response body of `GET /api/v1/products` (paginated)."""

    data: list[ProductListItem]
    meta: PaginationMeta
