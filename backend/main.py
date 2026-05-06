"""
API Guardian demo backend.

A small SaaS-like API designed to showcase:
  - Schema validation (path/query/body/headers/response) via API Guardian
  - False positives that CRS/managed rules would produce on legitimate API traffic
  - Unattended OIDC discovery & enforcement (via Keycloak)

The OAS spec is augmented with `x-bunny-shield` extensions on selected
parameters and an `openIdConnect` securityScheme so Shield can fetch the
discovery document automatically.
"""

from __future__ import annotations

import os
import uuid
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query
from enum import Enum
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8080/realms/demo")
OIDC_DISCOVERY_URL = f"{OIDC_ISSUER}/.well-known/openid-configuration"
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000")

app = FastAPI(
    title="API Guardian Demo",
    version="1.0.0",
    description=(
        "Demo API for showcasing Bunny Shield's API Guardian. "
        "Endpoints are intentionally shaped to produce false positives "
        "with legacy WAF rules, while remaining valid against this schema."
    ),
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Category(str, Enum):
    networking = "networking"
    databases = "databases"
    caching = "caching"
    security = "security"


class Product(BaseModel):
    id: str
    name: str
    category: str
    price: float
    rating: float


class ProductList(BaseModel):
    items: list[Product]
    total: int


class ReviewIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"additionalProperties": False})
    productId: str = Field(..., min_length=1, max_length=64)
    rating: int = Field(..., ge=1, le=5)
    comment: str = Field(..., min_length=1, max_length=500)


class ReviewOut(BaseModel):
    id: str
    productId: str
    rating: int
    comment: str


class Account(BaseModel):
    id: str
    email: str
    plan: str


class OrderIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"additionalProperties": False})
    productId: str = Field(..., min_length=1, max_length=64)
    quantity: int = Field(..., ge=1, le=100)


class OrderOut(BaseModel):
    id: str
    productId: str
    quantity: int
    status: str


# ---------------------------------------------------------------------------
# Fake data
# ---------------------------------------------------------------------------


PRODUCTS: list[Product] = [
    Product(id="11111111-1111-1111-1111-111111111111", name="Acme Router 3000", category="networking", price=199.0, rating=4.6),
    Product(id="22222222-2222-2222-2222-222222222222", name="QuantumDB Pro",    category="databases",  price=499.0, rating=4.8),
    Product(id="33333333-3333-3333-3333-333333333333", name="HyperCache",       category="caching",    price=89.0,  rating=4.2),
    Product(id="44444444-4444-4444-4444-444444444444", name="Sentinel WAF",     category="security",   price=299.0, rating=4.9),
]


# ---------------------------------------------------------------------------
# Auth dependency (real verification happens at the edge via Shield)
# ---------------------------------------------------------------------------


def require_bearer(authorization: Annotated[str | None, Header()] = None) -> str:
    """
    Backend trusts that Shield has already verified the JWT against the OIDC
    provider's JWKS. We just sanity-check that *some* bearer token is present
    so local dev still behaves predictably.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return authorization.split(" ", 1)[1]


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------


@app.get(
    "/api/products",
    response_model=ProductList,
    tags=["catalog"],
    summary="Search products",
)
def list_products(
    q: str | None = Query(
        default=None,
        max_length=200,
        description="Free-text search. Intentionally NOT scanned for SQLi/XSS — users may legitimately search for strings like \"1' OR rating>4\".",
    ),
    category: Category | None = Query(
        default=None,
        description="Product category. Strict enum + injection scanning at the edge.",
    ),
    limit: int = Query(default=20, ge=1, le=100),
) -> ProductList:
    items = PRODUCTS
    if category:
        items = [p for p in items if p.category == category.value]
    if q:
        ql = q.lower()
        items = [p for p in items if ql in p.name.lower()]
    return ProductList(items=items[:limit], total=len(items))


@app.get(
    "/api/products/{productId}",
    response_model=Product,
    tags=["catalog"],
    summary="Get a product by ID",
)
def get_product(
    productId: uuid.UUID = Path(
        ...,
        description="Product UUID. Strictly validated as a UUID; AGD also scans for injection at the edge.",
    ),
) -> Product:
    target = str(productId)
    for p in PRODUCTS:
        if p.id == target:
            return p
    raise HTTPException(status_code=404, detail="not found")


@app.post(
    "/api/reviews",
    response_model=ReviewOut,
    status_code=201,
    tags=["reviews"],
    summary="Submit a product review",
)
def create_review(review: ReviewIn) -> ReviewOut:
    return ReviewOut(
        id=str(uuid.uuid4()),
        productId=review.productId,
        rating=review.rating,
        comment=review.comment,
    )


# ---------------------------------------------------------------------------
# OIDC-protected endpoints
# ---------------------------------------------------------------------------


@app.get(
    "/api/account",
    response_model=Account,
    tags=["account"],
    summary="Get the current user account",
    openapi_extra={"security": [{"oidc": ["openid", "profile", "email"]}]},
)
def get_account(_token: str = Depends(require_bearer)) -> JSONResponse:
    # Deliberately returns an extra `internalNotes` field that is NOT in the
    # response schema. Use this to demo response-validation enforcement.
    leaky_payload: dict[str, Any] = {
        "id": "user-42",
        "email": "demo@example.com",
        "plan": "pro",
        "internalNotes": "do_not_leak: customer flagged for upsell",
    }
    return JSONResponse(content=leaky_payload)


@app.post(
    "/api/orders",
    response_model=OrderOut,
    status_code=201,
    tags=["orders"],
    summary="Place an order",
    openapi_extra={"security": [{"oidc": ["openid", "profile", "email"]}]},
)
def create_order(order: OrderIn, _token: str = Depends(require_bearer)) -> OrderOut:
    return OrderOut(
        id=str(uuid.uuid4()),
        productId=order.productId,
        quantity=order.quantity,
        status="confirmed",
    )


# ---------------------------------------------------------------------------
# Frontend (static SPA-ish single page)
# ---------------------------------------------------------------------------


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse("static/index.html")


@app.get("/config.js", include_in_schema=False)
def config_js() -> Response:
    """Expose a tiny runtime config so the static frontend can find Keycloak."""
    client_id = os.environ.get("OIDC_CLIENT_ID", "demo-spa")
    body = (
        "window.DEMO_CONFIG = {\n"
        f'  oidcIssuer: "{OIDC_ISSUER}",\n'
        f'  oidcClientId: "{client_id}",\n'
        f'  apiBase: "{PUBLIC_BASE_URL}"\n'
        "};\n"
    )
    return Response(content=body, media_type="application/javascript")


# ---------------------------------------------------------------------------
# OpenAPI customization: inject OIDC securityScheme + servers
# ---------------------------------------------------------------------------


SHIELD_HINTS: dict[tuple[str, str, str, str], str] = {
    # (path, method, in, name) -> x-bunny-shield value
    ("/api/products", "get", "query", "category"): "detectsqli,detectxss",
    ("/api/products/{productId}", "get", "path", "productId"): "detectsqli,detectxss",
}


def _apply_shield_hints(schema: dict[str, Any]) -> None:
    for path, methods in schema.get("paths", {}).items():
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue
            for param in op.get("parameters", []) or []:
                key = (path, method, param.get("in"), param.get("name"))
                hint = SHIELD_HINTS.get(key)
                if hint:
                    param.setdefault("schema", {})["x-bunny-shield"] = hint


def custom_openapi() -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    schema["servers"] = [{"url": PUBLIC_BASE_URL}]
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["oidc"] = {
        "type": "openIdConnect",
        "openIdConnectUrl": OIDC_DISCOVERY_URL,
    }
    _apply_shield_hints(schema)
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi  # type: ignore[assignment]
