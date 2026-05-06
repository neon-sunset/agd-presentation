"""
API Guardian demo backend.

A small SaaS-like API designed to showcase:
  - Schema validation (path/query/body/headers/response) via API Guardian
  - False positives that CRS/managed rules would produce on legitimate API traffic
  - Bearer JWT auth — AGD does structural validation at the edge

The OAS spec is augmented with `x-bunny-shield` extensions on selected
parameters and a `bearerAuth` (HTTP bearer / JWT) security scheme on the
protected endpoints.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Annotated, Any

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request
from enum import Enum
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-demo-secret-change-me-in-prod")
JWT_ALG = "HS256"
JWT_TTL_SECONDS = 3600

DEMO_USERS: dict[str, dict[str, Any]] = {
    "demo": {"password": "demo", "email": "demo@example.com", "roles": ["user"]},
    "alice": {"password": "alice", "email": "alice@example.com", "roles": ["user", "admin"]},
}

app = FastAPI(
    title="API Guardian Demo",
    version="1.0.0",
    description=(
        "Demo API for showcasing Bunny Shield's API Guardian. "
        "Endpoints are intentionally shaped to produce false positives "
        "with legacy WAF rules, while remaining valid against this schema."
    ),
    openapi_url=None,  # we serve /openapi.json ourselves so the `servers` block is request-derived
    docs_url=None,
    redoc_url=None,
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
# Auth: tiny in-process JWT (HS256). Shield does structural validation at the
# edge; the backend additionally verifies the signature so local runs without
# Shield still behave like prod.
# ---------------------------------------------------------------------------


class LoginIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"additionalProperties": False})
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class LoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def mint_jwt(username: str, roles: list[str]) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "roles": roles,
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
        "iss": "agd-demo",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def require_bearer(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1]
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"invalid token: {e}")


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
# Login + JWT-protected endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/api/login",
    response_model=LoginOut,
    tags=["auth"],
    summary="Issue a Bearer JWT for the demo users (demo/demo, alice/alice)",
)
def login(creds: LoginIn) -> LoginOut:
    user = DEMO_USERS.get(creds.username)
    if not user or user["password"] != creds.password:
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = mint_jwt(creds.username, user["roles"])
    return LoginOut(access_token=token, expires_in=JWT_TTL_SECONDS)


@app.get(
    "/api/account",
    response_model=Account,
    tags=["account"],
    summary="Get the current user account",
    openapi_extra={"security": [{"bearerAuth": []}]},
)
def get_account(claims: dict = Depends(require_bearer)) -> JSONResponse:
    # Deliberately returns an extra `internalNotes` field that is NOT in the
    # response schema. Use this to demo response-validation enforcement.
    username = claims.get("sub", "unknown")
    leaky_payload: dict[str, Any] = {
        "id": f"user-{username}",
        "email": DEMO_USERS.get(username, {}).get("email", f"{username}@example.com"),
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
    openapi_extra={"security": [{"bearerAuth": []}]},
)
def create_order(order: OrderIn, _claims: dict = Depends(require_bearer)) -> OrderOut:
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


# ---------------------------------------------------------------------------
# OpenAPI customization: inject bearerAuth securityScheme + servers
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


def _public_base_url(request: Request) -> str:
    """
    Resolve the externally-visible base URL from the inbound request, so the
    OAS `servers` block reflects whatever host (PZ, MC URL, localhost) the
    spec was fetched through. Honors X-Forwarded-Host / -Proto when present
    (set by Pull Zone / MC ingress), falls back to the request's own host.
    """
    headers = request.headers
    proto = (headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip()
    host = (headers.get("x-forwarded-host") or headers.get("host") or "").split(",")[0].strip()
    if not host:
        host = "localhost:8000"
    return f"{proto}://{host}"


def _downconvert_to_oas_30(node: Any) -> Any:
    """
    Walk the schema tree and rewrite OAS 3.1-isms that FastAPI emits into
    OAS 3.0-compatible equivalents. API Guardian matches Cloudflare's API
    Gateway and validates against 3.0.x — 3.1-only constructs are rejected.

    Currently rewrites the most common one Pydantic v2 produces:
      `anyOf: [<schema>, {"type": "null"}]`  →  `<schema>` + `nullable: true`
    """
    if isinstance(node, dict):
        any_of = node.get("anyOf")
        if isinstance(any_of, list):
            non_null = [s for s in any_of if not (isinstance(s, dict) and s.get("type") == "null")]
            had_null = len(non_null) != len(any_of)
            if had_null and len(non_null) == 1 and isinstance(non_null[0], dict):
                merged = {**non_null[0], **{k: v for k, v in node.items() if k != "anyOf"}}
                merged["nullable"] = True
                return _downconvert_to_oas_30(merged)
            if had_null:
                node = {**node, "anyOf": non_null, "nullable": True}
        return {k: _downconvert_to_oas_30(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_downconvert_to_oas_30(v) for v in node]
    return node


@app.get("/openapi.json", include_in_schema=False)
def openapi_spec(request: Request) -> JSONResponse:
    from fastapi.openapi.utils import get_openapi

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        openapi_version="3.0.3",
    )
    schema["servers"] = [{"url": _public_base_url(request)}]
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    _apply_shield_hints(schema)
    schema = _downconvert_to_oas_30(schema)
    return JSONResponse(content=schema)
