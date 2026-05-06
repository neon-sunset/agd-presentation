# API Guardian Presentation Demo

A small demo app that pairs with **Bunny Shield's API Guardian** to showcase:

1. **False positives** that legacy CRS/managed rules produce on legitimate API traffic.
2. **Schema-aware blocking** by API Guardian when fed an OpenAPI 3.0 spec.
3. **Unattended OIDC discovery & enforcement** — Shield fetches the issuer's
   `.well-known/openid-configuration` automatically and validates JWTs at the edge.

## Components

- **`backend/`** — FastAPI app exposing a small SaaS-like API plus a static
  one-page frontend. Auto-generates an OAS 3.0 spec at `/openapi.json` with
  `x-bunny-shield` extensions and an `openIdConnect` security scheme.
- **`keycloak/`** — Keycloak with a pre-seeded `demo` realm, a `demo-spa`
  public client (PKCE), and two users.

## Local run

```bash
cp .env.example .env   # then edit values
docker compose up --build
```

- App: <http://localhost:8000>
- Keycloak admin: <http://localhost:8080> (creds from your `.env`)
- OIDC discovery: <http://localhost:8080/realms/demo/.well-known/openid-configuration>
- OpenAPI spec: <http://localhost:8000/openapi.json>

Demo users: `demo / demo`, `alice / alice` (alice has the `admin` role).

## Production deployment (Magic Containers)

Two services, both pulled from GHCR (built by `.github/workflows/publish.yml`
on push to `main`):

| Service       | Image                                                     | Port |
|---------------|-----------------------------------------------------------|------|
| Backend + UI  | `ghcr.io/neon-sunset/agd-presentation-api:latest`         | 8000 |
| Keycloak IdP  | `ghcr.io/neon-sunset/agd-presentation-idp:latest`         | 8080 |

### Deploy the IdP first

It needs to be reachable from the Bunny edge so Shield can fetch the
discovery document. **Do not put a Pull Zone in front of Keycloak.**

**Required env vars (no defaults — boot will fail without them):**

- `KC_BOOTSTRAP_ADMIN_USERNAME` — pick a non-obvious username
- `KC_BOOTSTRAP_ADMIN_PASSWORD` — generate with e.g. `openssl rand -base64 24`

These are the bootstrap admin credentials for Keycloak's master realm. Once
the IdP is publicly reachable, anyone who finds it will try `admin/admin`,
so do not use those values. The image deliberately ships **without** any
default — Keycloak will refuse to start if both vars aren't set.

After it boots, copy its public URL — call it `IDP_URL`. Verify:

```bash
curl https://$IDP_URL/realms/demo/.well-known/openid-configuration
```

### Deploy the backend

Required env vars:

- `OIDC_ISSUER` = `https://IDP_URL/realms/demo`
- `OIDC_CLIENT_ID` = `demo-spa`
- `PUBLIC_BASE_URL` = `https://APP_URL` (the public URL of the backend, used
  in the OAS `servers` block and surfaced to the frontend)

After it boots, put a Pull Zone in front of it (`APP_URL` is the origin).

### Update Keycloak's allowed redirect URIs

The seeded realm allows `https://*.b-cdn.net/*`, `https://*.bunny.run/*`,
and `https://*.bunny.net/*`. If your Pull Zone hostname doesn't match, log
into Keycloak admin → Clients → `demo-spa` → add the callback URL.

## Demo arc (recommended order)

1. **Show the app working with no Shield.** Fire each green button under
   "Public catalog" — products list, search, get one, submit review. Sign
   in via the top-right button, fire account/order. Everything works.

2. **Enable Shield with managed rules only.** Re-fire:
   - "Search '1' OR rating>4'" — false-positive **block** (CRS reads SQLi).
   - "Submit review" with the comment containing "SELECT" — also blocked.
   - The audience sees: *managed rules break legit users.*

3. **Switch to API Guardian.** Upload the OAS at `/openapi.json` and
   activate. Re-fire the same buttons:
   - Legitimate ones now succeed.
   - Press the red attack buttons — each is blocked at the edge with a
     specific reason (wrong type, out of range, missing required field,
     extra field, path-param injection on a parameter tagged
     `detectsqli`).

4. **OIDC beat.** Show that Shield auto-discovered the IdP — no manual JWKS
   upload, no allowlist for `/authorize` or `/token`. Fire "Account without
   token" and "Account with junk token": both rejected at the edge before
   reaching origin.

5. **Response validation.** The signed-in `Get account` call has a backend
   that intentionally returns an extra `internalNotes` field. Shield's
   response-phase rule blocks it — origin leaks, edge stops it.

## Endpoints reference

| Method | Path                             | Purpose                                        |
|--------|----------------------------------|------------------------------------------------|
| GET    | `/api/products`                  | List/search products. `q` is unguarded; `category` is enum + `detectsqli,detectxss`. |
| GET    | `/api/products/{productId}`      | Get one. Path param is `format: uuid` + injection scan. |
| POST   | `/api/reviews`                   | Create review. Strict body schema. |
| GET    | `/api/account`                   | OIDC-protected. Backend leaks an extra field for response-validation demo. |
| POST   | `/api/orders`                    | OIDC-protected. Validates JWT at edge. |

## Files of interest

- [backend/main.py](backend/main.py) — endpoint definitions and OAS extensions
- [backend/static/index.html](backend/static/index.html) — single-page demo frontend
- [keycloak/realm-export.json](keycloak/realm-export.json) — pre-seeded realm
