# SAML + OIDC Authentication Framework for FastAPI

A production-oriented, lightweight authentication foundation that lets a FastAPI application act as a SAML Service Provider (SP) and as an OIDC/OAuth2 relying party for external identity providers such as ADP, Okta, Azure AD, Google, BambooHR, and Greenhouse.

The goal is not to build a full IAM platform. This project provides reusable, config-driven login flows, provider onboarding, user attribute mapping, and application session issuance.

## What is included

- FastAPI application factory and runnable `uvicorn` entrypoint.
- Config-driven provider registry for SAML and OIDC providers.
- SAML SP metadata endpoint, login initiation endpoint, and ACS endpoint.
- OIDC authorization-code login and callback handling using Authlib.
- JWT-backed application session cookie and bearer-token support.
- Protected-route middleware for startup-friendly auth enforcement.
- Example ADP SAML, Okta OIDC, Azure AD OIDC, and Google config patterns.
- Dockerfile and Docker Compose setup.

## Folder structure

```text
auth_framework/
  auth/          # user model and attribute mapping
  config/        # Pydantic config models and environment loading
  middleware/    # route protection and session extraction
  oidc/          # OIDC/Authlib provider flow
  providers/     # provider registry abstraction
  routes/        # FastAPI auth routes
  saml/          # python3-saml SP integration
  sessions/      # app JWT/session issuance and validation
  utils/         # HTTP request normalization helpers
config/          # local provider configuration
examples/        # reusable provider snippets
```

## Provider configuration

Providers are primarily onboarded through `config/providers.yaml`. Each provider has a stable `slug`, a `protocol`, IdP/client settings, and an `attribute_mapping` that normalizes IdP claims into the application user model.

### SAML provider example

```yaml
provider_name: "ADP Workforce Now"
slug: "adp-saml"
protocol: "SAML"
enabled: true
metadata_url: "https://adp-idp.example.com/metadata"
entity_id: "https://auth.yourcompany.com/auth/adp-saml/metadata"
acs_url: "https://auth.yourcompany.com/auth/adp-saml/acs"
attribute_mapping:
  email: "mail"
  name: "displayName"
  first_name: "givenName"
  last_name: "sn"
  external_id: "employeeId"
allowed_domains:
  - "yourcompany.com"
```

SAML can use `metadata_url` for IdP metadata ingestion or explicit IdP fields (`idp_entity_id`, `idp_sso_url`, `idp_x509_cert`). For production, enable signed AuthnRequests when your IdP requires them and provide `sp_x509_cert` and `sp_private_key`.

### OIDC provider example

```yaml
provider_name: "Okta"
slug: "okta"
protocol: "OIDC"
enabled: true
issuer: "https://your-company.okta.com/oauth2/default"
client_id: "replace-with-client-id"
client_secret: "replace-with-client-secret"
redirect_uri: "https://auth.yourcompany.com/auth/okta/callback"
scopes:
  - "openid"
  - "email"
  - "profile"
attribute_mapping:
  email: "email"
  name: "name"
  external_id: "sub"
allowed_domains:
  - "yourcompany.com"
```

OIDC supports discovery through `issuer` or `server_metadata_url`; explicit endpoints are also supported for providers that do not expose standard discovery metadata.

## Sample login flow

1. Discover enabled providers: `GET /auth/providers`.
2. Start login: `GET /auth/{provider_slug}/login?return_to=/me`.
3. For SAML, the user is redirected to the IdP and the IdP posts the assertion to `POST /auth/{provider_slug}/acs`.
4. For OIDC, the user is redirected to the IdP and returns to `GET /auth/{provider_slug}/callback` with an authorization code.
5. The framework validates the SAML response or OIDC tokens, maps attributes, issues an application JWT, and stores it in an HTTP-only cookie.
6. Protected routes read the session from the cookie or an `Authorization: Bearer <token>` header.

## Running locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export AUTH_JWT_SECRET="dev-only-change-me"
uvicorn auth_framework.main:app --reload
```

Then open:

- Health check: <http://localhost:8000/health>
- Providers: <http://localhost:8000/auth/providers>
- SAML metadata: <http://localhost:8000/auth/adp-saml/metadata> after enabling/configuring the SAML provider

The default providers are disabled because placeholder IdP settings cannot authenticate. Copy a file from `examples/` into `config/providers.yaml`, replace values, and set `enabled: true`.

## Docker

```bash
docker compose up --build
```

The image installs XML security system dependencies required by `python3-saml`.

## Reusable vs provider-specific components

Reusable components:

- Provider registry and Pydantic configuration models.
- SAML SP route structure, metadata generation, ACS validation, and attribute extraction.
- OIDC authorization-code flow, token exchange, userinfo retrieval, and claims mapping.
- JWT session creation, cookie handling, bearer-token parsing, and protected-path middleware.
- Normalized `AuthenticatedUser` model.

Provider-specific components:

- IdP metadata URL or SAML certificate and SSO endpoint.
- OIDC issuer/client credentials/redirect URI.
- Attribute mapping keys, because ADP, Okta, Azure AD, and Google use different claim names.
- Optional allowed email domains and provider-specific scopes.

## Production checklist

- Use a long random `AUTH_JWT_SECRET` from a secrets manager.
- Set `AUTH_COOKIE_SECURE=true` behind HTTPS.
- Pin production redirect URLs and ACS URLs to public HTTPS URLs.
- Store SAML private keys and OIDC client secrets outside the repository.
- Validate IdP metadata and certificate rotation procedures with each IdP.
- Restrict `allowed_domains` where appropriate.
- Put the app behind a reverse proxy that forwards scheme and host headers correctly.
- Add persistent user storage only when the product needs auditing, account linking, or profile enrichment.
- Add RBAC/admin UI later; this foundation intentionally does not include those concerns.

## Ambiguities to resolve before going live

- Which provider is first: ADP SAML, ADP OIDC, or another IdP?
- What are the exact production base URL, ACS URL, and redirect URI?
- Which IdP attributes should be considered stable unique identifiers?
- Should sessions be cookie-only, bearer-token-only, or both?
- Do you need single logout (SLO), or is application logout sufficient initially?
- Do you need persistent users in PostgreSQL now, or can that remain an extension point?
