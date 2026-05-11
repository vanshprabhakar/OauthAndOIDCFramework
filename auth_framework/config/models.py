from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, field_validator, model_validator


class Protocol(StrEnum):
    SAML = "SAML"
    OIDC = "OIDC"


class AttributeMapping(BaseModel):
    email: str = "email"
    name: str = "name"
    first_name: str | None = None
    last_name: str | None = None
    external_id: str | None = None
    groups: str | None = None


class BaseProviderConfig(BaseModel):
    provider_name: str = Field(..., min_length=1)
    slug: str = Field(..., min_length=1, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    protocol: Protocol
    enabled: bool = True
    attribute_mapping: AttributeMapping = Field(default_factory=AttributeMapping)
    allowed_domains: list[str] = Field(default_factory=list)

    @field_validator("allowed_domains")
    @classmethod
    def normalize_domains(cls, value: list[str]) -> list[str]:
        return [domain.lower().strip() for domain in value]


class SamlSecurityConfig(BaseModel):
    authn_requests_signed: bool = False
    logout_request_signed: bool = False
    logout_response_signed: bool = False
    want_assertions_signed: bool = True
    want_response_signed: bool = False
    want_name_id: bool = True
    requested_authn_context: bool | list[str] = False
    signature_algorithm: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    digest_algorithm: str = "http://www.w3.org/2001/04/xmlenc#sha256"


class SamlProviderConfig(BaseProviderConfig):
    protocol: Literal[Protocol.SAML] = Protocol.SAML
    entity_id: str
    acs_url: AnyHttpUrl
    metadata_url: AnyHttpUrl | None = None
    idp_entity_id: str | None = None
    idp_sso_url: AnyHttpUrl | None = None
    idp_slo_url: AnyHttpUrl | None = None
    idp_x509_cert: str | None = None
    sp_x509_cert: str | None = None
    sp_private_key: SecretStr | None = None
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    security: SamlSecurityConfig = Field(default_factory=SamlSecurityConfig)

    @model_validator(mode="after")
    def require_metadata_or_idp_fields(self) -> "SamlProviderConfig":
        if self.metadata_url:
            return self
        missing = [
            field_name
            for field_name in ("idp_entity_id", "idp_sso_url", "idp_x509_cert")
            if getattr(self, field_name) in (None, "")
        ]
        if missing:
            raise ValueError(
                "SAML providers require metadata_url or explicit IdP fields: " + ", ".join(missing)
            )
        return self


class OidcProviderConfig(BaseProviderConfig):
    protocol: Literal[Protocol.OIDC] = Protocol.OIDC
    client_id: str
    client_secret: SecretStr
    redirect_uri: AnyHttpUrl
    issuer: AnyHttpUrl | None = None
    server_metadata_url: AnyHttpUrl | None = None
    authorize_url: AnyHttpUrl | None = None
    token_url: AnyHttpUrl | None = None
    userinfo_url: AnyHttpUrl | None = None
    jwks_uri: AnyHttpUrl | None = None
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])

    @model_validator(mode="after")
    def require_discovery_or_endpoints(self) -> "OidcProviderConfig":
        if self.server_metadata_url or self.issuer:
            return self
        missing = [
            field_name
            for field_name in ("authorize_url", "token_url", "jwks_uri")
            if getattr(self, field_name) in (None, "")
        ]
        if missing:
            raise ValueError(
                "OIDC providers require issuer/server_metadata_url or explicit endpoints: "
                + ", ".join(missing)
            )
        return self


ProviderConfig = SamlProviderConfig | OidcProviderConfig


class SessionConfig(BaseModel):
    jwt_secret: SecretStr
    jwt_issuer: str = "auth-framework"
    cookie_name: str = "app_session"
    cookie_secure: bool = True
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    expiration_minutes: int = Field(default=480, gt=0)
    protected_path_prefixes: list[str] = Field(default_factory=lambda: ["/me"])


class AppSettings(BaseModel):
    app_name: str = "SAML + OIDC Auth Framework"
    public_base_url: AnyHttpUrl = "http://localhost:8000"
    environment: str = "local"
    session: SessionConfig
    providers: list[ProviderConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def ensure_unique_provider_slugs(self) -> "AppSettings":
        slugs = [provider.slug for provider in self.providers]
        if len(slugs) != len(set(slugs)):
            raise ValueError("Provider slugs must be unique")
        return self

    def provider_by_slug(self, slug: str) -> ProviderConfig:
        for provider in self.providers:
            if provider.slug == slug and provider.enabled:
                return provider
        raise KeyError(f"Provider not found or disabled: {slug}")


def load_provider(raw: dict[str, Any]) -> ProviderConfig:
    protocol = str(raw.get("protocol", "")).upper()
    raw = {**raw, "protocol": protocol}
    if protocol == Protocol.SAML:
        return SamlProviderConfig.model_validate(raw)
    if protocol == Protocol.OIDC:
        return OidcProviderConfig.model_validate(raw)
    raise ValueError(f"Unsupported provider protocol: {protocol}")


def default_config_path() -> Path:
    return Path.cwd() / "config" / "providers.yaml"
