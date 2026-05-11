from typing import Any

from authlib.integrations.starlette_client import OAuth
from fastapi import Request

from auth_framework.auth.user import AuthenticatedUser, map_attributes
from auth_framework.config.models import OidcProviderConfig


class OidcService:
    def __init__(self, provider: OidcProviderConfig, oauth: OAuth):
        self.provider = provider
        self.oauth = oauth
        self.client_name = provider.slug
        self._register_client()

    def _register_client(self) -> None:
        client_kwargs = {"scope": " ".join(self.provider.scopes)}
        register_kwargs: dict[str, Any] = {
            "name": self.client_name,
            "client_id": self.provider.client_id,
            "client_secret": self.provider.client_secret.get_secret_value(),
            "client_kwargs": client_kwargs,
        }
        if self.provider.server_metadata_url:
            register_kwargs["server_metadata_url"] = str(self.provider.server_metadata_url)
        elif self.provider.issuer:
            register_kwargs["server_metadata_url"] = (
                str(self.provider.issuer).rstrip("/") + "/.well-known/openid-configuration"
            )
        else:
            register_kwargs.update(
                {
                    "authorize_url": str(self.provider.authorize_url),
                    "access_token_url": str(self.provider.token_url),
                    "userinfo_endpoint": str(self.provider.userinfo_url)
                    if self.provider.userinfo_url
                    else None,
                    "jwks_uri": str(self.provider.jwks_uri),
                }
            )
        self.oauth.register(**{k: v for k, v in register_kwargs.items() if v is not None})

    async def authorize_redirect(self, request: Request) -> Any:
        client = self.oauth.create_client(self.client_name)
        return await client.authorize_redirect(request, str(self.provider.redirect_uri))

    async def process_callback(self, request: Request) -> AuthenticatedUser:
        client = self.oauth.create_client(self.client_name)
        token = await client.authorize_access_token(request)
        raw_claims = token.get("userinfo")
        if not raw_claims:
            raw_claims = await client.userinfo(token=token)
        claims = dict(raw_claims)
        subject = claims.get("sub")
        return map_attributes(self.provider, claims, subject=subject)
