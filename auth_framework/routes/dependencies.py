from functools import lru_cache

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, HTTPException

from auth_framework.config.models import AppSettings, OidcProviderConfig, SamlProviderConfig
from auth_framework.config.settings import get_settings
from auth_framework.providers.registry import ProviderRegistry
from auth_framework.sessions.jwt import SessionManager


@lru_cache
def get_oauth_registry() -> OAuth:
    return OAuth()


def get_registry(settings: AppSettings = Depends(get_settings)) -> ProviderRegistry:
    return ProviderRegistry(settings)


def get_session_manager(settings: AppSettings = Depends(get_settings)) -> SessionManager:
    return SessionManager(settings.session)


def get_saml_provider(
    slug: str, registry: ProviderRegistry = Depends(get_registry)
) -> SamlProviderConfig:
    try:
        provider = registry.get(slug)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Provider not found") from exc
    if not isinstance(provider, SamlProviderConfig):
        raise HTTPException(status_code=400, detail="Provider is not configured for SAML")
    return provider


def get_oidc_provider(
    slug: str, registry: ProviderRegistry = Depends(get_registry)
) -> OidcProviderConfig:
    try:
        provider = registry.get(slug)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Provider not found") from exc
    if not isinstance(provider, OidcProviderConfig):
        raise HTTPException(status_code=400, detail="Provider is not configured for OIDC")
    return provider
