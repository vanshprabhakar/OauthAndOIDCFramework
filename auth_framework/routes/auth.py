from typing import Any

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from auth_framework.config.models import AppSettings, OidcProviderConfig, SamlProviderConfig
from auth_framework.config.settings import get_settings
from auth_framework.oidc.service import OidcService
from auth_framework.providers.registry import ProviderRegistry
from auth_framework.routes.dependencies import (
    get_oauth_registry,
    get_oidc_provider,
    get_registry,
    get_saml_provider,
    get_session_manager,
)
from auth_framework.saml.service import SamlService
from auth_framework.sessions.jwt import SessionManager
from auth_framework.utils.http import prepare_saml_request_data
from auth_framework.utils.redirects import safe_relative_redirect

router = APIRouter(prefix="/auth", tags=["auth"])


def _session_response(
    user_token: str,
    settings: AppSettings,
    redirect_to: str | None = None,
) -> Response:
    response: Response
    if redirect_to:
        response = RedirectResponse(redirect_to, status_code=303)
    else:
        response = JSONResponse({"access_token": user_token, "token_type": "bearer"})
    response.set_cookie(
        key=settings.session.cookie_name,
        value=user_token,
        httponly=True,
        secure=settings.session.cookie_secure,
        samesite=settings.session.cookie_samesite,
        max_age=settings.session.expiration_minutes * 60,
    )
    return response


@router.get("/providers")
def list_providers(registry: ProviderRegistry = Depends(get_registry)) -> dict[str, Any]:
    return {
        "providers": [
            {
                "slug": provider.slug,
                "provider_name": provider.provider_name,
                "protocol": provider.protocol,
                "login_url": f"/auth/{provider.slug}/login",
            }
            for provider in registry.list_enabled()
        ]
    }


@router.get("/{slug}/metadata")
def saml_metadata(provider: SamlProviderConfig = Depends(get_saml_provider)) -> Response:
    metadata = SamlService(provider).metadata_xml()
    return Response(content=metadata, media_type="application/samlmetadata+xml")


@router.get("/{slug}/login")
async def login(
    slug: str,
    request: Request,
    return_to: str | None = None,
    registry: ProviderRegistry = Depends(get_registry),
    oauth: OAuth = Depends(get_oauth_registry),
):
    try:
        provider = registry.get(slug)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Provider not found") from exc

    if isinstance(provider, SamlProviderConfig):
        request_data = prepare_saml_request_data(request)
        redirect_url = SamlService(provider).login_url(request_data, return_to=return_to)
        return RedirectResponse(redirect_url)

    if isinstance(provider, OidcProviderConfig):
        if return_to:
            request.session["return_to"] = safe_relative_redirect(return_to)
        return await OidcService(provider, oauth).authorize_redirect(request)

    raise HTTPException(status_code=400, detail="Unsupported provider protocol")


@router.post("/{slug}/acs")
async def saml_acs(
    request: Request,
    slug: str,
    saml_response: str = Form(..., alias="SAMLResponse"),
    relay_state: str | None = Form(None, alias="RelayState"),
    provider: SamlProviderConfig = Depends(get_saml_provider),
    session_manager: SessionManager = Depends(get_session_manager),
    settings: AppSettings = Depends(get_settings),
):
    form_data = {"SAMLResponse": saml_response}
    if relay_state:
        form_data["RelayState"] = relay_state
    request_data = prepare_saml_request_data(request, form_data=form_data)
    try:
        user = SamlService(provider).process_acs(request_data)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    token = session_manager.create_token(user)
    return _session_response(token, settings, redirect_to=safe_relative_redirect(relay_state))


@router.get("/{slug}/callback")
async def oidc_callback(
    request: Request,
    provider: OidcProviderConfig = Depends(get_oidc_provider),
    oauth: OAuth = Depends(get_oauth_registry),
    session_manager: SessionManager = Depends(get_session_manager),
    settings: AppSettings = Depends(get_settings),
):
    try:
        user = await OidcService(provider, oauth).process_callback(request)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="OIDC authentication failed") from exc
    token = session_manager.create_token(user)
    return_to = safe_relative_redirect(request.session.pop("return_to", None))
    return _session_response(token, settings, redirect_to=return_to)


@router.post("/logout")
def logout(settings: AppSettings = Depends(get_settings)) -> JSONResponse:
    response = JSONResponse({"detail": "Logged out"})
    response.delete_cookie(settings.session.cookie_name)
    return response
