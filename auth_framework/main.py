from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware

from auth_framework.config.settings import get_settings
from auth_framework.middleware.session import AuthSessionMiddleware
from auth_framework.routes.auth import router as auth_router
from auth_framework.sessions.jwt import SessionManager


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session.jwt_secret.get_secret_value(),
        same_site=settings.session.cookie_samesite,
        https_only=settings.session.cookie_secure,
    )
    app.add_middleware(
        AuthSessionMiddleware,
        session_manager=SessionManager(settings.session),
        cookie_name=settings.session.cookie_name,
        protected_path_prefixes=settings.session.protected_path_prefixes,
    )
    app.include_router(auth_router)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/me", tags=["auth"])
    def me(request: Request) -> dict:
        return {"user": request.state.user}

    return app


app = create_app()
