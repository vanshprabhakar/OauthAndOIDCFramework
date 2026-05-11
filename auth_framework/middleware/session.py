from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from auth_framework.sessions.jwt import SessionManager


class AuthSessionMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        session_manager: SessionManager,
        cookie_name: str,
        protected_path_prefixes: list[str],
    ):
        super().__init__(app)
        self.session_manager = session_manager
        self.cookie_name = cookie_name
        self.protected_path_prefixes = tuple(protected_path_prefixes)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        token = request.cookies.get(self.cookie_name)
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]

        request.state.user = None
        if token:
            try:
                request.state.user = self.session_manager.decode_token(token)
            except Exception:
                request.state.user = None

        if request.url.path.startswith(self.protected_path_prefixes) and not request.state.user:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)

        return await call_next(request)
