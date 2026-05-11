from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pydantic import BaseModel, Field

from auth_framework.auth.user import AuthenticatedUser
from auth_framework.config.models import SessionConfig


class SessionClaims(BaseModel):
    sub: str
    provider: str
    protocol: str
    email: str | None = None
    name: str | None = None
    groups: list[str] = Field(default_factory=list)
    iat: int
    exp: int
    iss: str


class SessionManager:
    def __init__(self, config: SessionConfig):
        self.config = config

    def create_token(self, user: AuthenticatedUser) -> str:
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=self.config.expiration_minutes)
        claims = SessionClaims(
            sub=user.external_id,
            provider=user.provider,
            protocol=user.protocol,
            email=str(user.email) if user.email else None,
            name=user.name,
            groups=user.groups,
            iat=int(now.timestamp()),
            exp=int(expires_at.timestamp()),
            iss=self.config.jwt_issuer,
        )
        return jwt.encode(
            claims.model_dump(exclude_none=True),
            self.config.jwt_secret.get_secret_value(),
            algorithm="HS256",
        )

    def decode_token(self, token: str) -> dict[str, Any]:
        return jwt.decode(
            token,
            self.config.jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            issuer=self.config.jwt_issuer,
            options={"require": ["exp", "iat", "iss", "sub"]},
        )
