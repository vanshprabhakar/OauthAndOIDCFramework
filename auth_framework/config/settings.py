import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

from auth_framework.config.models import AppSettings, default_config_path, load_provider


class EnvironmentSettings(BaseSettings):
    auth_config_path: Path = default_config_path()
    jwt_secret: str = "change-me-in-production"
    cookie_secure: bool = False
    public_base_url: str = "http://localhost:8000"
    environment: str = "local"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="AUTH_", extra="ignore")


def _read_config_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Auth configuration file not found: {path}")
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(content)
    return yaml.safe_load(content) or {}


@lru_cache
def get_settings() -> AppSettings:
    env = EnvironmentSettings()
    raw = _read_config_file(env.auth_config_path)
    raw.setdefault("public_base_url", env.public_base_url)
    raw.setdefault("environment", env.environment)
    session = raw.setdefault("session", {})
    session.setdefault("jwt_secret", env.jwt_secret)
    session.setdefault("cookie_secure", env.cookie_secure)
    raw["providers"] = [load_provider(provider) for provider in raw.get("providers", [])]
    return AppSettings.model_validate(raw)
