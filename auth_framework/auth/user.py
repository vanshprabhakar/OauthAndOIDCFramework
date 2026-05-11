from typing import Any

from pydantic import BaseModel, EmailStr, Field

from auth_framework.config.models import AttributeMapping, BaseProviderConfig


class AuthenticatedUser(BaseModel):
    provider: str
    protocol: str
    external_id: str
    email: EmailStr | None = None
    name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    groups: list[str] = Field(default_factory=list)
    raw_attributes: dict[str, Any] = Field(default_factory=dict)


def _first_value(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def map_attributes(
    provider: BaseProviderConfig,
    raw_attributes: dict[str, Any],
    subject: str | None = None,
) -> AuthenticatedUser:
    mapping: AttributeMapping = provider.attribute_mapping
    email = _first_value(raw_attributes.get(mapping.email)) if mapping.email else None
    name = _first_value(raw_attributes.get(mapping.name)) if mapping.name else None
    external_id = (
        _first_value(raw_attributes.get(mapping.external_id)) if mapping.external_id else None
    ) or subject or email
    if not external_id:
        raise ValueError("Authenticated response did not contain a stable user identifier")

    if provider.allowed_domains and email:
        domain = str(email).split("@")[-1].lower()
        if domain not in provider.allowed_domains:
            raise ValueError(f"Email domain is not allowed for provider {provider.slug}")

    first_name = (
        _first_value(raw_attributes.get(mapping.first_name)) if mapping.first_name else None
    )
    last_name = _first_value(raw_attributes.get(mapping.last_name)) if mapping.last_name else None
    groups = _string_list(raw_attributes.get(mapping.groups)) if mapping.groups else []

    return AuthenticatedUser(
        provider=provider.slug,
        protocol=str(provider.protocol),
        external_id=str(external_id),
        email=email,
        name=name,
        first_name=first_name,
        last_name=last_name,
        groups=groups,
        raw_attributes=raw_attributes,
    )
