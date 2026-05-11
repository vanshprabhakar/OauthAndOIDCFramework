from auth_framework.config.models import AppSettings, Protocol, ProviderConfig


class ProviderRegistry:
    def __init__(self, settings: AppSettings):
        self._settings = settings

    def list_enabled(self) -> list[ProviderConfig]:
        return [provider for provider in self._settings.providers if provider.enabled]

    def get(self, slug: str) -> ProviderConfig:
        return self._settings.provider_by_slug(slug)

    def list_by_protocol(self, protocol: Protocol) -> list[ProviderConfig]:
        return [provider for provider in self.list_enabled() if provider.protocol == protocol]
