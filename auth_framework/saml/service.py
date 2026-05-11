from functools import lru_cache
from typing import Any

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from auth_framework.auth.user import AuthenticatedUser, map_attributes
from auth_framework.config.models import SamlProviderConfig


class SamlService:
    def __init__(self, provider: SamlProviderConfig):
        self.provider = provider

    def build_auth(self, request_data: dict[str, Any]) -> OneLogin_Saml2_Auth:
        return OneLogin_Saml2_Auth(request_data, self.settings_dict())

    def login_url(self, request_data: dict[str, Any], return_to: str | None = None) -> str:
        return self.build_auth(request_data).login(return_to=return_to)

    def process_acs(self, request_data: dict[str, Any]) -> AuthenticatedUser:
        auth = self.build_auth(request_data)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            raise ValueError(f"SAML response validation failed: {', '.join(errors)}")
        if not auth.is_authenticated():
            raise ValueError("SAML response did not authenticate the user")
        attributes = auth.get_attributes()
        subject = auth.get_nameid()
        return map_attributes(self.provider, attributes, subject=subject)

    def metadata_xml(self) -> str:
        settings = OneLogin_Saml2_Settings(self.settings_dict(), sp_validation_only=True)
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        if errors:
            raise ValueError(f"Invalid SP metadata: {', '.join(errors)}")
        return metadata

    def settings_dict(self) -> dict[str, Any]:
        idp_settings = self._idp_settings()
        settings: dict[str, Any] = {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": self.provider.entity_id,
                "assertionConsumerService": {
                    "url": str(self.provider.acs_url),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "NameIDFormat": self.provider.name_id_format,
                "x509cert": self.provider.sp_x509_cert or "",
                "privateKey": (
                    self.provider.sp_private_key.get_secret_value()
                    if self.provider.sp_private_key
                    else ""
                ),
            },
            "idp": idp_settings,
            "security": {
                "authnRequestsSigned": self.provider.security.authn_requests_signed,
                "logoutRequestSigned": self.provider.security.logout_request_signed,
                "logoutResponseSigned": self.provider.security.logout_response_signed,
                "wantAssertionsSigned": self.provider.security.want_assertions_signed,
                "wantMessagesSigned": self.provider.security.want_response_signed,
                "wantNameId": self.provider.security.want_name_id,
                "requestedAuthnContext": self.provider.security.requested_authn_context,
                "signatureAlgorithm": self.provider.security.signature_algorithm,
                "digestAlgorithm": self.provider.security.digest_algorithm,
            },
        }
        return settings

    def _idp_settings(self) -> dict[str, Any]:
        if self.provider.metadata_url:
            return _parse_remote_metadata(str(self.provider.metadata_url))["idp"]
        return {
            "entityId": self.provider.idp_entity_id,
            "singleSignOnService": {
                "url": str(self.provider.idp_sso_url),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": str(self.provider.idp_slo_url) if self.provider.idp_slo_url else "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": self.provider.idp_x509_cert,
        }


@lru_cache(maxsize=32)
def _parse_remote_metadata(metadata_url: str) -> dict[str, Any]:
    return OneLogin_Saml2_IdPMetadataParser.parse_remote(metadata_url)
