from auth_framework.config.models import AppSettings, load_provider


def test_load_saml_provider_from_config():
    provider = load_provider(
        {
            "provider_name": "ADP",
            "slug": "adp-saml",
            "protocol": "SAML",
            "metadata_url": "https://idp.example.com/metadata",
            "entity_id": "https://auth.example.com/auth/adp-saml/metadata",
            "acs_url": "https://auth.example.com/auth/adp-saml/acs",
            "attribute_mapping": {"email": "mail", "name": "displayName"},
        }
    )

    assert provider.slug == "adp-saml"
    assert provider.attribute_mapping.email == "mail"


def test_load_oidc_provider_from_config():
    provider = load_provider(
        {
            "provider_name": "Okta",
            "slug": "okta",
            "protocol": "OIDC",
            "issuer": "https://example.okta.com/oauth2/default",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "redirect_uri": "https://auth.example.com/auth/okta/callback",
        }
    )

    assert provider.slug == "okta"
    assert "openid" in provider.scopes


def test_settings_reject_duplicate_provider_slugs():
    saml = load_provider(
        {
            "provider_name": "ADP",
            "slug": "duplicate",
            "protocol": "SAML",
            "metadata_url": "https://idp.example.com/metadata",
            "entity_id": "https://auth.example.com/auth/duplicate/metadata",
            "acs_url": "https://auth.example.com/auth/duplicate/acs",
        }
    )
    oidc = load_provider(
        {
            "provider_name": "Okta",
            "slug": "duplicate",
            "protocol": "OIDC",
            "issuer": "https://example.okta.com/oauth2/default",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "redirect_uri": "https://auth.example.com/auth/duplicate/callback",
        }
    )

    try:
        AppSettings(session={"jwt_secret": "secret"}, providers=[saml, oidc])
    except ValueError as exc:
        assert "Provider slugs must be unique" in str(exc)
    else:
        raise AssertionError("Expected duplicate provider slugs to be rejected")
