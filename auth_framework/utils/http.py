from urllib.parse import urlparse

from fastapi import Request


def prepare_saml_request_data(request: Request, form_data: dict[str, str] | None = None) -> dict:
    parsed_url = urlparse(str(request.url))
    port = parsed_url.port
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.headers.get("host", parsed_url.netloc),
        "server_port": str(port or (443 if request.url.scheme == "https" else 80)),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": form_data or {},
    }
