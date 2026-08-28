"""Dynamic client registration and authorization-request validation."""

from __future__ import annotations

import secrets
import time
from urllib.parse import urlsplit

from .config import AuthorizationServerConfig
from .models import AuthorizationGrant, OAuthClient


class ClientMetadataError(ValueError):
    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


def _valid_redirect_uri(uri: str) -> bool:
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return False
    if (
        parsed.fragment
        or not parsed.scheme
        or not parsed.netloc
        or parsed.username
        or parsed.password
    ):
        return False
    if parsed.scheme == "https":
        return True
    if parsed.scheme != "http":
        return False
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def valid_redirect_uri(uri: str) -> bool:
    """Return whether a public-client redirect URI satisfies the shared policy."""
    return _valid_redirect_uri(uri)


def register_public_client(
    metadata: dict,
    *,
    supported_scopes: tuple[str, ...],
    default_scopes: tuple[str, ...] = (),
    max_redirect_uris: int = 5,
    allow_refresh_tokens: bool = False,
) -> OAuthClient:
    redirect_uris = metadata.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise ClientMetadataError("invalid_redirect_uri", "redirect_uris is required")
    if len(redirect_uris) > max_redirect_uris:
        raise ClientMetadataError("invalid_redirect_uri", "too many redirect URIs")
    if not all(isinstance(uri, str) for uri in redirect_uris):
        raise ClientMetadataError(
            "invalid_redirect_uri",
            "each redirect URI must be a string",
        )
    normalized = tuple(uri.strip() for uri in redirect_uris)
    if any(not _valid_redirect_uri(uri) for uri in normalized):
        raise ClientMetadataError("invalid_redirect_uri", "redirect URI is not allowed")

    auth_method = metadata.get("token_endpoint_auth_method", "none")
    if auth_method != "none":
        raise ClientMetadataError(
            "invalid_client_metadata", "only public clients are supported"
        )
    grants_raw = metadata.get("grant_types", ["authorization_code"])
    responses = metadata.get("response_types", ["code"])
    if not isinstance(grants_raw, list) or not all(
        isinstance(grant, str) for grant in grants_raw
    ):
        raise ClientMetadataError("invalid_client_metadata", "grant_types must be an array")
    grants = set(grants_raw)
    allowed_grants = {"authorization_code"}
    if allow_refresh_tokens:
        allowed_grants.add("refresh_token")
    if "authorization_code" not in grants or not grants.issubset(allowed_grants):
        raise ClientMetadataError(
            "invalid_client_metadata",
            "unsupported grant_types",
        )
    if responses != ["code"]:
        raise ClientMetadataError(
            "invalid_client_metadata",
            "only response_type=code is supported",
        )

    allowed = set(supported_scopes)
    if default_scopes and not set(default_scopes).issubset(allowed):
        raise ValueError("default_scopes must be a subset of supported_scopes")
    scope_raw = metadata.get("scope")
    if scope_raw is None:
        requested: tuple[str, ...] = ()
    elif isinstance(scope_raw, str):
        requested = tuple(scope_raw.split())
    else:
        raise ClientMetadataError(
            "invalid_client_metadata",
            "scope must be a space-delimited string",
        )
    unsupported = set(requested) - allowed
    if unsupported:
        raise ClientMetadataError(
            "invalid_client_metadata",
            "requested scope is not supported",
        )
    scopes = requested or default_scopes or tuple(supported_scopes)

    client_name_raw = metadata.get("client_name", "OAuth client")
    if not isinstance(client_name_raw, str):
        raise ClientMetadataError(
            "invalid_client_metadata",
            "client_name must be a string",
        )
    client_name = client_name_raw.strip()[:255]

    return OAuthClient(
        client_id=secrets.token_urlsafe(24),
        client_name=client_name,
        redirect_uris=normalized,
        scopes=tuple(scopes),
        token_endpoint_auth_method="none",
        created_at=time.time(),
    )


def register_public_client_for_server(
    metadata: dict,
    *,
    config: AuthorizationServerConfig,
    max_redirect_uris: int = 5,
) -> OAuthClient:
    """Register using one server config so scope defaults cannot drift."""
    return register_public_client(
        metadata,
        supported_scopes=config.effective_scopes_supported,
        default_scopes=config.default_scopes,
        max_redirect_uris=max_redirect_uris,
        allow_refresh_tokens=config.issue_refresh_tokens,
    )


def validate_authorization_request(
    *,
    client: OAuthClient,
    response_type: str,
    redirect_uri: str,
    requested_scope: str,
    code_challenge: str,
    code_challenge_method: str,
    resource: str,
    expected_resource: str,
    subject: str,
) -> AuthorizationGrant:
    if redirect_uri not in client.redirect_uris:
        raise ValueError("redirect_uri does not exactly match a registered URI")
    if response_type != "code":
        raise ValueError("only response_type=code is supported")
    if not code_challenge or code_challenge_method != "S256":
        raise ValueError("PKCE S256 is required")
    if not resource:
        raise ValueError("resource is required")
    if resource != expected_resource:
        raise ValueError("resource does not match this authorization server")
    requested = tuple(part for part in requested_scope.split() if part) or client.scopes
    if not set(requested).issubset(set(client.scopes)):
        raise ValueError("requested scope exceeds the client's registered scopes")
    return AuthorizationGrant(
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        scope=" ".join(requested),
        code_challenge=code_challenge,
        code_challenge_method="S256",
        resource=expected_resource,
        subject=subject,
    )
