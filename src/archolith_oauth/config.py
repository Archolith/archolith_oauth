"""OAuth resource-server and authorization-server configuration."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _quote_header_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _validate_url(
    value: str,
    name: str,
    *,
    allow_query: bool = False,
    allow_loopback_http: bool = True,
) -> str:
    cleaned = value.strip().rstrip("/")
    try:
        parsed = urlsplit(cleaned)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid URL") from exc
    if not parsed.netloc or parsed.fragment or parsed.username or parsed.password:
        raise ValueError(f"{name} must be an absolute URL without credentials or fragment")
    if parsed.query and not allow_query:
        raise ValueError(f"{name} must not contain a query")
    if parsed.scheme != "https":
        loopback_http = (
            allow_loopback_http
            and parsed.scheme == "http"
            and (parsed.hostname or "").lower() in _LOOPBACK_HOSTS
        )
        if not loopback_http:
            raise ValueError(f"{name} must use HTTPS (HTTP is allowed only on loopback)")
    return cleaned


def well_known_url(identifier: str, suffix: str) -> str:
    """Insert a well-known suffix between an identifier's authority and path."""
    parsed = urlsplit(identifier)
    identifier_path = parsed.path.lstrip("/")
    path = f"/.well-known/{suffix}"
    if identifier_path:
        path += f"/{identifier_path}"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


@dataclass(frozen=True)
class ResourceServerConfig:
    resource: str
    authorization_servers: tuple[str, ...]
    issuer: str
    jwks_uri: str
    audiences: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    allowed_algorithms: tuple[str, ...] = ("RS256",)
    jwks_cache_ttl_s: int = 300
    http_timeout_s: float = 5.0
    clock_skew_s: int = 60
    resource_name: str = "OAuth protected resource"
    metadata_url: str = ""

    def __post_init__(self) -> None:
        resource = _validate_url(
            self.resource,
            "resource",
            allow_query=True,
        )
        issuer = _validate_url(self.issuer, "issuer")
        jwks_uri = _validate_url(self.jwks_uri, "jwks_uri", allow_query=True)
        if not self.authorization_servers:
            raise ValueError("authorization_servers is required")
        authorization_servers = tuple(
            _validate_url(server, "authorization server")
            for server in self.authorization_servers
        )
        object.__setattr__(self, "resource", resource)
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "jwks_uri", jwks_uri)
        object.__setattr__(self, "authorization_servers", authorization_servers)
        if not self.audiences:
            object.__setattr__(self, "audiences", (resource,))
        if not self.metadata_url:
            object.__setattr__(
                self,
                "metadata_url",
                well_known_url(resource, "oauth-protected-resource"),
            )
        else:
            object.__setattr__(
                self,
                "metadata_url",
                _validate_url(self.metadata_url, "metadata_url", allow_query=True),
            )

    def challenge(
        self,
        *,
        error: str | None = None,
        description: str | None = None,
        scope: str | None = None,
    ) -> str:
        params = [
            f'resource_metadata="{_quote_header_value(self.metadata_url)}"'
        ]
        if error:
            params.append(f'error="{_quote_header_value(error)}"')
        if description:
            params.append(f'error_description="{_quote_header_value(description)}"')
        if scope:
            params.append(f'scope="{_quote_header_value(scope)}"')
        return "Bearer " + ", ".join(params)


@dataclass(frozen=True)
class AuthorizationServerConfig:
    issuer: str
    resource: str
    scopes_supported: tuple[str, ...]
    default_scopes: tuple[str, ...] = ()
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    registration_endpoint: str = ""
    jwks_uri: str = ""
    access_token_ttl_s: int = 3600
    authorization_code_ttl_s: int = 120
    issue_refresh_tokens: bool = False
    refresh_token_ttl_s: int = 30 * 24 * 60 * 60
    offline_access_scope: str = "offline_access"
    allowed_algorithms: tuple[str, ...] = ("RS256",)
    authorization_response_iss_parameter_supported: bool = False
    client_id_metadata_document_supported: bool = False

    def __post_init__(self) -> None:
        issuer = _validate_url(self.issuer, "issuer")
        resource = _validate_url(self.resource, "resource", allow_query=True)
        if not self.scopes_supported or any(not scope for scope in self.scopes_supported):
            raise ValueError("scopes_supported must contain at least one non-empty scope")
        if len(set(self.scopes_supported)) != len(self.scopes_supported):
            raise ValueError("scopes_supported must not contain duplicates")
        if self.issue_refresh_tokens and not self.offline_access_scope:
            raise ValueError("offline_access_scope is required for refresh tokens")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "resource", resource)

        defaults = {
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "registration_endpoint": f"{issuer}/oauth/register",
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
        }
        for field_name, default in defaults.items():
            value = getattr(self, field_name) or default
            object.__setattr__(
                self,
                field_name,
                _validate_url(value, field_name, allow_query=True),
            )

        default_scopes = self.default_scopes or self.scopes_supported
        if not set(default_scopes).issubset(set(self.effective_scopes_supported)):
            raise ValueError("default_scopes must be supported scopes")
        object.__setattr__(self, "default_scopes", tuple(default_scopes))

    @property
    def effective_scopes_supported(self) -> tuple[str, ...]:
        scopes = list(self.scopes_supported)
        if self.issue_refresh_tokens and self.offline_access_scope not in scopes:
            scopes.append(self.offline_access_scope)
        return tuple(scopes)

    @property
    def grant_types_supported(self) -> tuple[str, ...]:
        grants = ["authorization_code"]
        if self.issue_refresh_tokens:
            grants.append("refresh_token")
        return tuple(grants)

    @property
    def metadata_url(self) -> str:
        return well_known_url(self.issuer, "oauth-authorization-server")
