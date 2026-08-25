"""Reusable OAuth 2.1 building blocks for Archolith services."""

from .config import AuthorizationServerConfig, ResourceServerConfig, well_known_url
from .cimd import resolve_client_metadata_document
from .consent import (
    ConsentNonceStore,
    ConsentSession,
    ConsentTokenError,
    ConsentTokenManager,
    ConsentTransaction,
)
from .key_store import SigningKeyStore
from .metadata import authorization_server_metadata, protected_resource_metadata
from .models import (
    AuthCodeRecord,
    AuthorizationGrant,
    OAuthClient,
    OAuthPrincipal,
    RefreshTokenRecord,
)
from .pkce import create_verifier, s256_challenge, verify_s256
from .policy import ScopePolicy, ScopePolicyError, ScopeRequirement
from .refresh_tokens import RefreshTokenStore
from .registration import (
    ClientMetadataError,
    register_public_client,
    register_public_client_for_server,
    valid_redirect_uri,
    validate_authorization_request,
)
from .runtime import OAuthRuntime
from .settings import OAuthSettings, PreflightCheck, PreflightReport
from .stores import AuthorizationCodeStore, OAuthClientStore, hash_secret
from .tokens import (
    TokenExchangeError,
    TokenIssuer,
    TokenResponse,
    exchange_authorization_code,
    exchange_refresh_token,
)
from .verifier import AccessTokenVerifier, OAuthAuthenticationError, extract_scopes

__all__ = [
    "AccessTokenVerifier",
    "AuthCodeRecord",
    "AuthorizationCodeStore",
    "AuthorizationGrant",
    "AuthorizationServerConfig",
    "ClientMetadataError",
    "ConsentNonceStore",
    "ConsentSession",
    "ConsentTokenError",
    "ConsentTokenManager",
    "ConsentTransaction",
    "OAuthAuthenticationError",
    "OAuthClient",
    "OAuthClientStore",
    "OAuthPrincipal",
    "OAuthRuntime",
    "OAuthSettings",
    "PreflightCheck",
    "PreflightReport",
    "RefreshTokenRecord",
    "RefreshTokenStore",
    "ResourceServerConfig",
    "ScopePolicy",
    "ScopePolicyError",
    "ScopeRequirement",
    "SigningKeyStore",
    "TokenExchangeError",
    "TokenIssuer",
    "TokenResponse",
    "authorization_server_metadata",
    "create_verifier",
    "exchange_authorization_code",
    "exchange_refresh_token",
    "extract_scopes",
    "hash_secret",
    "protected_resource_metadata",
    "register_public_client",
    "register_public_client_for_server",
    "valid_redirect_uri",
    "resolve_client_metadata_document",
    "s256_challenge",
    "validate_authorization_request",
    "verify_s256",
    "well_known_url",
]

__version__ = "0.2.0"
