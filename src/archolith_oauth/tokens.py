"""Access-token issuance, authorization-code exchange, and refresh rotation."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from . import jose
from .config import AuthorizationServerConfig
from .models import OAuthClient
from .pkce import verify_s256
from .refresh_tokens import RefreshScopeError, RefreshTokenStore
from .stores import AuthorizationCodeStore, OAuthClientStore


class TokenExchangeError(ValueError):
    """OAuth token-endpoint error that an HTTP adapter can render directly."""

    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


@dataclass(frozen=True)
class TokenResponse:
    access_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
        }
        if self.refresh_token:
            payload["refresh_token"] = self.refresh_token
        return payload


class TokenIssuer:
    def __init__(self, config: AuthorizationServerConfig, signing_key) -> None:
        if "RS256" not in config.allowed_algorithms:
            raise ValueError("TokenIssuer currently requires RS256")
        self.config = config
        self.signing_key = signing_key

    def issue(
        self,
        *,
        subject: str,
        client: OAuthClient,
        scope: str,
        resource: str = "",
        refresh_token: str | None = None,
    ) -> TokenResponse:
        target_resource = resource or self.config.resource
        if target_resource != self.config.resource:
            raise ValueError("token resource does not match authorization server")
        now = int(time.time())
        ttl = self.config.access_token_ttl_s
        public = jose.serialize_key(self.signing_key, private=False)
        header = {"alg": "RS256", "kid": public["kid"], "typ": "JWT"}
        claims = {
            "iss": self.config.issuer,
            "sub": subject,
            "aud": target_resource,
            "client_id": client.client_id,
            "client_name": client.client_name,
            "scope": scope,
            "iat": now,
            "exp": now + ttl,
        }
        return TokenResponse(
            access_token=jose.sign_jwt(header, claims, self.signing_key),
            token_type="Bearer",
            expires_in=ttl,
            scope=scope,
            refresh_token=refresh_token,
        )


def exchange_authorization_code(
    *,
    code_store: AuthorizationCodeStore,
    client_store: OAuthClientStore,
    issuer: TokenIssuer,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    resource: str,
    refresh_store: RefreshTokenStore | None = None,
) -> TokenResponse:
    """Redeem one authorization code using PKCE and RFC 8707 resource binding."""
    if not resource:
        raise TokenExchangeError("invalid_request", "resource is required")
    record = code_store.redeem(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
    )
    if record is None:
        raise TokenExchangeError(
            "invalid_grant",
            "authorization code is invalid, expired, or already used",
        )
    if resource != record.resource or resource != issuer.config.resource:
        raise TokenExchangeError(
            "invalid_grant",
            "resource does not match the authorization request",
        )
    if record.code_challenge_method != "S256" or not verify_s256(
        code_verifier,
        record.code_challenge,
    ):
        raise TokenExchangeError("invalid_grant", "PKCE verification failed")
    client = client_store.get(client_id)
    if client is None:
        raise TokenExchangeError("invalid_grant", "registered client no longer exists")

    refresh_token: str | None = None
    scope_set = set(record.scope.split())
    if (
        issuer.config.issue_refresh_tokens
        and issuer.config.offline_access_scope in scope_set
    ):
        if refresh_store is None:
            raise TokenExchangeError(
                "server_error",
                "refresh token storage is not configured",
            )
        refresh_token = refresh_store.issue(
            client_id=client.client_id,
            subject=record.subject,
            scope=record.scope,
            resource=resource,
        )

    response = issuer.issue(
        subject=record.subject,
        client=client,
        scope=record.scope,
        resource=resource,
        refresh_token=refresh_token,
    )
    client_store.mark_exchanged(client_id)
    return response


def exchange_refresh_token(
    *,
    refresh_store: RefreshTokenStore,
    client_store: OAuthClientStore,
    issuer: TokenIssuer,
    refresh_token: str,
    client_id: str,
    resource: str,
    scope: str | None = None,
) -> TokenResponse:
    """Rotate a public client's refresh token and mint a new access token.

    An omitted or empty ``scope`` preserves the original grant scope. A
    requested scope must be equal to or a subset of the grant scope; the
    rotated replacement carries the narrowed scope. Scope expansion fails
    with ``invalid_scope`` before any mutation, leaving the presented token
    usable.
    """
    if not issuer.config.issue_refresh_tokens:
        raise TokenExchangeError(
            "unsupported_grant_type",
            "refresh_token grant is not enabled",
        )
    if not refresh_token or not client_id or not resource:
        raise TokenExchangeError(
            "invalid_request",
            "refresh_token, client_id, and resource are required",
        )
    if resource != issuer.config.resource:
        raise TokenExchangeError("invalid_grant", "resource does not match")
    client = client_store.get(client_id)
    if client is None:
        raise TokenExchangeError("invalid_grant", "registered client no longer exists")

    try:
        rotated = refresh_store.rotate(
            token=refresh_token,
            client_id=client_id,
            resource=resource,
            scope=scope,
        )
    except RefreshScopeError as exc:
        raise TokenExchangeError("invalid_scope", exc.description) from exc
    if rotated is None:
        raise TokenExchangeError(
            "invalid_grant",
            "refresh token is invalid, expired, replayed, or revoked",
        )
    record, replacement = rotated

    issued_scope = record.scope
    if scope is not None and scope.strip():
        requested_scopes = set(scope.split())
        if requested_scopes != set(record.scope.split()):
            issued_scope = " ".join(sorted(requested_scopes))

    return issuer.issue(
        subject=record.subject,
        client=client,
        scope=issued_scope,
        resource=record.resource,
        refresh_token=replacement,
    )
