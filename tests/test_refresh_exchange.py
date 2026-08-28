from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from archolith_oauth import (
    AccessTokenVerifier,
    AuthorizationCodeStore,
    AuthorizationServerConfig,
    OAuthClientStore,
    RefreshTokenStore,
    ResourceServerConfig,
    SigningKeyStore,
    TokenExchangeError,
    TokenIssuer,
    exchange_authorization_code,
    exchange_refresh_token,
    register_public_client,
    s256_challenge,
    validate_authorization_request,
)


@pytest.mark.asyncio
async def test_authorization_code_issues_rotating_refresh_token(tmp_path: Path):
    pytest.importorskip("joserfc")

    resource = "https://harness.example.com/mcp"
    config = AuthorizationServerConfig(
        issuer="https://auth.example.com/harness",
        resource=resource,
        scopes_supported=("harness:read", "harness:session"),
        issue_refresh_tokens=True,
    )
    client = register_public_client(
        {
            "redirect_uris": ["https://chat.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "harness:read offline_access",
        },
        supported_scopes=config.effective_scopes_supported,
        allow_refresh_tokens=True,
    )

    db = tmp_path / "oauth.db"
    clients = OAuthClientStore(db)
    codes = AuthorizationCodeStore(db)
    refreshes = RefreshTokenStore(db, ttl_s=config.refresh_token_ttl_s)
    clients.register(client)

    verifier_text = "v" * 64
    grant = validate_authorization_request(
        client=client,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        requested_scope="harness:read offline_access",
        code_challenge=s256_challenge(verifier_text),
        code_challenge_method="S256",
        resource=resource,
        expected_resource=resource,
        subject="user-1",
    )
    code = codes.issue(grant)
    key = SigningKeyStore(tmp_path / "signing-key.json").load_or_create()
    issuer = TokenIssuer(config, key)

    first = exchange_authorization_code(
        code_store=codes,
        client_store=clients,
        refresh_store=refreshes,
        issuer=issuer,
        code=code,
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
        code_verifier=verifier_text,
        resource=resource,
    )
    assert first.refresh_token

    second = exchange_refresh_token(
        refresh_store=refreshes,
        client_store=clients,
        issuer=issuer,
        refresh_token=first.refresh_token,
        client_id=client.client_id,
        resource=resource,
    )
    assert second.refresh_token
    assert second.refresh_token != first.refresh_token

    async def load_jwks():
        return SigningKeyStore.public_jwks(key)

    principal = await AccessTokenVerifier(
        ResourceServerConfig(
            resource=resource,
            authorization_servers=(config.issuer,),
            issuer=config.issuer,
            jwks_uri=config.jwks_uri,
            scopes_supported=config.effective_scopes_supported,
        ),
        jwks_loader=load_jwks,
    ).verify(second.access_token, required_scopes={"harness:read"})
    assert principal.subject == "user-1"
    assert principal.client_id == client.client_id

    with pytest.raises(TokenExchangeError) as replay:
        exchange_refresh_token(
            refresh_store=refreshes,
            client_store=clients,
            issuer=issuer,
            refresh_token=first.refresh_token,
            client_id=client.client_id,
            resource=resource,
        )
    assert replay.value.error == "invalid_grant"

    with pytest.raises(TokenExchangeError):
        exchange_refresh_token(
            refresh_store=refreshes,
            client_store=clients,
            issuer=issuer,
            refresh_token=second.refresh_token,
            client_id=client.client_id,
            resource=resource,
        )


def test_explicit_policy_can_issue_refresh_without_offline_access(tmp_path: Path):
    pytest.importorskip("joserfc")

    resource = "https://harness.example.com/mcp"
    config = AuthorizationServerConfig(
        issuer="https://auth.example.com/harness",
        resource=resource,
        scopes_supported=("harness:read",),
        issue_refresh_tokens=True,
    )
    client = register_public_client(
        {
            "redirect_uris": ["https://chat.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "harness:read",
        },
        supported_scopes=config.effective_scopes_supported,
        allow_refresh_tokens=True,
    )
    db = tmp_path / "oauth.db"
    clients = OAuthClientStore(db)
    codes = AuthorizationCodeStore(db)
    refreshes = RefreshTokenStore(db, ttl_s=config.refresh_token_ttl_s)
    clients.register(client)
    verifier_text = "v" * 64
    grant = validate_authorization_request(
        client=client,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        requested_scope="harness:read",
        code_challenge=s256_challenge(verifier_text),
        code_challenge_method="S256",
        resource=resource,
        expected_resource=resource,
        subject="user-1",
    )
    code_without_policy = codes.issue(grant)
    without_policy = exchange_authorization_code(
        code_store=codes,
        client_store=clients,
        refresh_store=refreshes,
        issuer=TokenIssuer(
            config,
            SigningKeyStore(tmp_path / "signing-key.json").load_or_create(),
        ),
        code=code_without_policy,
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
        code_verifier=verifier_text,
        resource=resource,
    )
    assert without_policy.refresh_token is None

    code = codes.issue(grant)

    response = exchange_authorization_code(
        code_store=codes,
        client_store=clients,
        refresh_store=refreshes,
        issuer=TokenIssuer(
            config,
            SigningKeyStore(tmp_path / "signing-key.json").load_or_create(),
        ),
        code=code,
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
        code_verifier=verifier_text,
        resource=resource,
        issue_refresh_without_offline_access=True,
    )

    assert response.refresh_token
    assert response.scope == "harness:read"


def _harness(tmp_path: Path):
    pytest.importorskip("joserfc")

    resource = "https://harness.example.com/mcp"
    config = AuthorizationServerConfig(
        issuer="https://auth.example.com/harness",
        resource=resource,
        scopes_supported=("harness:read", "harness:session"),
        issue_refresh_tokens=True,
    )
    client = register_public_client(
        {
            "redirect_uris": ["https://chat.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "harness:read offline_access",
        },
        supported_scopes=config.effective_scopes_supported,
        allow_refresh_tokens=True,
    )
    db = tmp_path / "oauth.db"
    clients = OAuthClientStore(db)
    codes = AuthorizationCodeStore(db)
    refreshes = RefreshTokenStore(db, ttl_s=config.refresh_token_ttl_s)
    clients.register(client)

    verifier_text = "v" * 64
    grant = validate_authorization_request(
        client=client,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        requested_scope="harness:read offline_access",
        code_challenge=s256_challenge(verifier_text),
        code_challenge_method="S256",
        resource=resource,
        expected_resource=resource,
        subject="user-1",
    )
    code = codes.issue(grant)
    key = SigningKeyStore(tmp_path / "signing-key.json").load_or_create()
    issuer = TokenIssuer(config, key)
    first = exchange_authorization_code(
        code_store=codes,
        client_store=clients,
        refresh_store=refreshes,
        issuer=issuer,
        code=code,
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
        code_verifier=verifier_text,
        resource=resource,
    )
    return refreshes, clients, issuer, first, client.client_id


@pytest.mark.asyncio
async def test_refresh_equal_scope_preserves_grant(tmp_path: Path):
    refreshes, clients, issuer, first, client_id = _harness(tmp_path)
    resource = issuer.config.resource

    second = exchange_refresh_token(
        refresh_store=refreshes,
        client_store=clients,
        issuer=issuer,
        refresh_token=first.refresh_token,
        client_id=client_id,
        resource=resource,
        scope="harness:read offline_access",
    )
    assert set(second.scope.split()) == {"harness:read", "offline_access"}
    assert second.refresh_token

    third = exchange_refresh_token(
        refresh_store=refreshes,
        client_store=clients,
        issuer=issuer,
        refresh_token=second.refresh_token,
        client_id=client_id,
        resource=resource,
    )
    assert third.refresh_token
    assert third.scope == second.scope


@pytest.mark.asyncio
async def test_refresh_subset_narrows_family_scope(tmp_path: Path):
    refreshes, clients, issuer, first, client_id = _harness(tmp_path)
    resource = issuer.config.resource

    narrowed = exchange_refresh_token(
        refresh_store=refreshes,
        client_store=clients,
        issuer=issuer,
        refresh_token=first.refresh_token,
        client_id=client_id,
        resource=resource,
        scope="offline_access",
    )
    assert set(narrowed.scope.split()) == {"offline_access"}

    # The original was consumed exactly once and the single replacement is
    # the only live token in the family, carrying the narrowed scope.
    with sqlite3.connect(tmp_path / "oauth.db") as conn:
        live = conn.execute(
            "SELECT COUNT(*) FROM oauth_refresh_tokens "
            "WHERE used_at IS NULL AND revoked_at IS NULL"
        ).fetchone()[0]
    assert live == 1
    continued = exchange_refresh_token(
        refresh_store=refreshes,
        client_store=clients,
        issuer=issuer,
        refresh_token=narrowed.refresh_token,
        client_id=client_id,
        resource=resource,
    )
    assert set(continued.scope.split()) == {"offline_access"}

    # Replaying the original token revokes the entire family, including the
    # newest continuation produced above.
    with pytest.raises(TokenExchangeError) as replay:
        exchange_refresh_token(
            refresh_store=refreshes,
            client_store=clients,
            issuer=issuer,
            refresh_token=first.refresh_token,
            client_id=client_id,
            resource=resource,
        )
    assert replay.value.error == "invalid_grant"
    with pytest.raises(TokenExchangeError) as revoked_family:
        exchange_refresh_token(
            refresh_store=refreshes,
            client_store=clients,
            issuer=issuer,
            refresh_token=continued.refresh_token,
            client_id=client_id,
            resource=resource,
        )
    assert revoked_family.value.error == "invalid_grant"


@pytest.mark.asyncio
async def test_refresh_expansion_fails_before_issuance(tmp_path: Path):
    refreshes, clients, issuer, first, client_id = _harness(tmp_path)
    resource = issuer.config.resource

    with pytest.raises(TokenExchangeError) as expansion:
        exchange_refresh_token(
            refresh_store=refreshes,
            client_store=clients,
            issuer=issuer,
            refresh_token=first.refresh_token,
            client_id=client_id,
            resource=resource,
            scope="harness:read harness:session offline_access",
        )
    assert expansion.value.error == "invalid_scope"

    # invalid_scope mutates nothing: the original token is still usable and
    # an equal-scope exchange now succeeds.
    retried = exchange_refresh_token(
        refresh_store=refreshes,
        client_store=clients,
        issuer=issuer,
        refresh_token=first.refresh_token,
        client_id=client_id,
        resource=resource,
        scope="harness:read offline_access",
    )
    assert set(retried.scope.split()) == {"harness:read", "offline_access"}
