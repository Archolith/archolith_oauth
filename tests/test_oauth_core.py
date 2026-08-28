from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from archolith_oauth import (
    AccessTokenVerifier,
    AuthorizationCodeStore,
    AuthorizationGrant,
    AuthorizationServerConfig,
    ClientMetadataError,
    OAuthAuthenticationError,
    OAuthClient,
    OAuthClientStore,
    ReceiptEncryptionKeyring,
    RefreshTokenStore,
    ResourceServerConfig,
    SigningKeyStore,
    TokenExchangeError,
    TokenIssuer,
    authorization_server_metadata,
    exchange_authorization_code,
    exchange_refresh_token,
    exchange_refresh_token_durable,
    protected_resource_metadata,
    register_public_client,
    s256_challenge,
    validate_authorization_request,
    verify_s256,
)
from archolith_oauth import jose


def test_metadata_defaults():
    auth = AuthorizationServerConfig(
        issuer="https://auth.example.com/",
        resource="https://service.example.com/mcp",
        scopes_supported=("service:read",),
    )
    assert auth.token_endpoint == "https://auth.example.com/oauth/token"
    assert authorization_server_metadata(auth)["grant_types_supported"] == [
        "authorization_code"
    ]
    assert (
        authorization_server_metadata(auth)[
            "authorization_response_iss_parameter_supported"
        ]
        is False
    )
    assert (
        authorization_server_metadata(auth)["client_id_metadata_document_supported"]
        is False
    )


def test_rfc9207_and_cimd_metadata_flags_are_truthful():
    auth = AuthorizationServerConfig(
        issuer="https://auth.example.com/",
        resource="https://service.example.com/mcp",
        scopes_supported=("service:read",),
        authorization_response_iss_parameter_supported=True,
        client_id_metadata_document_supported=True,
    )
    metadata = authorization_server_metadata(auth)
    assert metadata["authorization_response_iss_parameter_supported"] is True
    assert metadata["client_id_metadata_document_supported"] is True

    resource = ResourceServerConfig(
        resource=auth.resource,
        authorization_servers=(auth.issuer,),
        issuer=auth.issuer,
        jwks_uri=auth.jwks_uri,
        scopes_supported=auth.scopes_supported,
        metadata_url="https://service.example.com/.well-known/oauth-protected-resource",
    )
    assert resource.audiences == (auth.resource,)
    assert protected_resource_metadata(resource)["bearer_methods_supported"] == [
        "header"
    ]
    assert resource.challenge().startswith("Bearer resource_metadata=")


def test_pkce():
    verifier = "a" * 64
    challenge = s256_challenge(verifier)
    assert verify_s256(verifier, challenge)
    assert not verify_s256("wrong", challenge)


def test_dcr_rejects_unsupported_scope_and_credentialed_redirect():
    with pytest.raises(ClientMetadataError):
        register_public_client(
            {
                "redirect_uris": ["https://chat.example.com/callback"],
                "scope": "service:admin",
            },
            supported_scopes=("service:read",),
        )

    with pytest.raises(ClientMetadataError):
        register_public_client(
            {"redirect_uris": ["https://user:secret@chat.example.com/callback"]},
            supported_scopes=("service:read",),
        )


def test_store_opens_existing_menhir_schema(tmp_path: Path):
    db = tmp_path / "menhir_oauth_as.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            """CREATE TABLE oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_name TEXT,
                redirect_uris TEXT,
                scopes TEXT,
                client_secret_hash TEXT,
                created_at REAL,
                token_endpoint_auth_method TEXT,
                last_exchanged REAL
            )"""
        )
    store = OAuthClientStore(db)
    client = OAuthClient(
        client_id="menhir-client",
        client_name="Menhir client",
        redirect_uris=("https://chat.example.com/callback",),
        scopes=("menhir:read",),
        client_secret_hash="",
        created_at=1.0,
    )
    store.register(client)
    assert store.get(client.client_id) == client
    assert store.count() == 1
    assert store.all() == [client]
    assert store.reap_stale(10, now=100.0) == 1


def test_store_migrates_initial_package_schema(tmp_path: Path):
    db = tmp_path / "oauth.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            """CREATE TABLE oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_name TEXT NOT NULL,
                redirect_uris TEXT NOT NULL,
                scopes TEXT NOT NULL,
                token_endpoint_auth_method TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_exchanged REAL
            )"""
        )
    OAuthClientStore(db)
    with sqlite3.connect(db) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(oauth_clients)")}
    assert "client_secret_hash" in columns


def test_token_exchange_requires_matching_resource(tmp_path: Path):
    resource = "https://service.example.com/mcp"
    grant = AuthorizationGrant(
        client_id="client-1",
        redirect_uri="https://chat.example.com/callback",
        scope="service:read",
        code_challenge=s256_challenge("v" * 64),
        code_challenge_method="S256",
        resource=resource,
        subject="user-1",
    )
    codes = AuthorizationCodeStore(tmp_path / "oauth.db")
    clients = OAuthClientStore(tmp_path / "oauth.db")
    raw_code = codes.issue(grant)
    fake_issuer = SimpleNamespace(config=SimpleNamespace(resource=resource))

    with pytest.raises(TokenExchangeError) as missing:
        exchange_authorization_code(
            code_store=codes,
            client_store=clients,
            issuer=fake_issuer,
            code=raw_code,
            client_id=grant.client_id,
            redirect_uri=grant.redirect_uri,
            code_verifier="v" * 64,
            resource="",
        )
    assert missing.value.error == "invalid_request"

    with pytest.raises(TokenExchangeError) as mismatch:
        exchange_authorization_code(
            code_store=codes,
            client_store=clients,
            issuer=fake_issuer,
            code=raw_code,
            client_id=grant.client_id,
            redirect_uri=grant.redirect_uri,
            code_verifier="v" * 64,
            resource="https://other.example.com/mcp",
        )
    assert mismatch.value.error == "invalid_grant"
    assert codes.redeem(
        code=raw_code,
        client_id=grant.client_id,
        redirect_uri=grant.redirect_uri,
    ) is not None
    assert codes.redeem(
        code=raw_code,
        client_id=grant.client_id,
        redirect_uri=grant.redirect_uri,
    ) is None


def test_code_validation_failures_do_not_consume_grant(tmp_path: Path):
    pytest.importorskip("joserfc")

    resource = "https://service.example.com/mcp"
    config = AuthorizationServerConfig(
        issuer="https://auth.example.com",
        resource=resource,
        scopes_supported=("service:read", "service:write"),
    )
    client = register_public_client(
        {
            "redirect_uris": ["https://chat.example.com/callback"],
            "scope": "service:read service:write",
        },
        supported_scopes=config.effective_scopes_supported,
    )
    db = tmp_path / "oauth.db"
    clients = OAuthClientStore(db)
    clients.register(client)
    codes = AuthorizationCodeStore(db)
    verifier = "v" * 64
    grant = validate_authorization_request(
        client=client,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        requested_scope="service:read service:write",
        code_challenge=s256_challenge(verifier),
        code_challenge_method="S256",
        resource=resource,
        expected_resource=resource,
        subject="user-1",
    )
    code = codes.issue(grant)
    issuer = TokenIssuer(
        config,
        SigningKeyStore(tmp_path / "signing-key.json").load_or_create(),
    )

    attempts = (
        {"client_id": "unknown-client"},
        {"redirect_uri": "https://chat.example.com/wrong"},
        {"resource": "https://other.example.com/mcp"},
        {"code_verifier": "x" * 64},
        {"required_scopes": {"service:read"}},
    )
    base = {
        "code_store": codes,
        "client_store": clients,
        "issuer": issuer,
        "code": code,
        "client_id": client.client_id,
        "redirect_uri": client.redirect_uris[0],
        "code_verifier": verifier,
        "resource": resource,
        "allowed_scopes": config.effective_scopes_supported,
        "required_scopes": {"service:read", "service:write"},
    }
    for override in attempts:
        with pytest.raises(TokenExchangeError) as refused:
            exchange_authorization_code(**(base | override))
        assert refused.value.error == "invalid_grant"

    response = exchange_authorization_code(**base)
    assert set(response.scope.split()) == {"service:read", "service:write"}
    with pytest.raises(TokenExchangeError) as replay:
        exchange_authorization_code(**base)
    assert replay.value.error == "invalid_grant"


@pytest.mark.asyncio
async def test_full_code_exchange_and_verification(tmp_path: Path):
    pytest.importorskip("joserfc")

    resource = "https://service.example.com/mcp"
    scopes = ("service:read", "service:write")
    auth = AuthorizationServerConfig(
        issuer="https://auth.example.com",
        resource=resource,
        scopes_supported=scopes,
    )
    client = register_public_client(
        {
            "redirect_uris": ["https://chat.example.com/callback"],
            "client_name": "Test client",
            "scope": "service:read service:write",
        },
        supported_scopes=scopes,
    )
    db = tmp_path / "oauth.db"
    clients = OAuthClientStore(db)
    codes = AuthorizationCodeStore(db)
    clients.register(client)

    verifier_text = "v" * 64
    grant = validate_authorization_request(
        client=client,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        requested_scope="service:read",
        code_challenge=s256_challenge(verifier_text),
        code_challenge_method="S256",
        resource=resource,
        expected_resource=resource,
        subject="user-1",
    )
    raw_code = codes.issue(grant)
    key_store = SigningKeyStore(tmp_path / "signing-key.json")
    key = key_store.load_or_create()
    token = exchange_authorization_code(
        code_store=codes,
        client_store=clients,
        issuer=TokenIssuer(auth, key),
        code=raw_code,
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
        code_verifier=verifier_text,
        resource=resource,
    )
    assert token.token_type == "Bearer"
    assert codes.redeem(
        code=raw_code,
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
    ) is None

    public_jwks = SigningKeyStore.public_jwks(key)
    assert "d" not in public_jwks["keys"][0]

    async def load_jwks():
        return public_jwks

    rs = ResourceServerConfig(
        resource=resource,
        authorization_servers=(auth.issuer,),
        issuer=auth.issuer,
        jwks_uri=auth.jwks_uri,
        scopes_supported=scopes,
    )
    principal = await AccessTokenVerifier(rs, jwks_loader=load_jwks).verify(
        token.access_token,
        required_scopes={"service:read"},
    )
    assert principal.subject == "user-1"
    assert principal.client_id == client.client_id
    assert principal.scopes == frozenset({"service:read"})

    with pytest.raises(OAuthAuthenticationError) as exc:
        await AccessTokenVerifier(rs, jwks_loader=load_jwks).verify(
            token.access_token,
            required_scopes={"service:admin"},
        )
    assert exc.value.status_code == 403


def _tier_exchange_harness(tmp_path: Path):
    pytest.importorskip("joserfc")

    resource = "https://service.example.com/mcp"
    config = AuthorizationServerConfig(
        issuer="https://auth.example.com",
        resource=resource,
        scopes_supported=("service:read",),
        issue_refresh_tokens=True,
    )
    client = register_public_client(
        {
            "redirect_uris": ["https://chat.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "service:read offline_access",
        },
        supported_scopes=config.effective_scopes_supported,
        allow_refresh_tokens=True,
    )
    db = tmp_path / "tier-oauth.db"
    clients = OAuthClientStore(db)
    codes = AuthorizationCodeStore(db)
    refreshes = RefreshTokenStore(db)
    clients.register(client)
    verifier = "v" * 64
    grant = validate_authorization_request(
        client=client,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        requested_scope="service:read offline_access",
        code_challenge=s256_challenge(verifier),
        code_challenge_method="S256",
        resource=resource,
        expected_resource=resource,
        subject="user-1",
    )
    code = codes.issue(grant)
    key = SigningKeyStore(tmp_path / "tier-signing-key.json").load_or_create()
    return config, client, clients, codes, refreshes, verifier, code, key


def _verified_claims(token: str, key) -> dict[str, Any]:
    keyset = jose.parse_jwks(SigningKeyStore.public_jwks(key))
    return jose.verify_jwt(token, keyset, ["RS256"], 60)


def test_tier_survives_code_refresh_and_durable_refresh_exchanges(tmp_path: Path):
    config, client, clients, codes, refreshes, verifier, code, key = (
        _tier_exchange_harness(tmp_path)
    )
    issuer = TokenIssuer(config, key)

    code_response = exchange_authorization_code(
        code_store=codes,
        client_store=clients,
        refresh_store=refreshes,
        issuer=issuer,
        code=code,
        client_id=client.client_id,
        redirect_uri=client.redirect_uris[0],
        code_verifier=verifier,
        resource=config.resource,
        tier="agent",
    )
    assert _verified_claims(code_response.access_token, key)["tier"] == "agent"

    refresh_response = exchange_refresh_token(
        refresh_store=refreshes,
        client_store=clients,
        issuer=issuer,
        refresh_token=code_response.refresh_token,
        client_id=client.client_id,
        resource=config.resource,
        tier="readonly",
    )
    assert _verified_claims(refresh_response.access_token, key)["tier"] == "readonly"

    durable_response = exchange_refresh_token_durable(
        refresh_store=refreshes,
        client_store=clients,
        issuer=issuer,
        keyring=ReceiptEncryptionKeyring({"test": b"k" * 32}),
        refresh_token=refresh_response.refresh_token,
        client_id=client.client_id,
        resource=config.resource,
        tier="operator",
    )
    assert _verified_claims(durable_response.access_token, key)["tier"] == "operator"


@pytest.mark.parametrize("tier", ["", " agent", "agent ", "agent tier", 7])
def test_token_issuer_rejects_malformed_tier_before_signing(
    tmp_path: Path,
    monkeypatch,
    tier,
):
    pytest.importorskip("joserfc")
    config, client, _clients, _codes, _refreshes, _verifier, _code, key = (
        _tier_exchange_harness(tmp_path)
    )
    signed = False

    def fail_if_signed(*args, **kwargs):
        nonlocal signed
        signed = True
        raise AssertionError("malformed tier reached JWT signing")

    monkeypatch.setattr(jose, "sign_jwt", fail_if_signed)
    with pytest.raises(ValueError, match="tier"):
        TokenIssuer(config, key).issue(
            subject="user-1",
            client=client,
            scope="service:read",
            tier=tier,
        )
    assert signed is False


def test_malformed_tier_does_not_consume_code_or_refresh_tokens(tmp_path: Path):
    config, client, clients, codes, refreshes, verifier, code, key = (
        _tier_exchange_harness(tmp_path)
    )
    issuer = TokenIssuer(config, key)
    code_args = {
        "code_store": codes,
        "client_store": clients,
        "refresh_store": refreshes,
        "issuer": issuer,
        "code": code,
        "client_id": client.client_id,
        "redirect_uri": client.redirect_uris[0],
        "code_verifier": verifier,
        "resource": config.resource,
    }
    with pytest.raises(ValueError, match="tier"):
        exchange_authorization_code(**code_args, tier="")
    code_response = exchange_authorization_code(**code_args, tier="agent")

    refresh_args = {
        "refresh_store": refreshes,
        "client_store": clients,
        "issuer": issuer,
        "refresh_token": code_response.refresh_token,
        "client_id": client.client_id,
        "resource": config.resource,
    }
    with pytest.raises(ValueError, match="tier"):
        exchange_refresh_token(**refresh_args, tier="bad tier")
    refresh_response = exchange_refresh_token(**refresh_args, tier="agent")

    durable_args = {
        "refresh_store": refreshes,
        "client_store": clients,
        "issuer": issuer,
        "keyring": ReceiptEncryptionKeyring({"test": b"k" * 32}),
        "refresh_token": refresh_response.refresh_token,
        "client_id": client.client_id,
        "resource": config.resource,
    }
    with pytest.raises(ValueError, match="tier"):
        exchange_refresh_token_durable(**durable_args, tier=" ")
    durable_response = exchange_refresh_token_durable(**durable_args, tier="agent")
    assert _verified_claims(durable_response.access_token, key)["tier"] == "agent"
