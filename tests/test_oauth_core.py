from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

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
    ResourceServerConfig,
    SigningKeyStore,
    TokenExchangeError,
    TokenIssuer,
    authorization_server_metadata,
    exchange_authorization_code,
    protected_resource_metadata,
    register_public_client,
    s256_challenge,
    validate_authorization_request,
    verify_s256,
)


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
    ) is None


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
