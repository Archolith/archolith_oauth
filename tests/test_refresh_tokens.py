from __future__ import annotations

from pathlib import Path

import pytest

from archolith_oauth import (
    AuthorizationServerConfig,
    RefreshTokenStore,
    authorization_server_metadata,
    register_public_client,
)


def test_refresh_support_is_opt_in_and_advertised():
    default = AuthorizationServerConfig(
        issuer="https://auth.example.com",
        resource="https://service.example.com/mcp",
        scopes_supported=("service:read",),
    )
    assert default.grant_types_supported == ("authorization_code",)
    assert "offline_access" not in default.effective_scopes_supported

    enabled = AuthorizationServerConfig(
        issuer="https://auth.example.com",
        resource="https://service.example.com/mcp",
        scopes_supported=("service:read",),
        issue_refresh_tokens=True,
    )
    metadata = authorization_server_metadata(enabled)
    assert metadata["grant_types_supported"] == [
        "authorization_code",
        "refresh_token",
    ]
    assert "offline_access" in metadata["scopes_supported"]

    client = register_public_client(
        {
            "redirect_uris": ["https://chat.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "service:read offline_access",
        },
        supported_scopes=enabled.effective_scopes_supported,
        allow_refresh_tokens=True,
    )
    assert client.scopes == ("service:read", "offline_access")


def test_refresh_rotation_detects_replay_and_revokes_family(tmp_path: Path):
    store = RefreshTokenStore(tmp_path / "oauth.db", ttl_s=3600)
    first = store.issue(
        client_id="client-1",
        subject="user-1",
        scope="service:read offline_access",
        resource="https://service.example.com/mcp",
        now=100.0,
    )
    rotated = store.rotate(
        token=first,
        client_id="client-1",
        resource="https://service.example.com/mcp",
        now=101.0,
    )
    assert rotated is not None
    record, second = rotated
    assert first != second
    assert not store.family_is_revoked(record.family_id)

    assert store.rotate(
        token=first,
        client_id="client-1",
        resource="https://service.example.com/mcp",
        now=102.0,
    ) is None
    assert store.family_is_revoked(record.family_id)

    assert store.rotate(
        token=second,
        client_id="client-1",
        resource="https://service.example.com/mcp",
        now=103.0,
    ) is None


def test_current_scope_policy_is_checked_before_rotation(tmp_path: Path):
    store = RefreshTokenStore(tmp_path / "oauth.db", ttl_s=3600)
    token = store.issue(
        client_id="chatgpt",
        subject="owner",
        scope="menhir:read menhir:admin offline_access",
        resource="https://memory.example.com/mcp-http",
    )

    with pytest.raises(ValueError, match="no longer supported"):
        store.rotate(
            token=token,
            client_id="chatgpt",
            resource="https://memory.example.com/mcp-http",
            allowed_scopes={"menhir:read", "offline_access"},
        )

    # Policy refusal did not mutate the token; explicit narrowing can still rotate it.
    record, replacement = store.rotate(
        token=token,
        client_id="chatgpt",
        resource="https://memory.example.com/mcp-http",
        scope="menhir:read offline_access",
        allowed_scopes={"menhir:read", "offline_access"},
    )
    assert set(record.scope.split()) == {
        "menhir:read",
        "menhir:admin",
        "offline_access",
    }
    assert replacement
