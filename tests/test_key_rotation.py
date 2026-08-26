from __future__ import annotations

import json

import pytest

from archolith_oauth import OAuthClient, OAuthRuntime, OAuthSettings, SigningKeyStore
from archolith_oauth.cli import run as run_cli


def _settings(tmp_path) -> OAuthSettings:
    return OAuthSettings(
        issuer="https://auth.example.com/harness",
        resource="https://service.example.com/mcp",
        scopes_supported=("service:read",),
        default_scopes=("service:read",),
        data_dir=tmp_path / "oauth",
    )


def test_rotation_preserves_legacy_active_file_and_keeps_only_public_history(tmp_path):
    store = SigningKeyStore(tmp_path / "oauth-signing-key.json")
    store.load_or_create()
    before = json.loads(store.path.read_text("utf-8"))
    old_kid = before["kid"]
    assert "d" in before
    assert "active" not in before

    store.rotate(retain_previous=1)

    active = json.loads(store.path.read_text("utf-8"))
    previous = json.loads(store.previous_path.read_text("utf-8"))
    assert "d" in active
    assert active["kid"] != old_kid
    assert len(previous) == 1
    assert previous[0]["kid"] == old_kid
    assert "d" not in previous[0]
    assert store.key_ids() == (active["kid"], old_kid)

    store.rotate(retain_previous=1)
    assert len(store.public_jwks_all()["keys"]) == 2
    assert old_kid not in store.key_ids()


def test_readonly_load_refuses_missing_key_without_creating_state(tmp_path):
    store = SigningKeyStore(tmp_path / "missing" / "oauth-signing-key.json")

    with pytest.raises(FileNotFoundError, match="signing key does not exist"):
        store.load_existing()

    assert not store.path.parent.exists()


def test_readonly_jwks_does_not_chmod_or_create_files(tmp_path, monkeypatch):
    store = SigningKeyStore(tmp_path / "oauth-signing-key.json")
    store.load_or_create()
    expected_kid = json.loads(store.path.read_text("utf-8"))["kid"]
    before = set(tmp_path.iterdir())

    monkeypatch.setattr(
        "archolith_oauth.key_store.os.chmod",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("read-only load attempted chmod")
        ),
    )

    jwks = store.public_jwks_existing()

    assert jwks["keys"][0]["kid"] == expected_kid
    assert set(tmp_path.iterdir()) == before


@pytest.mark.asyncio
async def test_runtime_verifies_tokens_across_one_rotation(tmp_path):
    runtime = OAuthRuntime.from_settings(_settings(tmp_path))
    client = OAuthClient(
        client_id="client-1",
        client_name="Rotation test",
        redirect_uris=("https://chat.example.com/callback",),
        scopes=("service:read",),
    )
    old_token = runtime.token_issuer.issue(
        subject="user-1",
        client=client,
        scope="service:read",
        resource=runtime.authorization_config.resource,
    ).access_token
    old_principal = await runtime.token_verifier.verify(old_token)
    assert old_principal.subject == "user-1"

    key_ids = runtime.rotate_signing_key(retain_previous=1)
    assert len(key_ids) == 2
    new_token = runtime.token_issuer.issue(
        subject="user-1",
        client=client,
        scope="service:read",
        resource=runtime.authorization_config.resource,
    ).access_token

    assert (await runtime.token_verifier.verify(new_token)).subject == "user-1"
    assert (await runtime.token_verifier.verify(old_token)).subject == "user-1"


def test_cli_rotate_key_reports_active_and_previous_ids(tmp_path, monkeypatch, capsys):
    prefix = "ROTATE_TEST_"
    monkeypatch.setenv(prefix + "ISSUER", "https://auth.example.com/harness")
    monkeypatch.setenv(prefix + "RESOURCE", "https://service.example.com/mcp")
    monkeypatch.setenv(prefix + "SCOPES", "service:read")
    monkeypatch.setenv(prefix + "DATA_DIR", str(tmp_path / "oauth"))

    assert run_cli(["--prefix", prefix, "rotate-key", "--json"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["active_kid"]
    assert first["retained_previous_kids"] == []

    assert run_cli(["--prefix", prefix, "rotate-key", "--json"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["active_kid"] != first["active_kid"]
    assert second["retained_previous_kids"] == [first["active_kid"]]
