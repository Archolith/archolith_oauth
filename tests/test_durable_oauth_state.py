from __future__ import annotations

import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from archolith_oauth import (
    AuthorizationCodeStore,
    AuthorizationGrant,
    ReceiptEncryptionKeyring,
    RefreshTokenStore,
    consent_request_digest,
)
from archolith_oauth.stores import hash_secret


RESOURCE = "https://memory.example.test/mcp-http"
CLIENT_ID = "chatgpt-client"


def _keyring(key_id: str = "v1", byte: bytes = b"k") -> ReceiptEncryptionKeyring:
    return ReceiptEncryptionKeyring({key_id: byte * 32}, current_key_id=key_id)


def _response(record, replacement: str) -> dict[str, object]:
    return {
        "access_token": "access-" + secrets.token_urlsafe(18),
        "token_type": "Bearer",
        "expires_in": 900,
        "scope": record.scope,
        "refresh_token": replacement,
    }


def _refresh_store(tmp_path, **kwargs) -> tuple[RefreshTokenStore, str]:
    store = RefreshTokenStore(
        tmp_path / "oauth.db",
        ttl_s=3600,
        receipt_ttl_s=60,
        **kwargs,
    )
    token = store.issue(
        client_id=CLIENT_ID,
        subject="user-1",
        scope="menhir:read menhir:write",
        resource=RESOURCE,
        now=100,
    )
    return store, token


def _family_id(db_path, token: str) -> str:
    with sqlite3.connect(db_path) as conn:
        return str(
            conn.execute(
                "SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = ?",
                (hash_secret(token),),
            ).fetchone()[0]
        )


def test_exact_retry_survives_store_restart_and_is_identical(tmp_path) -> None:
    store, original = _refresh_store(tmp_path)
    first = store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=_keyring(),
        sign_response=_response,
        now=110,
    )
    assert first is not None and not first.replayed

    restarted = RefreshTokenStore(
        tmp_path / "oauth.db",
        ttl_s=3600,
        receipt_ttl_s=60,
    )
    replay = restarted.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=_keyring(),
        sign_response=lambda *_: (_ for _ in ()).throw(
            AssertionError("exact replay called signer")
        ),
        now=120,
    )

    assert replay is not None and replay.replayed
    assert replay.response == first.response


def test_concurrent_exact_retry_returns_one_identical_response(tmp_path) -> None:
    store, original = _refresh_store(tmp_path)

    def exchange():
        local = RefreshTokenStore(tmp_path / "oauth.db", ttl_s=3600, receipt_ttl_s=60)
        return local.rotate_durable(
            token=original,
            client_id=CLIENT_ID,
            resource=RESOURCE,
            keyring=_keyring(),
            sign_response=_response,
            now=110,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: exchange(), range(2)))

    assert all(result is not None for result in results)
    assert results[0].response == results[1].response
    assert sorted(result.replayed for result in results) == [False, True]


@pytest.mark.parametrize(
    ("retry_scope", "retry_at"),
    [("", 120), (None, 171)],
)
def test_variant_or_post_grace_retry_revokes_family(
    tmp_path,
    retry_scope: str | None,
    retry_at: float,
) -> None:
    store, original = _refresh_store(tmp_path)
    family_id = _family_id(store.db_path, original)
    assert store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        scope=None,
        keyring=_keyring(),
        sign_response=_response,
        now=110,
    )

    result = store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        scope=retry_scope,
        keyring=_keyring(),
        sign_response=_response,
        now=retry_at,
    )

    assert result is None
    assert store.family_is_revoked(family_id)


def test_corrupt_receipt_revokes_family_and_returns_no_credential(tmp_path) -> None:
    store, original = _refresh_store(tmp_path)
    family_id = _family_id(store.db_path, original)
    assert store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=_keyring(),
        sign_response=_response,
        now=110,
    )
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE oauth_refresh_receipts SET response_blob = 'corrupt'"
        )

    assert store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=_keyring(),
        sign_response=_response,
        now=120,
    ) is None
    assert store.family_is_revoked(family_id)


def test_key_rotation_can_read_old_receipt_during_grace(tmp_path) -> None:
    store, original = _refresh_store(tmp_path)
    first = store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=_keyring("old", b"o"),
        sign_response=_response,
        now=110,
    )
    rotating = ReceiptEncryptionKeyring(
        {"old": b"o" * 32, "new": b"n" * 32},
        current_key_id="new",
    )

    replay = store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=rotating,
        sign_response=_response,
        now=120,
    )

    assert replay is not None and first is not None
    assert replay.response == first.response


def test_successor_rotation_purges_predecessor_receipt_before_bounds(tmp_path) -> None:
    store, original = _refresh_store(
        tmp_path,
        receipt_global_limit=1,
        receipt_per_client_limit=1,
    )
    first = store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=_keyring(),
        sign_response=_response,
        now=110,
    )
    assert first is not None and first.refresh_token

    second = store.rotate_durable(
        token=first.refresh_token,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=_keyring(),
        sign_response=_response,
        now=120,
    )

    assert second is not None
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM oauth_refresh_receipts").fetchone()[0] == 1


def test_callback_failure_rolls_back_token_and_receipt(tmp_path) -> None:
    store, original = _refresh_store(tmp_path)

    with pytest.raises(RuntimeError, match="signing failed"):
        store.rotate_durable(
            token=original,
            client_id=CLIENT_ID,
            resource=RESOURCE,
            keyring=_keyring(),
            sign_response=lambda *_: (_ for _ in ()).throw(RuntimeError("signing failed")),
            now=110,
        )

    recovered = store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=_keyring(),
        sign_response=_response,
        now=120,
    )
    assert recovered is not None and not recovered.replayed


def test_receipt_database_contains_no_plaintext_tokens(tmp_path) -> None:
    store, original = _refresh_store(tmp_path)
    result = store.rotate_durable(
        token=original,
        client_id=CLIENT_ID,
        resource=RESOURCE,
        keyring=_keyring(),
        sign_response=_response,
        now=110,
    )
    assert result is not None and result.refresh_token

    database_bytes = store.db_path.read_bytes()
    assert original.encode() not in database_bytes
    assert result.refresh_token.encode() not in database_bytes
    assert str(result.response["access_token"]).encode() not in database_bytes


def test_receipt_bounds_cannot_exceed_hard_limits(tmp_path) -> None:
    with pytest.raises(ValueError, match="operator bound 256"):
        RefreshTokenStore(tmp_path / "global.db", receipt_global_limit=257)
    with pytest.raises(ValueError, match="operator bound 32"):
        RefreshTokenStore(tmp_path / "client.db", receipt_per_client_limit=33)


def test_legacy_refresh_schema_migrates_and_newer_schema_is_refused(tmp_path) -> None:
    db_path = tmp_path / "oauth.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """CREATE TABLE oauth_refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                family_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                scope TEXT NOT NULL,
                resource TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used_at REAL,
                revoked_at REAL
            )"""
        )

    RefreshTokenStore(db_path)
    with sqlite3.connect(db_path) as conn:
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(oauth_refresh_tokens)")
        }
        assert "family_version" in columns
        conn.execute(
            "UPDATE archolith_oauth_schema SET version = 2 "
            "WHERE component = 'durable_refresh'"
        )

    with pytest.raises(ValueError, match="schema version 2 is not supported"):
        RefreshTokenStore(db_path)


def test_component_schema_metadata_shape_is_refused_on_drift(tmp_path) -> None:
    db_path = tmp_path / "oauth.db"
    RefreshTokenStore(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE archolith_oauth_schema ADD COLUMN unexpected TEXT")

    with pytest.raises(ValueError, match="archolith_oauth_schema is incompatible"):
        RefreshTokenStore(db_path)


def _grant() -> AuthorizationGrant:
    return AuthorizationGrant(
        client_id=CLIENT_ID,
        redirect_uri="https://chat.example.test/callback",
        scope="menhir:read menhir:write",
        code_challenge="challenge",
        code_challenge_method="S256",
        resource=RESOURCE,
        subject="user-1",
    )


def _grant_digest(grant: AuthorizationGrant, state: str) -> str:
    return consent_request_digest(
        client_id=grant.client_id,
        redirect_uri=grant.redirect_uri,
        scope=grant.scope,
        code_challenge=grant.code_challenge,
        code_challenge_method=grant.code_challenge_method,
        resource=grant.resource,
        subject=grant.subject,
        state=state,
    )


def test_consent_nonce_register_and_code_issue_are_durable_and_atomic(tmp_path) -> None:
    db_path = tmp_path / "oauth.db"
    store = AuthorizationCodeStore(db_path, ttl_s=120)
    grant = _grant()
    digest = _grant_digest(grant, "state-1")
    assert store.register_consent_nonce(
        jti="jti-1",
        request_digest=digest,
        expires_at=200,
        now=100,
    )

    restarted = AuthorizationCodeStore(db_path, ttl_s=120)
    code = restarted.issue_with_consent_nonce(
        grant,
        jti="jti-1",
        state="state-1",
        now=110,
    )
    assert code
    assert restarted.issue_with_consent_nonce(
        grant,
        jti="jti-1",
        state="state-1",
        now=111,
    ) is None


def test_consent_variant_expiry_and_denial_fail_closed(tmp_path) -> None:
    store = AuthorizationCodeStore(tmp_path / "oauth.db")
    grant = _grant()
    digest = _grant_digest(grant, "state-1")
    assert store.register_consent_nonce(
        jti="denied",
        request_digest=digest,
        expires_at=200,
        now=100,
    )
    assert store.consume_consent_nonce(
        jti="denied",
        request_digest=digest,
        now=110,
    )
    assert store.issue_with_consent_nonce(
        grant,
        jti="denied",
        state="state-1",
        now=111,
    ) is None

    assert store.register_consent_nonce(
        jti="variant",
        request_digest=digest,
        expires_at=200,
        now=100,
    )
    assert store.issue_with_consent_nonce(
        grant,
        jti="variant",
        state="changed-state",
        now=110,
    ) is None
    assert store.issue_with_consent_nonce(
        grant,
        jti="variant",
        state="state-1",
        now=201,
    ) is None


def test_concurrent_consent_approval_issues_exactly_one_code(tmp_path) -> None:
    db_path = tmp_path / "oauth.db"
    store = AuthorizationCodeStore(db_path)
    grant = _grant()
    assert store.register_consent_nonce(
        jti="concurrent",
        request_digest=_grant_digest(grant, "state-1"),
        expires_at=200,
        now=100,
    )

    def approve():
        return AuthorizationCodeStore(db_path).issue_with_consent_nonce(
            grant,
            jti="concurrent",
            state="state-1",
            now=110,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(pool.map(lambda _: approve(), range(2)))

    assert sum(code is not None for code in codes) == 1
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM oauth_codes").fetchone()[0] == 1
