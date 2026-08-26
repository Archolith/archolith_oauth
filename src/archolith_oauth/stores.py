"""SQLite stores for public clients and single-use authorization codes.

The client schema is intentionally compatible with Menhir's embedded OAuth AS
so an existing ``menhir_oauth_as.db`` can be adopted without rewriting rows.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .models import AuthCodeRecord, AuthorizationGrant, OAuthClient


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=30.0)


def _component_schema_version(
    conn: sqlite3.Connection,
    component: str,
    supported_version: int,
) -> int | None:
    """Return a component version, refusing unknown newer/invalid schemas."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS archolith_oauth_schema (
            component TEXT PRIMARY KEY,
            version INTEGER NOT NULL
        )"""
    )
    schema_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(archolith_oauth_schema)")
    }
    if schema_columns != {"component", "version"}:
        raise ValueError(
            "archolith_oauth_schema is incompatible with this package version"
        )
    row = conn.execute(
        "SELECT version FROM archolith_oauth_schema WHERE component = ?",
        (component,),
    ).fetchone()
    if row is None:
        return None
    version = int(row[0])
    if version != supported_version:
        raise ValueError(
            f"{component} schema version {version} is not supported; "
            f"this build requires version {supported_version}"
        )
    return version


def _record_component_schema(
    conn: sqlite3.Connection,
    component: str,
    version: int,
) -> None:
    conn.execute(
        "INSERT INTO archolith_oauth_schema (component, version) VALUES (?, ?)",
        (component, version),
    )


def consent_request_digest(
    *,
    client_id: str = "",
    redirect_uri: str = "",
    scope: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    resource: str = "",
    subject: str = "",
    state: str = "",
) -> str:
    """Canonical digest binding a consent nonce to its exact authorization request.

    Includes every field that identifies the authorization request so a JTI
    registered for one request cannot be replayed against a variant request.
    """
    payload = json.dumps(
        [
            client_id,
            redirect_uri,
            scope,
            code_challenge,
            code_challenge_method,
            resource,
            subject,
            state,
        ],
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ReceiptCryptoError(ValueError):
    """Durable receipt blob could not be authenticated or decrypted."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ReceiptCryptoError(
            "cryptography is required for durable refresh receipts"
        ) from exc
    return AESGCM


def _normalize_key(value: bytes | str | bytearray) -> bytes:
    if isinstance(value, str):
        key_bytes = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        key_bytes = bytes(value)
    else:
        raise ValueError("receipt keyring keys must be bytes or str")
    if len(key_bytes) != 32:
        raise ValueError("receipt keyring keys must be exactly 32 bytes (AES-256)")
    return key_bytes


class ReceiptEncryptionKeyring:
    """Versioned AES-256-GCM keyring for durable refresh retry receipts.

    Keys are 32-byte AES-256 keys keyed by an opaque ``key_id``. ``encrypt``
    produces a self-describing, versioned blob that ``decrypt`` can authenticate
    and reverse without the caller remembering which key was current. The blob
    is bound to caller-supplied associated data so a receipt cannot be replayed
    against a different request.
    """

    _SCHEMA_VERSION = 1
    _NONCE_BYTES = 12

    def __init__(
        self,
        keys: Mapping[str, bytes | str | bytearray],
        *,
        current_key_id: str | None = None,
    ) -> None:
        if not keys:
            raise ValueError("receipt keyring requires at least one key")
        normalized: dict[str, bytes] = {}
        for key_id, value in keys.items():
            normalized[str(key_id)] = _normalize_key(value)
        if current_key_id is None:
            if len(normalized) == 1:
                current_key_id = next(iter(normalized))
            else:
                raise ValueError(
                    "current_key_id is required when multiple keys are present"
                )
        current_key_id = str(current_key_id)
        if current_key_id not in normalized:
            raise ValueError("current_key_id is not present in the keyring")
        self._keys = normalized
        self._current_key_id = current_key_id

    @property
    def current_key_id(self) -> str:
        return self._current_key_id

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(self._keys)

    @property
    def schema_version(self) -> int:
        return self._SCHEMA_VERSION

    def encrypt(self, plaintext: bytes, *, aad: bytes = b"") -> str:
        key_id = self._current_key_id
        nonce = os.urandom(self._NONCE_BYTES)
        ciphertext = _aesgcm()(self._keys[key_id]).encrypt(nonce, plaintext, aad)
        return ".".join(
            (
                str(self._SCHEMA_VERSION),
                _b64e(key_id.encode("utf-8")),
                _b64e(nonce),
                _b64e(ciphertext),
            )
        )

    def decrypt(self, blob: str, *, aad: bytes = b"") -> bytes:
        parts = blob.split(".")
        if len(parts) != 4:
            raise ReceiptCryptoError("receipt blob is malformed")
        version, key_id_b64, nonce_b64, ciphertext_b64 = parts
        try:
            version_int = int(version)
        except ValueError as exc:
            raise ReceiptCryptoError("receipt blob has an invalid schema version") from exc
        if version_int != self._SCHEMA_VERSION:
            raise ReceiptCryptoError("receipt blob uses an unsupported schema version")
        try:
            key_id = _b64d(key_id_b64).decode("utf-8")
            nonce = _b64d(nonce_b64)
            ciphertext = _b64d(ciphertext_b64)
        except Exception as exc:
            raise ReceiptCryptoError("receipt blob is malformed") from exc
        key = self._keys.get(key_id)
        if key is None:
            raise ReceiptCryptoError("receipt blob references an unknown key")
        try:
            return _aesgcm()(key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise ReceiptCryptoError("receipt blob authentication failed") from exc


class OAuthClientStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with _connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_name TEXT NOT NULL,
                    redirect_uris TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    client_secret_hash TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    token_endpoint_auth_method TEXT NOT NULL,
                    last_exchanged REAL
                )"""
            )
            columns = {
                str(row[1]) for row in conn.execute("PRAGMA table_info(oauth_clients)")
            }
            if "client_secret_hash" not in columns:
                conn.execute(
                    "ALTER TABLE oauth_clients "
                    "ADD COLUMN client_secret_hash TEXT NOT NULL DEFAULT ''"
                )
            if "last_exchanged" not in columns:
                conn.execute("ALTER TABLE oauth_clients ADD COLUMN last_exchanged REAL")

    @staticmethod
    def _row_to_client(row: sqlite3.Row) -> OAuthClient:
        return OAuthClient(
            client_id=row["client_id"],
            client_name=row["client_name"],
            redirect_uris=tuple(json.loads(row["redirect_uris"])),
            scopes=tuple(json.loads(row["scopes"])),
            client_secret_hash=row["client_secret_hash"] or "",
            token_endpoint_auth_method=row["token_endpoint_auth_method"],
            created_at=float(row["created_at"]),
            last_exchanged=row["last_exchanged"],
        )

    def register(self, client: OAuthClient) -> None:
        with self._lock, _connect(self.db_path) as conn:
            try:
                conn.execute(
                    """INSERT INTO oauth_clients
                       (client_id, client_name, redirect_uris, scopes,
                        client_secret_hash, created_at,
                        token_endpoint_auth_method, last_exchanged)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        client.client_id,
                        client.client_name,
                        json.dumps(list(client.redirect_uris)),
                        json.dumps(list(client.scopes)),
                        client.client_secret_hash,
                        client.created_at,
                        client.token_endpoint_auth_method,
                        client.last_exchanged,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("client_id already registered") from exc

    def get(self, client_id: str) -> OAuthClient | None:
        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """SELECT client_id, client_name, redirect_uris, scopes,
                          client_secret_hash, created_at,
                          token_endpoint_auth_method, last_exchanged
                   FROM oauth_clients WHERE client_id = ?""",
                (client_id,),
            ).fetchone()
        return None if row is None else self._row_to_client(row)

    def mark_exchanged(self, client_id: str, *, now: float | None = None) -> None:
        with self._lock, _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE oauth_clients SET last_exchanged = ? WHERE client_id = ?",
                (time.time() if now is None else now, client_id),
            )

    def reap_never_exchanged(self, max_age_s: float, *, now: float | None = None) -> int:
        cutoff = (time.time() if now is None else now) - max_age_s
        with self._lock, _connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM oauth_clients "
                "WHERE last_exchanged IS NULL AND created_at < ?",
                (cutoff,),
            )
            return int(cursor.rowcount)

    def reap_stale(self, max_age_s: float, *, now: float | None = None) -> int:
        """Menhir-compatible alias for ``reap_never_exchanged``."""
        return self.reap_never_exchanged(max_age_s, now=now)

    def count(self) -> int:
        with _connect(self.db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()
        return int(row[0]) if row else 0

    def all(self) -> list[OAuthClient]:
        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT client_id, client_name, redirect_uris, scopes,
                          client_secret_hash, created_at,
                          token_endpoint_auth_method, last_exchanged
                   FROM oauth_clients ORDER BY created_at ASC"""
            ).fetchall()
        return [self._row_to_client(row) for row in rows]

    def verify_secret(self, client_id: str, presented_secret: str) -> bool:
        client = self.get(client_id)
        if client is None or not client.client_secret_hash:
            return False
        return hmac.compare_digest(
            client.client_secret_hash,
            hash_secret(presented_secret),
        )


class AuthorizationCodeStore:
    _CONSENT_SCHEMA_VERSION = 1
    _CONSENT_REG_COLUMNS = {
        "jti",
        "request_digest",
        "expires_at",
        "consumed_at",
    }
    _CONSENT_SPENT_COLUMNS = {"jti", "consumed_at", "expires_at"}

    def __init__(self, db_path: Path, *, ttl_s: float = 120.0) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_s = float(ttl_s)
        self._lock = threading.Lock()
        with _connect(self.db_path) as conn:
            consent_version = _component_schema_version(
                conn,
                "durable_consent",
                self._CONSENT_SCHEMA_VERSION,
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_codes (
                    code_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    code_challenge_method TEXT NOT NULL,
                    resource TEXT,
                    subject TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    redeemed_at REAL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_consent_nonces (
                    jti TEXT PRIMARY KEY,
                    consumed_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_consent_nonce_regs (
                    jti TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                )"""
            )
            reg_columns = {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(oauth_consent_nonce_regs)")
            }
            spent_columns = {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(oauth_consent_nonces)")
            }
            if reg_columns != self._CONSENT_REG_COLUMNS:
                raise ValueError(
                    "oauth_consent_nonce_regs schema is incompatible with this package version"
                )
            if spent_columns != self._CONSENT_SPENT_COLUMNS:
                raise ValueError(
                    "oauth_consent_nonces schema is incompatible with this package version"
                )
            if consent_version is None:
                _record_component_schema(
                    conn,
                    "durable_consent",
                    self._CONSENT_SCHEMA_VERSION,
                )

    def issue(
        self,
        grant: AuthorizationGrant | None = None,
        *,
        client_id: str = "",
        redirect_uri: str = "",
        scope: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "S256",
        resource: str = "",
        subject: str = "",
    ) -> str:
        """Issue from a grant object or Menhir's existing keyword call shape."""
        if grant is None:
            if not all(
                (
                    client_id,
                    redirect_uri,
                    code_challenge,
                    resource,
                    subject,
                )
            ):
                raise ValueError(
                    "client_id, redirect_uri, code_challenge, resource, and subject are required"
                )
            grant = AuthorizationGrant(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                resource=resource,
                subject=subject,
            )
        if grant.code_challenge_method != "S256":
            raise ValueError("code_challenge_method must be S256")

        raw = secrets.token_urlsafe(32)
        now = time.time()
        with _connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO oauth_codes
                   (code_hash, client_id, redirect_uri, scope, code_challenge,
                    code_challenge_method, resource, subject, created_at,
                    expires_at, redeemed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                (
                    hash_secret(raw),
                    grant.client_id,
                    grant.redirect_uri,
                    grant.scope,
                    grant.code_challenge,
                    grant.code_challenge_method,
                    grant.resource,
                    grant.subject,
                    now,
                    now + self.ttl_s,
                ),
            )
        return raw

    def register_consent_nonce(
        self,
        *,
        jti: str,
        expires_at: float,
        request_digest: str,
        now: float | None = None,
    ) -> bool:
        """Register an unspent consent JTI bound to an exact request digest.

        The JTI must already have been minted by the consent token manager; this
        records its unspent state so a later ``consume_consent_nonce`` or
        ``issue_with_consent_nonce`` can transition it exactly once. Returns
        ``False`` when the JTI is missing, malformed, expired, or already
        registered.
        """
        if not isinstance(jti, str) or not jti:
            return False
        if not isinstance(expires_at, (int, float)):
            return False
        current = time.time() if now is None else now
        if expires_at <= current:
            return False
        with _connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """INSERT INTO oauth_consent_nonce_regs
                       (jti, request_digest, expires_at, consumed_at)
                       VALUES (?, ?, ?, NULL)""",
                    (jti, request_digest, expires_at),
                )
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
        return True

    def consume_consent_nonce(
        self,
        *,
        jti: str,
        request_digest: str,
        now: float | None = None,
    ) -> bool:
        """Spend a registered consent JTI without issuing an authorization code.

        Used for the denial and failed-secret paths so a nonce can never be
        approved after it has been refused. The JTI must exist unspent with a
        matching request digest and unexpired time bound; otherwise returns
        ``False`` and mutates nothing.
        """
        if not isinstance(jti, str) or not jti:
            return False
        current = time.time() if now is None else now
        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT expires_at FROM oauth_consent_nonce_regs
                   WHERE jti = ? AND consumed_at IS NULL
                     AND expires_at > ? AND request_digest = ?""",
                (jti, current, request_digest),
            ).fetchone()
            if row is None:
                conn.rollback()
                return False
            conn.execute(
                "UPDATE oauth_consent_nonce_regs SET consumed_at = ? "
                "WHERE jti = ? AND consumed_at IS NULL",
                (current, jti),
            )
            conn.execute(
                "INSERT INTO oauth_consent_nonces VALUES (?, ?, ?)",
                (jti, current, row["expires_at"]),
            )
        return True

    def issue_with_consent_nonce(
        self,
        grant: AuthorizationGrant | None = None,
        *,
        jti: str,
        state: str = "",
        client_id: str = "",
        redirect_uri: str = "",
        scope: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "S256",
        resource: str = "",
        subject: str = "",
        now: float | None = None,
    ) -> str | None:
        """Atomically consume a registered consent JTI and issue an auth code.

        The presented grant and ``state`` are recomputed into a request digest
        that must exactly match the digest the JTI was registered with, verified
        in the same ``BEGIN IMMEDIATE`` transaction that marks the nonce spent
        and inserts the code. A missing, expired, already-spent, or variant
        nonce fails closed and returns ``None`` without minting a code; no two
        calls can ever be issued a code for the same JTI. Grant validation
        errors (the same conditions ``issue`` rejects) still raise
        ``ValueError``.
        """
        if not isinstance(jti, str) or not jti:
            return None
        current = time.time() if now is None else now

        if grant is None:
            if not all(
                (
                    client_id,
                    redirect_uri,
                    code_challenge,
                    resource,
                    subject,
                )
            ):
                raise ValueError(
                    "client_id, redirect_uri, code_challenge, resource, and subject are required"
                )
            grant = AuthorizationGrant(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                resource=resource,
                subject=subject,
            )
        if grant.code_challenge_method != "S256":
            raise ValueError("code_challenge_method must be S256")

        request_digest = consent_request_digest(
            client_id=grant.client_id,
            redirect_uri=grant.redirect_uri,
            scope=grant.scope,
            code_challenge=grant.code_challenge,
            code_challenge_method=grant.code_challenge_method,
            resource=grant.resource,
            subject=grant.subject,
            state=state,
        )

        raw = secrets.token_urlsafe(32)
        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT expires_at FROM oauth_consent_nonce_regs
                   WHERE jti = ? AND consumed_at IS NULL
                     AND expires_at > ? AND request_digest = ?""",
                (jti, current, request_digest),
            ).fetchone()
            if row is None:
                conn.rollback()
                return None
            conn.execute(
                "UPDATE oauth_consent_nonce_regs SET consumed_at = ? "
                "WHERE jti = ? AND consumed_at IS NULL",
                (current, jti),
            )
            conn.execute(
                "INSERT INTO oauth_consent_nonces VALUES (?, ?, ?)",
                (jti, current, row["expires_at"]),
            )
            conn.execute(
                """INSERT INTO oauth_codes
                   (code_hash, client_id, redirect_uri, scope, code_challenge,
                    code_challenge_method, resource, subject, created_at,
                    expires_at, redeemed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                (
                    hash_secret(raw),
                    grant.client_id,
                    grant.redirect_uri,
                    grant.scope,
                    grant.code_challenge,
                    grant.code_challenge_method,
                    grant.resource,
                    grant.subject,
                    current,
                    current + self.ttl_s,
                ),
            )
        return raw

    def redeem(
        self,
        *,
        code: str,
        client_id: str,
        redirect_uri: str,
    ) -> AuthCodeRecord | None:
        now = time.time()
        code_hash = hash_secret(code)
        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """UPDATE oauth_codes SET redeemed_at = ?
                   WHERE code_hash = ? AND redeemed_at IS NULL AND expires_at > ?""",
                (now, code_hash, now),
            )
            if cursor.rowcount != 1:
                return None
            row = conn.execute(
                "SELECT * FROM oauth_codes WHERE code_hash = ?",
                (code_hash,),
            ).fetchone()
        if (
            row is None
            or row["client_id"] != client_id
            or row["redirect_uri"] != redirect_uri
        ):
            return None
        return AuthCodeRecord(
            client_id=row["client_id"],
            redirect_uri=row["redirect_uri"],
            scope=row["scope"],
            code_challenge=row["code_challenge"],
            code_challenge_method=row["code_challenge_method"],
            resource=row["resource"] or "",
            subject=row["subject"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            redeemed_at=row["redeemed_at"],
        )

    def purge_expired(self, *, now: float | None = None) -> int:
        cutoff = time.time() if now is None else now
        with self._lock, _connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM oauth_codes "
                "WHERE expires_at <= ? OR redeemed_at IS NOT NULL",
                (cutoff,),
            )
            conn.execute(
                "DELETE FROM oauth_consent_nonce_regs WHERE expires_at <= ?",
                (cutoff,),
            )
            return int(cursor.rowcount)
