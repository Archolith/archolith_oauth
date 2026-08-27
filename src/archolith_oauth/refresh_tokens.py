"""Rotating, replay-detecting refresh-token storage for public OAuth clients."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import RefreshTokenRecord
from .stores import (
    ReceiptCryptoError,
    ReceiptEncryptionKeyring,
    _component_schema_version,
    _record_component_schema,
    hash_secret,
)


class RefreshScopeError(ValueError):
    """Requested refresh scope exceeds the grant recorded for the family."""

    def __init__(self, description: str) -> None:
        super().__init__(description)
        self.description = description


def _connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=30.0)


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


@dataclass(frozen=True)
class DurableRotationResult:
    """Result of a durable refresh rotation, fresh or replayed."""

    response: dict[str, Any]
    record: RefreshTokenRecord | None
    refresh_token: str | None
    replayed: bool


def _canonical_scope(scope: str | None) -> str | None:
    """Return ``None`` for an omitted scope, else sorted space-joined tokens.

    ``None`` (omitted) is distinct from ``""`` (explicitly supplied empty or
    whitespace scope), so the request digest never conflates the two.
    """
    if scope is None:
        return None
    return " ".join(sorted(scope.split()))


def _request_digest(
    token_hash: str,
    client_id: str,
    resource: str,
    canonical_scope: str | None,
) -> str:
    payload = json.dumps(
        [token_hash, client_id, resource, canonical_scope],
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _record(row: sqlite3.Row, *, used_at: float | None = None) -> RefreshTokenRecord:
    return RefreshTokenRecord(
        family_id=row["family_id"],
        client_id=row["client_id"],
        subject=row["subject"],
        scope=row["scope"],
        resource=row["resource"],
        created_at=float(row["created_at"]),
        expires_at=float(row["expires_at"]),
        used_at=row["used_at"] if used_at is None else used_at,
        revoked_at=row["revoked_at"],
    )


class RefreshTokenStore:
    """SQLite-backed refresh tokens stored only as SHA-256 hashes.

    Tokens are single-use. Rotation happens in one SQLite transaction. Reusing
    an already-consumed token revokes its entire family, including the newest
    rotated token, as required for public-client refresh-token replay defense.

    The durable variant additionally persists an exact-response retry receipt so
    a concurrent or restarted retry can be replayed without revoking the family.
    """

    _RECEIPT_GLOBAL_LIMIT_DEFAULT = 256
    _RECEIPT_PER_CLIENT_LIMIT_DEFAULT = 32
    _RECEIPT_GLOBAL_LIMIT_MAX = 256
    _RECEIPT_PER_CLIENT_LIMIT_MAX = 32
    _DURABLE_SCHEMA_VERSION = 1

    _REFRESH_REQUIRED_COLUMNS = {
        "token_hash",
        "family_id",
        "family_version",
        "client_id",
        "subject",
        "scope",
        "resource",
        "created_at",
        "expires_at",
        "used_at",
        "revoked_at",
    }
    _RECEIPT_REQUIRED_COLUMNS = {
        "request_digest",
        "client_id",
        "family_id",
        "family_version",
        "successor_digest",
        "response_blob",
        "key_id",
        "key_version",
        "created_at",
        "expires_at",
    }

    def __init__(
        self,
        db_path: Path,
        *,
        ttl_s: float = 30 * 24 * 60 * 60,
        receipt_ttl_s: float = 60.0,
        receipt_global_limit: int = _RECEIPT_GLOBAL_LIMIT_DEFAULT,
        receipt_per_client_limit: int = _RECEIPT_PER_CLIENT_LIMIT_DEFAULT,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_s = float(ttl_s)
        if not self.ttl_s > 0 or self.ttl_s == float("inf"):
            raise ValueError("ttl_s must be a positive finite value")
        self.receipt_ttl_s = float(receipt_ttl_s)
        if not self.receipt_ttl_s > 0 or self.receipt_ttl_s == float("inf"):
            raise ValueError("receipt_ttl_s must be a positive finite value")
        self.receipt_global_limit = int(receipt_global_limit)
        self.receipt_per_client_limit = int(receipt_per_client_limit)
        if self.receipt_global_limit <= 0 or self.receipt_per_client_limit <= 0:
            raise ValueError("receipt bounds must be positive integers")
        if self.receipt_global_limit > self._RECEIPT_GLOBAL_LIMIT_MAX:
            raise ValueError(
                f"receipt_global_limit exceeds the operator bound "
                f"{self._RECEIPT_GLOBAL_LIMIT_MAX}"
            )
        if self.receipt_per_client_limit > self._RECEIPT_PER_CLIENT_LIMIT_MAX:
            raise ValueError(
                f"receipt_per_client_limit exceeds the operator bound "
                f"{self._RECEIPT_PER_CLIENT_LIMIT_MAX}"
            )
        with _connect(self.db_path) as conn:
            self._ensure_schema(conn)

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        schema_version = _component_schema_version(
            conn,
            "durable_refresh",
            self._DURABLE_SCHEMA_VERSION,
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                family_id TEXT NOT NULL,
                family_version INTEGER NOT NULL DEFAULT 0,
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
        columns = _columns(conn, "oauth_refresh_tokens")
        if "family_version" not in columns:
            conn.execute(
                "ALTER TABLE oauth_refresh_tokens "
                "ADD COLUMN family_version INTEGER NOT NULL DEFAULT 0"
            )
            columns = _columns(conn, "oauth_refresh_tokens")
        if columns != self._REFRESH_REQUIRED_COLUMNS:
            raise ValueError(
                "oauth_refresh_tokens schema is incompatible with this package version"
            )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_oauth_refresh_family "
            "ON oauth_refresh_tokens(family_id)"
        )

        conn.execute(
            """CREATE TABLE IF NOT EXISTS oauth_refresh_receipts (
                request_digest TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                family_id TEXT NOT NULL,
                family_version INTEGER NOT NULL,
                successor_digest TEXT NOT NULL,
                response_blob TEXT NOT NULL,
                key_id TEXT NOT NULL,
                key_version INTEGER NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )"""
        )
        if _columns(conn, "oauth_refresh_receipts") != self._RECEIPT_REQUIRED_COLUMNS:
            raise ValueError(
                "oauth_refresh_receipts schema is incompatible with this package version"
            )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_oauth_refresh_receipts_client "
            "ON oauth_refresh_receipts(client_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_oauth_refresh_receipts_successor "
            "ON oauth_refresh_receipts(successor_digest)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_oauth_refresh_receipts_family "
            "ON oauth_refresh_receipts(family_id)"
        )
        if schema_version is None:
            _record_component_schema(
                conn,
                "durable_refresh",
                self._DURABLE_SCHEMA_VERSION,
            )

    def _revoke_family(self, conn: sqlite3.Connection, family_id: str, at: float) -> None:
        conn.execute(
            "UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) "
            "WHERE family_id = ?",
            (at, family_id),
        )
        conn.execute(
            "DELETE FROM oauth_refresh_receipts WHERE family_id = ?",
            (family_id,),
        )

    def issue(
        self,
        *,
        client_id: str,
        subject: str,
        scope: str,
        resource: str,
        family_id: str | None = None,
        now: float | None = None,
    ) -> str:
        raw = secrets.token_urlsafe(48)
        issued_at = time.time() if now is None else now
        family = family_id or secrets.token_urlsafe(24)
        with _connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO oauth_refresh_tokens
                   (token_hash, family_id, family_version, client_id, subject,
                    scope, resource, created_at, expires_at, used_at, revoked_at)
                   VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    hash_secret(raw),
                    family,
                    client_id,
                    subject,
                    scope,
                    resource,
                    issued_at,
                    issued_at + self.ttl_s,
                ),
            )
        return raw

    def rotate(
        self,
        *,
        token: str,
        client_id: str,
        resource: str,
        scope: str | None = None,
        allowed_scopes: Collection[str] | None = None,
        required_scopes: Collection[str] | None = None,
        now: float | None = None,
    ) -> tuple[RefreshTokenRecord, str] | None:
        """Atomically rotate a token, optionally narrowing the family scope.

        An omitted or empty ``scope`` preserves the original scope. A scope
        equal to or a subset of the grant is validated before any mutation.
        When ``allowed_scopes`` is provided, the continued scope must also be
        inside the authorization server's current policy surface. On either
        failure ``RefreshScopeError`` is raised and the presented token stays
        valid. On success exactly one narrowed replacement is created.
        """
        token_hash = hash_secret(token)
        rotated_at = time.time() if now is None else now
        replacement = secrets.token_urlsafe(48)
        replacement_hash = hash_secret(replacement)

        requested_scopes: set[str] | None = None
        if scope is not None and scope.strip():
            requested_scopes = set(scope.split())

        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None

            valid = (
                row["client_id"] == client_id
                and row["resource"] == resource
                and row["used_at"] is None
                and row["revoked_at"] is None
                and float(row["expires_at"]) > rotated_at
            )
            if not valid:
                self._revoke_family(conn, row["family_id"], rotated_at)
                return None

            original_scopes = set(str(row["scope"]).split())
            continuation_scope = str(row["scope"])
            if requested_scopes is not None:
                if not requested_scopes.issubset(original_scopes):
                    raise RefreshScopeError(
                        "requested scope exceeds the originally granted scope"
                    )
                if requested_scopes != original_scopes:
                    continuation_scope = " ".join(sorted(requested_scopes))

            continued_scopes = set(continuation_scope.split())
            if allowed_scopes is not None and not continued_scopes.issubset(
                set(allowed_scopes)
            ):
                raise RefreshScopeError(
                    "continued scope is no longer supported by the authorization server"
                )
            if required_scopes is not None and continued_scopes != set(required_scopes):
                raise RefreshScopeError(
                    "continued scope does not match current client scope policy"
                )

            cursor = conn.execute(
                """UPDATE oauth_refresh_tokens SET used_at = ?
                   WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL
                     AND expires_at > ?""",
                (rotated_at, token_hash, rotated_at),
            )
            if cursor.rowcount != 1:
                self._revoke_family(conn, row["family_id"], rotated_at)
                return None

            conn.execute(
                "DELETE FROM oauth_refresh_receipts WHERE successor_digest = ?",
                (token_hash,),
            )

            conn.execute(
                """INSERT INTO oauth_refresh_tokens
                   (token_hash, family_id, family_version, client_id, subject,
                    scope, resource, created_at, expires_at, used_at, revoked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    replacement_hash,
                    row["family_id"],
                    int(row["family_version"]) + 1,
                    row["client_id"],
                    row["subject"],
                    continuation_scope,
                    row["resource"],
                    rotated_at,
                    rotated_at + self.ttl_s,
                ),
            )

        return _record(row, used_at=rotated_at), replacement

    def _replay_receipt(
        self,
        conn: sqlite3.Connection,
        receipt: sqlite3.Row,
        keyring: ReceiptEncryptionKeyring,
        *,
        aad: bytes,
        client_id: str,
        at: float,
    ) -> dict[str, Any] | None:
        """Decrypt and validate a stored receipt, revoking on any failure.

        Any undecryptable, malformed, key-mismatched, or stale receipt is treated
        as corruption: the family is revoked and its receipts deleted, and
        ``None`` is returned so the caller fails closed without a credential.
        """
        if (
            receipt["client_id"] != client_id
            or int(receipt["key_version"]) != keyring.schema_version
            or receipt["key_id"] not in keyring.key_ids
        ):
            self._revoke_family(conn, receipt["family_id"], at)
            return None

        successor = conn.execute(
            "SELECT family_version, used_at, revoked_at "
            "FROM oauth_refresh_tokens WHERE token_hash = ?",
            (receipt["successor_digest"],),
        ).fetchone()
        if (
            successor is None
            or successor["revoked_at"] is not None
            or successor["used_at"] is not None
            or int(successor["family_version"]) != int(receipt["family_version"])
        ):
            self._revoke_family(conn, receipt["family_id"], at)
            return None

        try:
            plaintext = keyring.decrypt(receipt["response_blob"], aad=aad)
            response = json.loads(plaintext.decode("utf-8"))
        except (ReceiptCryptoError, ValueError, UnicodeDecodeError):
            self._revoke_family(conn, receipt["family_id"], at)
            return None
        if not isinstance(response, dict):
            self._revoke_family(conn, receipt["family_id"], at)
            return None
        refresh_token = response.get("refresh_token")
        if not isinstance(refresh_token, str) or hash_secret(refresh_token) != receipt[
            "successor_digest"
        ]:
            self._revoke_family(conn, receipt["family_id"], at)
            return None
        return response

    def rotate_durable(
        self,
        *,
        token: str,
        client_id: str,
        resource: str,
        keyring: ReceiptEncryptionKeyring,
        sign_response: Callable[[RefreshTokenRecord, str], dict[str, Any]],
        scope: str | None = None,
        allowed_scopes: Collection[str] | None = None,
        required_scopes: Collection[str] | None = None,
        now: float | None = None,
    ) -> DurableRotationResult | None:
        """Rotate a refresh token and persist a durable retry receipt.

        The family validation, successor insert, and receipt insert happen in a
        single ``BEGIN IMMEDIATE`` transaction. The ``sign_response`` callback,
        response serialization, and encryption all run inside that transaction
        before commit, so any failure rolls back the rotation, successor, and
        receipt together.

        A concurrent or restarted retry presenting the same original token with
        the same ``client_id``, ``resource``, and canonical scope, within the
        receipt grace period, replays the exact previously-issued response
        (identical access and refresh strings) without revoking the family. A
        variant, post-grace, or corrupt replay fails closed and revokes the
        family.

        Only the request digest and an authenticated-encrypted, versioned
        response blob (plus key/version and family metadata) are persisted; the
        raw presented token and plaintext successor credentials are never stored.
        """
        token_hash = hash_secret(token)
        rotated_at = time.time() if now is None else now

        requested_scopes: set[str] | None = None
        if scope is not None and scope.strip():
            requested_scopes = set(scope.split())
        canonical_scope = _canonical_scope(scope)
        digest = _request_digest(token_hash, client_id, resource, canonical_scope)
        aad = digest.encode("ascii")

        with _connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")

            # Validate immutable per-client scope policy before any cleanup,
            # replay, revocation, rotation, successor, or receipt mutation.
            policy_row = conn.execute(
                "SELECT scope FROM oauth_refresh_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if policy_row is not None:
                policy_scopes = set(str(policy_row["scope"]).split())
                if required_scopes is not None and policy_scopes != set(required_scopes):
                    raise RefreshScopeError(
                        "continued scope does not match current client scope policy"
                    )

            conn.execute(
                "DELETE FROM oauth_refresh_receipts WHERE expires_at <= ?",
                (rotated_at,),
            )

            receipt = conn.execute(
                "SELECT * FROM oauth_refresh_receipts WHERE request_digest = ?",
                (digest,),
            ).fetchone()
            if receipt is not None:
                response = self._replay_receipt(
                    conn,
                    receipt,
                    keyring,
                    aad=aad,
                    client_id=client_id,
                    at=rotated_at,
                )
                if response is None:
                    return None
                refresh_token = response.get("refresh_token")
                return DurableRotationResult(
                    response=response,
                    record=None,
                    refresh_token=(
                        refresh_token if isinstance(refresh_token, str) else None
                    ),
                    replayed=True,
                )

            row = conn.execute(
                "SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None

            valid = (
                row["client_id"] == client_id
                and row["resource"] == resource
                and row["used_at"] is None
                and row["revoked_at"] is None
                and float(row["expires_at"]) > rotated_at
            )
            if not valid:
                self._revoke_family(conn, row["family_id"], rotated_at)
                return None

            original_scopes = set(str(row["scope"]).split())
            continuation_scope = str(row["scope"])
            if requested_scopes is not None:
                if not requested_scopes.issubset(original_scopes):
                    raise RefreshScopeError(
                        "requested scope exceeds the originally granted scope"
                    )
                if requested_scopes != original_scopes:
                    continuation_scope = " ".join(sorted(requested_scopes))

            continued_scopes = set(continuation_scope.split())
            if allowed_scopes is not None and not continued_scopes.issubset(
                set(allowed_scopes)
            ):
                raise RefreshScopeError(
                    "continued scope is no longer supported by the authorization server"
                )
            if required_scopes is not None and continued_scopes != set(required_scopes):
                raise RefreshScopeError(
                    "continued scope does not match current client scope policy"
                )

            # Once a successor is itself presented, its predecessor's exact-retry
            # grace must end. Purge that receipt before applying receipt bounds so
            # a full per-client/global cache cannot block normal family progress.
            conn.execute(
                "DELETE FROM oauth_refresh_receipts WHERE successor_digest = ?",
                (token_hash,),
            )

            global_count = conn.execute(
                "SELECT COUNT(*) FROM oauth_refresh_receipts WHERE expires_at > ?",
                (rotated_at,),
            ).fetchone()[0]
            per_client_count = conn.execute(
                "SELECT COUNT(*) FROM oauth_refresh_receipts "
                "WHERE client_id = ? AND expires_at > ?",
                (client_id, rotated_at),
            ).fetchone()[0]
            if (
                global_count >= self.receipt_global_limit
                or per_client_count >= self.receipt_per_client_limit
            ):
                return None

            cursor = conn.execute(
                """UPDATE oauth_refresh_tokens SET used_at = ?
                   WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL
                     AND expires_at > ?""",
                (rotated_at, token_hash, rotated_at),
            )
            if cursor.rowcount != 1:
                self._revoke_family(conn, row["family_id"], rotated_at)
                return None

            replacement = secrets.token_urlsafe(48)
            replacement_hash = hash_secret(replacement)
            new_version = int(row["family_version"]) + 1
            conn.execute(
                """INSERT INTO oauth_refresh_tokens
                   (token_hash, family_id, family_version, client_id, subject,
                    scope, resource, created_at, expires_at, used_at, revoked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    replacement_hash,
                    row["family_id"],
                    new_version,
                    row["client_id"],
                    row["subject"],
                    continuation_scope,
                    row["resource"],
                    rotated_at,
                    rotated_at + self.ttl_s,
                ),
            )

            record = _record(row, used_at=rotated_at)
            response = sign_response(record, replacement)
            if not isinstance(response, dict):
                raise ValueError("sign_response must return a dict")
            if response.get("refresh_token") != replacement:
                raise ValueError(
                    "sign_response must carry the rotated successor refresh token"
                )

            plaintext = json.dumps(response, separators=(",", ":")).encode("utf-8")
            blob = keyring.encrypt(plaintext, aad=aad)
            conn.execute(
                """INSERT INTO oauth_refresh_receipts
                   (request_digest, client_id, family_id, family_version,
                    successor_digest, response_blob, key_id, key_version,
                    created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    digest,
                    client_id,
                    row["family_id"],
                    new_version,
                    replacement_hash,
                    blob,
                    keyring.current_key_id,
                    keyring.schema_version,
                    rotated_at,
                    rotated_at + self.receipt_ttl_s,
                ),
            )

        return DurableRotationResult(
            response=response,
            record=record,
            refresh_token=replacement,
            replayed=False,
        )

    def family_is_revoked(self, family_id: str) -> bool:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM oauth_refresh_tokens "
                "WHERE family_id = ? AND revoked_at IS NOT NULL LIMIT 1",
                (family_id,),
            ).fetchone()
        return row is not None

    def purge_expired(self, *, now: float | None = None) -> int:
        cutoff = time.time() if now is None else now
        with _connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM oauth_refresh_tokens WHERE expires_at <= ?",
                (cutoff,),
            )
            conn.execute(
                "DELETE FROM oauth_refresh_receipts WHERE expires_at <= ?",
                (cutoff,),
            )
            return int(cursor.rowcount)
