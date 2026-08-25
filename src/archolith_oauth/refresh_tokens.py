"""Rotating, replay-detecting refresh-token storage for public OAuth clients."""

from __future__ import annotations

import secrets
import sqlite3
import time
from pathlib import Path

from .models import RefreshTokenRecord
from .stores import hash_secret


class RefreshScopeError(ValueError):
    """Requested refresh scope exceeds the grant recorded for the family."""

    def __init__(self, description: str) -> None:
        super().__init__(description)
        self.description = description


def _connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=30.0)


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
    """

    def __init__(self, db_path: Path, *, ttl_s: float = 30 * 24 * 60 * 60) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_s = float(ttl_s)
        with _connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_oauth_refresh_family "
                "ON oauth_refresh_tokens(family_id)"
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
                   (token_hash, family_id, client_id, subject, scope, resource,
                    created_at, expires_at, used_at, revoked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
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
        now: float | None = None,
    ) -> tuple[RefreshTokenRecord, str] | None:
        """Atomically rotate a token, optionally narrowing the family scope.

        An omitted or empty ``scope`` preserves the original scope. A scope
        equal to or a subset of the grant is validated before any mutation:
        on expansion ``RefreshScopeError`` is raised and the presented token
        stays valid. On success exactly one narrowed replacement is created.
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
                conn.execute(
                    "UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) "
                    "WHERE family_id = ?",
                    (rotated_at, row["family_id"]),
                )
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

            cursor = conn.execute(
                """UPDATE oauth_refresh_tokens SET used_at = ?
                   WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL
                     AND expires_at > ?""",
                (rotated_at, token_hash, rotated_at),
            )
            if cursor.rowcount != 1:
                conn.execute(
                    "UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) "
                    "WHERE family_id = ?",
                    (rotated_at, row["family_id"]),
                )
                return None

            conn.execute(
                """INSERT INTO oauth_refresh_tokens
                   (token_hash, family_id, client_id, subject, scope, resource,
                    created_at, expires_at, used_at, revoked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    replacement_hash,
                    row["family_id"],
                    row["client_id"],
                    row["subject"],
                    continuation_scope,
                    row["resource"],
                    rotated_at,
                    rotated_at + self.ttl_s,
                ),
            )

        return _record(row, used_at=rotated_at), replacement

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
            return int(cursor.rowcount)
