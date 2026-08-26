"""Persistent signing-key storage with minimal safe rotation support.

The active private-key file remains a single private JWK for compatibility with
Menhir's existing deployment. Retired keys are stored separately as public JWKs
only, so old access tokens remain verifiable without retaining old private keys.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from . import jose


class SigningKeyStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @property
    def previous_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".previous.json")

    @property
    def lock_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".lock")

    def _load(self):
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return self._read_existing()

    def _read_existing(self):
        return jose.load_key(json.loads(self.path.read_text("utf-8")))

    @staticmethod
    def _public_jwk(key) -> dict[str, Any]:
        public = jose.serialize_key(key, private=False)
        if "d" in public:
            raise AssertionError("private key material leaked into public JWKS")
        return public

    @staticmethod
    def _write_json_atomic(path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=path.parent,
                prefix=path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as temp:
                json.dump(payload, temp, separators=(",", ":"))
                temp.flush()
                os.fsync(temp.fileno())
                temp_path = Path(temp.name)
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass
            os.replace(temp_path, path)
            temp_path = None
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def _acquire_lock(self, *, timeout_s: float = 5.0) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                return os.open(
                    str(self.lock_path),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"timed out waiting for signing-key lock: {self.lock_path}")
                time.sleep(0.05)

    def _release_lock(self, lock_fd: int) -> None:
        os.close(lock_fd)
        self.lock_path.unlink(missing_ok=True)

    def _load_previous_public_keys(self) -> list[dict[str, Any]]:
        if not self.previous_path.exists():
            return []
        payload = json.loads(self.previous_path.read_text("utf-8"))
        if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
            raise ValueError("retired signing-key file must contain a JSON array of JWK objects")
        result: list[dict[str, Any]] = []
        for item in payload:
            public = dict(item)
            if "d" in public:
                raise ValueError("retired signing-key file must not contain private material")
            result.append(public)
        return result

    def load_or_create(self):
        if self.path.exists():
            return self._load()

        lock_fd = self._acquire_lock()
        try:
            if self.path.exists():
                return self._load()
            key = jose.generate_signing_key()
            self._write_json_atomic(
                self.path,
                jose.serialize_key(key, private=True),
            )
            return key
        finally:
            self._release_lock(lock_fd)

    def load_existing(self):
        """Load the active key without creating files or changing metadata."""
        if not self.path.is_file():
            raise FileNotFoundError(f"signing key does not exist: {self.path}")
        return self._read_existing()

    def rotate(self, *, retain_previous: int = 1):
        """Create a new active key and retain up to N previous public keys.

        The retired public-key file is written before replacing the active key.
        A crash between those writes can temporarily duplicate the current key in
        JWKS, but cannot make already-issued tokens unverifiable.
        """
        if retain_previous < 0:
            raise ValueError("retain_previous must be zero or greater")

        lock_fd = self._acquire_lock()
        try:
            if not self.path.exists():
                key = jose.generate_signing_key()
                self._write_json_atomic(
                    self.path,
                    jose.serialize_key(key, private=True),
                )
                return key

            current = self._load()
            previous = [self._public_jwk(current), *self._load_previous_public_keys()]
            deduplicated: list[dict[str, Any]] = []
            seen_kids: set[str] = set()
            for public in previous:
                kid = str(public.get("kid", ""))
                if kid and kid in seen_kids:
                    continue
                if kid:
                    seen_kids.add(kid)
                deduplicated.append(public)

            retained = deduplicated[:retain_previous]
            if retained:
                self._write_json_atomic(self.previous_path, retained)
            else:
                self.previous_path.unlink(missing_ok=True)

            new_key = jose.generate_signing_key()
            self._write_json_atomic(
                self.path,
                jose.serialize_key(new_key, private=True),
            )
            return new_key
        finally:
            self._release_lock(lock_fd)

    @staticmethod
    def public_jwks(key) -> dict[str, list[dict[str, Any]]]:
        return {"keys": [SigningKeyStore._public_jwk(key)]}

    def public_jwks_all(self) -> dict[str, list[dict[str, Any]]]:
        active = self._public_jwk(self.load_or_create())
        return self._public_jwks_with_active(active)

    def public_jwks_existing(self) -> dict[str, list[dict[str, Any]]]:
        """Return the existing keyset without creating or chmodding key files."""
        active = self._public_jwk(self.load_existing())
        return self._public_jwks_with_active(active)

    def _public_jwks_with_active(
        self,
        active: dict[str, Any],
    ) -> dict[str, list[dict[str, Any]]]:
        keys = [active, *self._load_previous_public_keys()]
        deduplicated: list[dict[str, Any]] = []
        seen_kids: set[str] = set()
        for public in keys:
            kid = str(public.get("kid", ""))
            if kid and kid in seen_kids:
                continue
            if kid:
                seen_kids.add(kid)
            deduplicated.append(public)
        return {"keys": deduplicated}

    def key_ids(self) -> tuple[str, ...]:
        return tuple(
            str(key.get("kid", ""))
            for key in self.public_jwks_all()["keys"]
            if key.get("kid")
        )
