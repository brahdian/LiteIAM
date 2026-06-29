from __future__ import annotations

import asyncio
import base64
import secrets
from datetime import UTC, datetime, timedelta, timezone
from typing import Dict, List, Optional

import structlog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.signing_key import SigningKey

logger = structlog.get_logger(__name__)


def _make_fernet() -> Fernet:
    return Fernet(settings.fernet_key())


def _encrypt_pem(pem: bytes) -> str:
    return _make_fernet().encrypt(pem).decode()


def _decrypt_pem(enc: str) -> bytes:
    return _make_fernet().decrypt(enc.encode())


def _generate_rsa_pair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=settings.RSA_KEY_SIZE
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _pem_to_jwk(public_pem: bytes, kid: str) -> dict:
    key = serialization.load_pem_public_key(public_pem)
    pub_numbers = key.public_numbers()

    def _b64url(n: int) -> str:
        byte_len = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(byte_len, "big")).rstrip(b"=").decode()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url(pub_numbers.n),
        "e": _b64url(pub_numbers.e),
    }


class KeyManager:
    """
    Process-local RSA key manager. Caches the current signing key and all valid
    public keys in memory. Initialized once on startup via `initialize(session)`.
    Thread-safe for asyncio (single event loop per worker); rotation is locked.
    """

    def __init__(self) -> None:
        self._current: dict | None = None  # {kid, private_pem, public_pem}
        self._valid_jwks: list[dict] = []
        # kid → public_pem bytes for ALL valid (not just current) keys
        self._public_pems: dict[str, bytes] = {}
        self._rotation_lock = asyncio.Lock()

    async def initialize(self, db: AsyncSession) -> None:
        current_row = await db.scalar(
            select(SigningKey).where(SigningKey.is_current)
        )
        if current_row is None:
            logger.info("No signing key found — generating initial RSA key pair")
            current_row = await self._create_key(db)

        self._current = {
            "kid": current_row.kid,
            "private_pem": _decrypt_pem(current_row.private_key_enc),
            "public_pem": current_row.public_key_pem.encode(),
        }

        valid_rows = list(await db.scalars(
            select(SigningKey).where(SigningKey.expires_at > datetime.now(UTC))
        ))
        self._valid_jwks = [
            _pem_to_jwk(r.public_key_pem.encode(), r.kid)
            for r in valid_rows
        ]
        # Cache public PEM for every valid key so rotated-out keys can still verify tokens
        self._public_pems = {r.kid: r.public_key_pem.encode() for r in valid_rows}
        logger.info("KeyManager initialized", kid=self._current["kid"], valid_keys=len(self._valid_jwks))

    async def _create_key(self, db: AsyncSession) -> SigningKey:
        private_pem, public_pem = _generate_rsa_pair()
        kid = secrets.token_urlsafe(8)
        row = SigningKey(
            kid=kid,
            private_key_enc=_encrypt_pem(private_pem),
            public_key_pem=public_pem.decode(),
            is_current=True,
            expires_at=datetime.now(UTC) + timedelta(days=settings.SIGNING_KEY_ROTATION_DAYS),
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return row

    def get_current_key(self) -> dict:
        if self._current is None:
            raise RuntimeError("KeyManager.initialize() must be called before use")
        return self._current

    def get_jwks(self) -> dict:
        return {"keys": list(self._valid_jwks)}

    def get_public_pem_by_kid(self, kid: str) -> bytes | None:
        # Returns PEM for ANY valid key (current or rotated-out but not yet expired)
        # so tokens signed before a key rotation remain verifiable within their TTL.
        return self._public_pems.get(kid)

    async def rotate(self, db: AsyncSession) -> str:
        async with self._rotation_lock:
            await db.execute(update(SigningKey).values(is_current=False))
            # _create_key opens its own session commit — use a fresh engine connection
            # to avoid committing the caller's in-progress transaction.
            from sqlalchemy.ext.asyncio import AsyncSession as _AS

            from app.core.database import engine as _engine
            async with _AS(bind=_engine) as fresh_db:
                new_row = await self._create_key(fresh_db)
            self._current = {
                "kid": new_row.kid,
                "private_pem": _decrypt_pem(new_row.private_key_enc),
                "public_pem": new_row.public_key_pem.encode(),
            }
            new_pem = new_row.public_key_pem.encode()
            # Append new JWK and PEM; keep old ones until their expiry
            self._valid_jwks.append(_pem_to_jwk(new_pem, new_row.kid))
            self._public_pems[new_row.kid] = new_pem
            logger.info("Signing key rotated", new_kid=new_row.kid)
            # Invalidate the in-process JWKS response cache so the next fetch reflects the new key.
            try:
                from app.api.v1.jwks import invalidate_jwks_cache
                invalidate_jwks_cache()
            except ImportError:
                pass
            return new_row.kid


# Process-level singleton — one per uvicorn worker
key_manager = KeyManager()
