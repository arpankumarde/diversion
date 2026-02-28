"""AES-256 encryption for sensitive artifacts (cookie jars, auth tokens)."""

from __future__ import annotations

import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-256 key size
KEY_SIZE = 32
# GCM nonce size
NONCE_SIZE = 12


def generate_key() -> bytes:
    """Generate a random AES-256 key."""
    return secrets.token_bytes(KEY_SIZE)


def save_key(key: bytes, path: str | os.PathLike[str]) -> None:
    """Save encryption key to file with restrictive permissions."""
    from pathlib import Path

    key_path = Path(path)
    key_path.write_bytes(key)
    key_path.chmod(0o600)


def load_key(path: str | os.PathLike[str]) -> bytes:
    """Load encryption key from file."""
    from pathlib import Path

    return Path(path).read_bytes()


class ArtifactEncryptor:
    """AES-256-GCM encryption for sensitive data at rest."""

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data. Returns nonce + ciphertext (nonce is prepended)."""
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data. Expects nonce + ciphertext format."""
        if len(data) < NONCE_SIZE:
            raise ValueError("Data too short to contain nonce")
        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]
        return self._aesgcm.decrypt(nonce, ciphertext, None)
