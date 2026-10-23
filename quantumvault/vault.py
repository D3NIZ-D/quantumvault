"""Encrypted on-disk storage for generated passwords.

Cryptographic design
--------------------
* Key derivation: Argon2id (RFC 9106) turns the master password into a
  256-bit key. Argon2id is memory-hard, which makes brute forcing the master
  password expensive on GPUs, ASICs and any future quantum hardware alike.
* Encryption: AES-256-GCM (authenticated encryption). Grover's algorithm at
  best halves the effective key length, leaving 128-bit security, which is
  the level NIST considers safe against quantum computers.
* No public-key cryptography is used anywhere, so Shor's algorithm - the
  quantum attack that breaks RSA and elliptic curves - does not apply.

File format (JSON)::

    {
      "format": "quantumvault",
      "version": 1,
      "kdf": {"name": "argon2id", "salt": <b64>, "time_cost": .., "memory_cost": .., "parallelism": ..},
      "cipher": "aes-256-gcm",
      "nonce": <b64>,
      "ciphertext": <b64>
    }

The header (everything except nonce and ciphertext) is bound to the
ciphertext as AES-GCM associated data, so tampering with the KDF parameters
is detected. A fresh random 96-bit nonce is used for every save.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_NAME = "quantumvault"
FORMAT_VERSION = 1
KEY_BYTES = 32  # 256-bit key
SALT_BYTES = 32
NONCE_BYTES = 12

# Argon2id parameters. 256 MiB of memory and 4 passes take roughly a second on
# a modern desktop - slow enough to cripple guessing, fast enough to unlock.
DEFAULT_KDF = {"time_cost": 4, "memory_cost": 262_144, "parallelism": 4}

MIN_MASTER_PASSWORD_LENGTH = 12
MAX_TITLE_LENGTH = 200


class VaultError(Exception):
    """Base class for vault errors."""


class VaultLockedError(VaultError):
    pass


class InvalidMasterPasswordError(VaultError):
    pass


class EntryNotFoundError(VaultError):
    pass


@dataclass
class Entry:
    id: str
    title: str
    password: str
    entropy_bits: float
    created_at: str
    updated_at: str
    notes: str = ""

    def summary(self) -> dict:
        """Entry metadata without the secret itself."""
        data = asdict(self)
        data.pop("password")
        data["length"] = len(self.password)
        return data


@dataclass
class _State:
    key: bytes
    kdf: dict
    entries: list[Entry] = field(default_factory=list)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def derive_key(master_password: str, salt: bytes, kdf: dict) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=kdf["time_cost"],
        memory_cost=kdf["memory_cost"],
        parallelism=kdf["parallelism"],
        hash_len=KEY_BYTES,
        type=Type.ID,
    )


def _header(kdf: dict) -> dict:
    return {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "kdf": kdf,
        "cipher": "aes-256-gcm",
    }


def _aad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Vault:
    """Thread-safe encrypted password vault backed by a single file."""

    def __init__(self, path: str | os.PathLike, kdf_params: dict | None = None):
        self.path = Path(path)
        self._kdf_params = dict(kdf_params or DEFAULT_KDF)
        self._state: _State | None = None
        self._lock = threading.RLock()

    # -- lifecycle ---------------------------------------------------------

    @property
    def exists(self) -> bool:
        return self.path.is_file()

    @property
    def unlocked(self) -> bool:
        return self._state is not None

    def create(self, master_password: str) -> None:
        with self._lock:
            if self.exists:
                raise VaultError("A vault already exists at this location.")
            if len(master_password) < MIN_MASTER_PASSWORD_LENGTH:
                raise VaultError(
                    f"Master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters."
                )
            kdf = {"name": "argon2id", "salt": _b64e(secrets.token_bytes(SALT_BYTES)), **self._kdf_params}
            key = derive_key(master_password, _b64d(kdf["salt"]), kdf)
            self._state = _State(key=key, kdf=kdf)
            self._save()

    def unlock(self, master_password: str) -> None:
        with self._lock:
            if not self.exists:
                raise VaultError("No vault found. Create one first.")
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if raw.get("format") != FORMAT_NAME or raw.get("version") != FORMAT_VERSION:
                raise VaultError("Unsupported vault file format.")
            kdf = raw["kdf"]
            if kdf.get("name") != "argon2id":
                raise VaultError("Unsupported key derivation function.")
            key = derive_key(master_password, _b64d(kdf["salt"]), kdf)
            try:
                plaintext = AESGCM(key).decrypt(
                    _b64d(raw["nonce"]), _b64d(raw["ciphertext"]), _aad(_header(kdf))
                )
            except InvalidTag:
                raise InvalidMasterPasswordError("Wrong master password or corrupted vault.") from None
            payload = json.loads(plaintext.decode("utf-8"))
            entries = [Entry(**item) for item in payload.get("entries", [])]
            self._state = _State(key=key, kdf=kdf, entries=entries)

    def lock(self) -> None:
        with self._lock:
            # Python cannot reliably wipe immutable bytes, but dropping every
            # reference lets the memory be reclaimed as soon as possible.
            self._state = None

    # -- entries -----------------------------------------------------------

    def list_entries(self) -> list[Entry]:
        with self._lock:
            return list(self._require_state().entries)

    def get_entry(self, entry_id: str) -> Entry:
        with self._lock:
            for entry in self._require_state().entries:
                if entry.id == entry_id:
                    return entry
            raise EntryNotFoundError(entry_id)

    def add_entry(self, title: str, password: str, entropy_bits: float, notes: str = "") -> Entry:
        with self._lock:
            state = self._require_state()
            now = _now()
            entry = Entry(
                id=uuid.uuid4().hex,
                title=_clean_title(title),
                password=password,
                entropy_bits=round(entropy_bits, 2),
                created_at=now,
                updated_at=now,
                notes=_clean_notes(notes),
            )
            state.entries.append(entry)
            self._save()
            return entry

    def update_entry(
        self,
        entry_id: str,
        *,
        title: str | None = None,
        notes: str | None = None,
        password: str | None = None,
        entropy_bits: float | None = None,
    ) -> Entry:
        with self._lock:
            entry = self.get_entry(entry_id)
            if title is not None:
                entry.title = _clean_title(title)
            if notes is not None:
                entry.notes = _clean_notes(notes)
            if password is not None:
                entry.password = password
                entry.entropy_bits = round(entropy_bits or 0.0, 2)
            entry.updated_at = _now()
            self._save()
            return entry

    def delete_entry(self, entry_id: str) -> None:
        with self._lock:
            state = self._require_state()
            before = len(state.entries)
            state.entries = [e for e in state.entries if e.id != entry_id]
            if len(state.entries) == before:
                raise EntryNotFoundError(entry_id)
            self._save()

    # -- internals ---------------------------------------------------------

    def _require_state(self) -> _State:
        if self._state is None:
            raise VaultLockedError("Vault is locked.")
        return self._state

    def _save(self) -> None:
        state = self._require_state()
        header = _header(state.kdf)
        payload = json.dumps({"entries": [asdict(e) for e in state.entries]}).encode("utf-8")
        nonce = secrets.token_bytes(NONCE_BYTES)
        ciphertext = AESGCM(state.key).encrypt(nonce, payload, _aad(header))
        document = {**header, "nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}

        # Write to a temporary file and atomically replace, so a crash can
        # never leave a half-written (and therefore unreadable) vault.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".vault-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(document, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


def _clean_title(title: str) -> str:
    title = (title or "").strip()
    if not title:
        raise VaultError("Title is required.")
    if len(title) > MAX_TITLE_LENGTH:
        raise VaultError(f"Title must be at most {MAX_TITLE_LENGTH} characters.")
    return title


def _clean_notes(notes: str) -> str:
    notes = (notes or "").strip()
    if len(notes) > 2000:
        raise VaultError("Notes must be at most 2000 characters.")
    return notes
