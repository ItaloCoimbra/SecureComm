"""Password-encrypted local identity, ratchet state, and verified contacts.

The vault is local client state, never a relay database. Application transactions
must hold ``transaction_lock`` across snapshot, mutation, and commit. Old backups
can roll back ratchets; restoring a backup is not a supported recovery mechanism.
"""

import base64
import copy
import ctypes
import json
import os
import re
import tempfile
import threading
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from filelock import FileLock, Timeout
from vodozemac import Account

from core.protocol import ValidationError, identity_from_account, validate_identity

MAX_VAULT_BYTES = 16 * 1024 * 1024
_MAGIC = b"SecureCommVault\x00\x01"
_HEADER_SIZE = len(_MAGIC) + 16 + 12
_STATE_FIELDS = {
    "account", "pickle_key", "contacts", "sessions", "outbox", "history",
    "seen", "prekey_count", "prekey_bundles",
}


class VaultError(ValueError):
    """Cannot safely open or persist a local profile; never contains secrets."""


class ContactError(VaultError):
    """A peer has not been explicitly trusted, or a trust operation mismatched."""


def _private_permissions(path, directory=False):
    if os.name != "nt":
        os.chmod(path, 0o700 if directory else 0o600)
        return
    # A protected owner-only DACL replaces inherited grants. OWNER RIGHTS (OW)
    # represents the object's current owner. No shell or username interpolation.
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    convert.restype = wintypes.BOOL
    set_security = advapi.SetFileSecurityW
    set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    set_security.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not convert("D:P(A;;FA;;;OW)", 1, ctypes.byref(descriptor), None):
        raise OSError("Cannot create private file permissions")
    try:
        if not set_security(str(path), 0x00000004 | 0x80000000, descriptor):
            raise OSError("Cannot apply private file permissions")
    finally:
        kernel.LocalFree(descriptor)


def _password_bytes(password):
    if not isinstance(password, str) or not password or len(password) > 4096:
        raise VaultError("A nonempty local vault password is required")
    try:
        return password.encode("utf-8")
    except UnicodeError:
        raise VaultError("Invalid local vault password") from None


def _derive_key(password, salt):
    # Format v1 fixes KDF parameters; an untrusted header cannot request costly
    # parameters. 32 MiB Scrypt memory per open/create, never per message.
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password)


def _pickle_key(state):
    value = state.get("pickle_key")
    if not isinstance(value, str):
        raise VaultError("Invalid local vault state")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise VaultError("Invalid local vault state") from None
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise VaultError("Invalid local vault state")
    return decoded


def _account(state):
    try:
        return Account.from_pickle(state["account"], _pickle_key(state))
    except Exception:
        raise VaultError("Invalid local identity state") from None


def _alias(alias):
    if not isinstance(alias, str) or re.fullmatch(r"[\w .@+-]{1,64}", alias) is None or alias.strip() != alias:
        raise ContactError("Invalid contact alias")
    return alias


def _validate_state(state):
    if type(state) is not dict or set(state) != _STATE_FIELDS:
        raise VaultError("Invalid local vault state")
    if not isinstance(state["account"], str) or not state["account"]:
        raise VaultError("Invalid local identity state")
    for name in ("contacts", "sessions", "outbox", "seen", "prekey_bundles"):
        if type(state[name]) is not dict:
            raise VaultError("Invalid local vault state")
    if type(state["history"]) is not list or type(state["prekey_count"]) is not int or state["prekey_count"] < 0:
        raise VaultError("Invalid local vault state")
    identity = identity_from_account(_account(state))
    found = set()
    for alias, contact in state["contacts"].items():
        _alias(alias)
        if type(contact) is not dict or set(contact) != {"alias", "identity", "revoked"}:
            raise VaultError("Invalid local contact state")
        if contact["alias"] != alias or type(contact["revoked"]) is not bool:
            raise VaultError("Invalid local contact state")
        try:
            peer = validate_identity(contact["identity"])
        except ValidationError:
            raise VaultError("Invalid local contact state") from None
        if peer["id"] in found or peer["id"] == identity["id"]:
            raise VaultError("Duplicate local contact identity")
        found.add(peer["id"])
    return identity


class IdentityVault:
    """One open profile per process; use ``with`` or call ``close`` explicitly."""

    def __init__(self, path, lock, salt, key, state):
        self.path = path
        self.transaction_lock = threading.RLock()
        self._lock = lock
        self._salt = salt
        self._key = key
        self._state = state
        self._closed = False
        self._creating = False

    @staticmethod
    def _acquire(path, create=False):
        requested = Path(path).expanduser()
        if requested.is_symlink():
            raise VaultError("A vault cannot be a symbolic link")
        path = requested.resolve()
        if not path.parent.exists():
            if not create:
                raise VaultError("Local vault does not exist")
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _private_permissions(path.parent, directory=True)
        lock_path = Path(str(path) + ".lock")
        if lock_path.is_symlink():
            raise VaultError("Invalid local vault lock")
        lock = FileLock(str(lock_path), timeout=0, mode=0o600, thread_local=False)
        try:
            lock.acquire()
            _private_permissions(lock_path)
        except (OSError, Timeout):
            lock.release()
            raise VaultError("Local vault is already open or cannot be locked") from None
        return path, lock

    @classmethod
    def create(cls, path, password):
        password = _password_bytes(password)
        lock = None
        try:
            path, lock = cls._acquire(path, create=True)
            if path.exists() or path.is_symlink():
                raise VaultError("Local vault already exists; it was not replaced")
            salt = os.urandom(16)
            pickle_key = os.urandom(32)
            state = {
                "account": Account().pickle(pickle_key),
                "pickle_key": base64.b64encode(pickle_key).decode("ascii"),
                "contacts": {}, "sessions": {}, "outbox": {}, "history": [],
                "seen": {}, "prekey_count": 0, "prekey_bundles": {},
            }
            vault = cls(path, lock, salt, _derive_key(password, salt), state)
            vault._creating = True
            vault.commit(state)
            return vault
        except Exception as exc:
            if lock is not None:
                lock.release()
            if isinstance(exc, VaultError):
                raise
            raise VaultError("Cannot create the local vault") from None

    @classmethod
    def open(cls, path, password):
        password = _password_bytes(password)
        lock = None
        try:
            path, lock = cls._acquire(path)
            if not path.is_file() or path.stat().st_size > MAX_VAULT_BYTES:
                raise VaultError("Local vault is missing or exceeds its size limit")
            with path.open("rb") as stream:
                data = stream.read(MAX_VAULT_BYTES + 1)
            if len(data) > MAX_VAULT_BYTES or len(data) < _HEADER_SIZE + 16 or not data.startswith(_MAGIC):
                raise VaultError("Unsupported or damaged local vault")
            salt = data[len(_MAGIC):len(_MAGIC) + 16]
            nonce = data[len(_MAGIC) + 16:_HEADER_SIZE]
            key = _derive_key(password, salt)
            raw = AESGCM(key).decrypt(nonce, data[_HEADER_SIZE:], data[:_HEADER_SIZE])
            state = json.loads(raw)
            _validate_state(state)
            _private_permissions(path)
            return cls(path, lock, salt, key, state)
        except Exception as exc:
            if lock is not None:
                lock.release()
            if isinstance(exc, VaultError):
                raise
            raise VaultError("Cannot open local vault: invalid password or damaged state") from None

    def _require_open(self):
        if self._closed or not self._lock.is_locked:
            raise VaultError("Local vault is closed")

    def snapshot(self):
        with self.transaction_lock:
            self._require_open()
            return copy.deepcopy(self._state)

    def public_identity(self):
        with self.transaction_lock:
            self._require_open()
            return identity_from_account(_account(self._state))

    def sign(self, payload):
        if not isinstance(payload, bytes):
            raise VaultError("Signing requires bytes")
        with self.transaction_lock:
            self._require_open()
            return _account(self._state).sign(payload).to_base64()

    def commit(self, state):
        """Write authenticated state before exposing the new snapshot to callers."""
        with self.transaction_lock:
            self._require_open()
            temporary = None
            replaced = False
            try:
                candidate = copy.deepcopy(state)
                identity = _validate_state(candidate)
                if identity != self.public_identity():
                    raise VaultError("A commit cannot replace the local identity")
                raw = json.dumps(candidate, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
                if len(raw) + _HEADER_SIZE + 16 > MAX_VAULT_BYTES:
                    raise VaultError("Local vault size limit reached")
                nonce = os.urandom(12)
                header = _MAGIC + self._salt + nonce
                data = header + AESGCM(self._key).encrypt(nonce, raw, header)
                fd, temporary = tempfile.mkstemp(prefix=".securecomm-", suffix=".tmp", dir=self.path.parent)
                with os.fdopen(fd, "wb") as stream:
                    _private_permissions(temporary)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                if self._creating:
                    # Atomic no-clobber publication for the first snapshot.
                    # Never replace an unrelated file appearing after _acquire.
                    os.link(temporary, self.path)
                else:
                    os.replace(temporary, self.path)
                replaced = True
                if os.name != "nt":
                    directory_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                self._state = candidate
                self._creating = False
            except Exception as exc:
                # A directory-sync failure after replacement is ambiguous. Close
                # instead of allowing a stale in-memory ratchet to continue.
                if replaced:
                    self.close()
                if isinstance(exc, VaultError):
                    raise
                raise VaultError("Cannot persist local vault state") from None
            finally:
                if temporary is not None:
                    try:
                        Path(temporary).unlink(missing_ok=True)
                    except OSError:
                        pass

    def list_contacts(self):
        with self.transaction_lock:
            self._require_open()
            return copy.deepcopy(list(self._state["contacts"].values()))

    def get_contact(self, alias):
        with self.transaction_lock:
            self._require_open()
            contact = self._state["contacts"].get(_alias(alias))
            if contact is None or contact["revoked"]:
                raise ContactError("Contact is unknown or revoked")
            return copy.deepcopy(contact)

    def require_contact_id(self, identity_id):
        with self.transaction_lock:
            self._require_open()
            for contact in self._state["contacts"].values():
                if contact["identity"]["id"] == identity_id and not contact["revoked"]:
                    return copy.deepcopy(contact)
            raise ContactError("Contact identity is unknown or revoked")

    def _verified_identity(self, identity, fingerprint):
        try:
            identity = validate_identity(identity)
        except ValidationError:
            raise ContactError("Invalid contact identity") from None
        if fingerprint != identity["id"]:
            raise ContactError("The independently verified fingerprint does not match")
        if identity["id"] == self.public_identity()["id"]:
            raise ContactError("The local identity cannot be added as a contact")
        return identity

    def add_contact(self, alias, identity, verified_fingerprint):
        with self.transaction_lock:
            self._require_open()
            alias = _alias(alias)
            identity = self._verified_identity(identity, verified_fingerprint)
            if alias in self._state["contacts"]:
                raise ContactError("Contact alias already exists; use explicit replacement")
            if any(item["identity"]["id"] == identity["id"] for item in self._state["contacts"].values()):
                raise ContactError("Contact identity already exists")
            state = self.snapshot()
            contact = {"alias": alias, "identity": identity, "revoked": False}
            state["contacts"][alias] = contact
            self.commit(state)
            return copy.deepcopy(contact)

    @staticmethod
    def _purge_peer(state, identity_id):
        state["sessions"].pop(identity_id, None)
        for message_id, pending in list(state["outbox"].items()):
            envelope = pending.get("envelope", {}) if isinstance(pending, dict) else {}
            if identity_id in (envelope.get("sender"), envelope.get("recipient")):
                del state["outbox"][message_id]

    def revoke_contact(self, alias, expected_id):
        with self.transaction_lock:
            self._require_open()
            alias = _alias(alias)
            contact = self._state["contacts"].get(alias)
            if contact is None or contact["identity"]["id"] != expected_id:
                raise ContactError("Contact fingerprint changed or does not exist")
            state = self.snapshot()
            state["contacts"][alias]["revoked"] = True
            self._purge_peer(state, expected_id)
            self.commit(state)
            return copy.deepcopy(state["contacts"][alias])

    def replace_contact(self, alias, identity, expected_old, verified_new):
        with self.transaction_lock:
            self._require_open()
            alias = _alias(alias)
            old = self._state["contacts"].get(alias)
            if old is None or old["identity"]["id"] != expected_old:
                raise ContactError("The previous contact fingerprint does not match")
            identity = self._verified_identity(identity, verified_new)
            for other_alias, contact in self._state["contacts"].items():
                if other_alias != alias and contact["identity"]["id"] == identity["id"]:
                    raise ContactError("Contact identity already exists")
            state = self.snapshot()
            self._purge_peer(state, expected_old)
            contact = {"alias": alias, "identity": identity, "revoked": False}
            state["contacts"][alias] = contact
            self.commit(state)
            return copy.deepcopy(contact)

    def close(self):
        with self.transaction_lock:
            if not self._closed:
                self._closed = True
                self._state = None
                self._key = None
                self._lock.release()

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
