"""Local, synthetic-data tests of the encrypted identity and trust store."""

import importlib
import os
import subprocess
import sys

import pytest
from vodozemac import Ed25519PublicKey, Ed25519Signature


@pytest.fixture
def identity_api():
    try:
        return importlib.import_module("core.identity")
    except ModuleNotFoundError as exc:
        pytest.fail(f"The identity vault implementation is missing: {exc.name}")


def test_identity_and_signature_survive_reopening(tmp_path, identity_api):
    path = tmp_path / "alice.vault"
    with identity_api.IdentityVault.create(path, "synthetic test password") as vault:
        identity = vault.public_identity()
        signature = vault.sign(b"synthetic transport challenge")
        Ed25519PublicKey.from_base64(identity["ed25519"]).verify_signature(
            b"synthetic transport challenge", Ed25519Signature.from_base64(signature)
        )
    with identity_api.IdentityVault.open(path, "synthetic test password") as vault:
        assert vault.public_identity() == identity
        assert vault.sign(b"synthetic transport challenge") == signature


def test_state_is_encrypted_and_snapshots_are_detached(tmp_path, identity_api):
    path = tmp_path / "alice.vault"
    with identity_api.IdentityVault.create(path, "synthetic test password") as vault:
        state = vault.snapshot()
        state["history"].append({"text": "synthetic private message 56ba42"})
        assert vault.snapshot()["history"] == []
        vault.commit(state)
        state["history"].clear()
        assert vault.snapshot()["history"] == [{"text": "synthetic private message 56ba42"}]
        assert b"synthetic private message" not in path.read_bytes()
        assert vault.public_identity()["ed25519"].encode() not in path.read_bytes()
    with identity_api.IdentityVault.open(path, "synthetic test password") as vault:
        assert vault.snapshot()["history"][0]["text"] == "synthetic private message 56ba42"


def test_password_and_corruption_fail_without_replacing_identity(tmp_path, identity_api):
    path = tmp_path / "alice.vault"
    with identity_api.IdentityVault.create(path, "synthetic test password"):
        pass
    original = path.read_bytes()
    with pytest.raises(identity_api.VaultError):
        identity_api.IdentityVault.open(path, "incorrect password")
    assert path.read_bytes() == original
    changed = bytearray(original)
    changed[-1] ^= 1
    path.write_bytes(changed)
    with pytest.raises(identity_api.VaultError):
        identity_api.IdentityVault.open(path, "synthetic test password")
    assert path.read_bytes() == changed


def test_create_never_overwrites_and_open_never_creates(tmp_path, identity_api):
    path = tmp_path / "alice.vault"
    with pytest.raises(identity_api.VaultError):
        identity_api.IdentityVault.open(path, "synthetic test password")
    assert not path.exists()
    with identity_api.IdentityVault.create(path, "synthetic test password"):
        pass
    original = path.read_bytes()
    with pytest.raises(identity_api.VaultError):
        identity_api.IdentityVault.create(path, "synthetic test password")
    assert path.read_bytes() == original


def test_exclusive_lock_and_closed_objects(tmp_path, identity_api):
    path = tmp_path / "alice.vault"
    vault = identity_api.IdentityVault.create(path, "synthetic test password")
    with pytest.raises(identity_api.VaultError):
        identity_api.IdentityVault.open(path, "synthetic test password")
    vault.close()
    vault.close()
    with pytest.raises(identity_api.VaultError):
        vault.snapshot()
    with pytest.raises(identity_api.VaultError):
        vault.sign(b"synthetic")
    with identity_api.IdentityVault.open(path, "synthetic test password"):
        pass


def test_failed_atomic_replace_preserves_disk_and_memory(tmp_path, identity_api, monkeypatch):
    path = tmp_path / "alice.vault"
    with identity_api.IdentityVault.create(path, "synthetic test password") as vault:
        original = path.read_bytes()
        before = vault.snapshot()
        changed = vault.snapshot()
        changed["history"].append({"text": "synthetic unsaved message"})

        def fail_replace(*args, **kwargs):
            raise OSError("synthetic disk failure")

        monkeypatch.setattr(identity_api.os, "replace", fail_replace)
        with pytest.raises(identity_api.VaultError):
            vault.commit(changed)
        assert vault.snapshot() == before
        assert path.read_bytes() == original
        assert not list(tmp_path.glob("*.tmp"))


def test_contact_requires_matching_fingerprint_and_returns_copies(tmp_path, identity_api):
    with identity_api.IdentityVault.create(tmp_path / "bob", "synthetic password") as bob:
        public = bob.public_identity()
    with identity_api.IdentityVault.create(tmp_path / "alice", "synthetic password") as alice:
        with pytest.raises(identity_api.ContactError):
            alice.add_contact("bob", public, "0" * 64)
        assert alice.list_contacts() == []
        alice.add_contact("bob", public, public["id"])
        contact = alice.get_contact("bob")
        assert contact == {"alias": "bob", "identity": public, "revoked": False}
        assert alice.require_contact_id(public["id"]) == contact
        contact["identity"]["ed25519"] = "changed"
        assert alice.get_contact("bob")["identity"] == public
        with pytest.raises(identity_api.ContactError):
            alice.add_contact("bob", public, public["id"])
        with pytest.raises(identity_api.ContactError):
            alice.add_contact("other alias", public, public["id"])


def test_revoke_is_persistent_and_removes_peer_sessions_outbox(tmp_path, identity_api):
    with identity_api.IdentityVault.create(tmp_path / "bob", "synthetic password") as bob:
        public = bob.public_identity()
    path = tmp_path / "alice"
    with identity_api.IdentityVault.create(path, "synthetic password") as alice:
        alice.add_contact("bob", public, public["id"])
        state = alice.snapshot()
        state["sessions"][public["id"]] = {"synthetic_session": "synthetic_pickle"}
        state["outbox"]["synthetic_id"] = {"envelope": {"recipient": public["id"]}}
        alice.commit(state)
        with pytest.raises(identity_api.ContactError):
            alice.revoke_contact("bob", "0" * 64)
        alice.revoke_contact("bob", public["id"])
        assert alice.list_contacts()[0]["revoked"] is True
        assert alice.snapshot()["sessions"] == {}
        assert alice.snapshot()["outbox"] == {}
        with pytest.raises(identity_api.ContactError):
            alice.get_contact("bob")
        with pytest.raises(identity_api.ContactError):
            alice.require_contact_id(public["id"])
    with identity_api.IdentityVault.open(path, "synthetic password") as alice:
        with pytest.raises(identity_api.ContactError):
            alice.require_contact_id(public["id"])


def test_contact_replacement_requires_old_and_new_fingerprints(tmp_path, identity_api):
    with identity_api.IdentityVault.create(tmp_path / "bob1", "synthetic password") as bob:
        old = bob.public_identity()
    with identity_api.IdentityVault.create(tmp_path / "bob2", "synthetic password") as bob:
        new = bob.public_identity()
    with identity_api.IdentityVault.create(tmp_path / "alice", "synthetic password") as alice:
        alice.add_contact("bob", old, old["id"])
        with pytest.raises(identity_api.ContactError):
            alice.replace_contact("bob", new, "0" * 64, new["id"])
        with pytest.raises(identity_api.ContactError):
            alice.replace_contact("bob", new, old["id"], "0" * 64)
        assert alice.get_contact("bob")["identity"] == old
        alice.replace_contact("bob", new, old["id"], new["id"])
        assert alice.get_contact("bob")["identity"] == new
        with pytest.raises(identity_api.ContactError):
            alice.require_contact_id(old["id"])


def test_invalid_state_and_oversized_file_fail_closed(tmp_path, identity_api):
    path = tmp_path / "alice"
    with identity_api.IdentityVault.create(path, "synthetic password") as alice:
        original = path.read_bytes()
        state = alice.snapshot()
        state["contacts"] = []
        with pytest.raises(identity_api.VaultError):
            alice.commit(state)
        assert path.read_bytes() == original
    with path.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(identity_api.VaultError):
        identity_api.IdentityVault.open(path, "synthetic password")


def test_vault_permissions_are_private_on_posix(tmp_path, identity_api):
    if os.name == "nt":
        pytest.skip("POSIX permission bits do not describe Windows DACLs")
    path = tmp_path / "alice"
    with identity_api.IdentityVault.create(path, "synthetic password"):
        assert path.stat().st_mode & 0o777 == 0o600


def test_empty_password_is_rejected(tmp_path, identity_api):
    with pytest.raises(identity_api.VaultError):
        identity_api.IdentityVault.create(tmp_path / "alice", "")


def test_exclusive_lock_rejects_a_second_process(tmp_path, identity_api):
    path = tmp_path / "alice"
    with identity_api.IdentityVault.create(path, "synthetic password"):
        child = subprocess.run(
            [sys.executable, "-c", (
                "import sys; from core.identity import IdentityVault, VaultError; "
                "\ntry: IdentityVault.open(sys.argv[1], 'synthetic password')"
                "\nexcept VaultError: print('locked')"
                "\nelse: raise SystemExit('unexpected access')"
            ), str(path)], capture_output=True, text=True, timeout=10, check=True,
        )
        assert child.stdout.strip() == "locked"


def test_commit_cannot_silently_replace_the_local_identity(tmp_path, identity_api):
    with identity_api.IdentityVault.create(tmp_path / "new", "synthetic password") as other:
        other_state = other.snapshot()
    path = tmp_path / "original"
    with identity_api.IdentityVault.create(path, "synthetic password") as vault:
        original = vault.public_identity()
        original_file = path.read_bytes()
        with pytest.raises(identity_api.VaultError):
            vault.commit(other_state)
        assert vault.public_identity() == original
        assert path.read_bytes() == original_file


def test_oversized_commit_retains_the_previous_state(tmp_path, identity_api):
    path = tmp_path / "alice"
    with identity_api.IdentityVault.create(path, "synthetic password") as vault:
        original = path.read_bytes()
        state = vault.snapshot()
        state["history"].append({"text": "x" * (16 * 1024 * 1024)})
        with pytest.raises(identity_api.VaultError):
            vault.commit(state)
        assert vault.snapshot()["history"] == []
        assert path.read_bytes() == original


def test_replacement_purges_old_peer_state_and_persists(tmp_path, identity_api):
    with identity_api.IdentityVault.create(tmp_path / "bob1", "synthetic password") as bob:
        old = bob.public_identity()
    with identity_api.IdentityVault.create(tmp_path / "bob2", "synthetic password") as bob:
        new = bob.public_identity()
    path = tmp_path / "alice"
    with identity_api.IdentityVault.create(path, "synthetic password") as alice:
        alice.add_contact("bob", old, old["id"])
        state = alice.snapshot()
        state["sessions"][old["id"]] = {"synthetic_session": "synthetic_pickle"}
        state["outbox"]["synthetic_id"] = {"envelope": {"recipient": old["id"]}}
        alice.commit(state)
        alice.replace_contact("bob", new, old["id"], new["id"])
        assert alice.snapshot()["sessions"] == {}
        assert alice.snapshot()["outbox"] == {}
    with identity_api.IdentityVault.open(path, "synthetic password") as alice:
        assert alice.get_contact("bob")["identity"] == new


def test_windows_dacl_is_protected_and_owner_only(tmp_path, identity_api):
    if os.name != "nt":
        pytest.skip("Windows DACL inspection requires Windows")
    import ctypes
    from ctypes import wintypes

    path = tmp_path / "alice"
    with identity_api.IdentityVault.create(path, "synthetic password"):
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_security = advapi.GetFileSecurityW
        get_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        get_security.restype = wintypes.BOOL
        convert = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
        convert.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
        convert.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        size = wintypes.DWORD()
        get_security(str(path), 4, None, 0, ctypes.byref(size))
        assert size.value > 0
        descriptor = ctypes.create_string_buffer(size.value)
        assert get_security(str(path), 4, descriptor, size.value, ctypes.byref(size))
        text = ctypes.c_void_p()
        assert convert(descriptor, 1, 4, ctypes.byref(text), None)
        try:
            assert ctypes.wstring_at(text) == "D:P(A;;FA;;;OW)"
        finally:
            kernel.LocalFree(text)


def test_create_preserves_a_file_that_appears_during_initialization(tmp_path, identity_api, monkeypatch):
    path = tmp_path / "alice"
    original_permissions = identity_api._private_permissions

    def concurrent_creation(temporary, directory=False):
        if str(temporary).endswith(".tmp"):
            path.write_bytes(b"synthetic preexisting file")
        return original_permissions(temporary, directory=directory)

    monkeypatch.setattr(identity_api, "_private_permissions", concurrent_creation)
    with pytest.raises(identity_api.VaultError):
        identity_api.IdentityVault.create(path, "synthetic password")
    assert path.read_bytes() == b"synthetic preexisting file"


def test_pending_prekey_publication_cache_is_persistent(tmp_path, identity_api):
    path = tmp_path / "alice"
    with identity_api.IdentityVault.create(path, "synthetic password") as vault:
        state = vault.snapshot()
        assert state.get("prekey_bundles") == {}
        state["prekey_bundles"]["relay:synthetic"] = {"identity": vault.public_identity(), "prekeys": []}
        vault.commit(state)
    with identity_api.IdentityVault.open(path, "synthetic password") as vault:
        assert vault.snapshot()["prekey_bundles"]["relay:synthetic"]["prekeys"] == []
