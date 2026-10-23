import json

import pytest

from quantumvault.vault import (
    EntryNotFoundError,
    InvalidMasterPasswordError,
    Vault,
    VaultError,
    VaultLockedError,
)

# Light Argon2id parameters keep the test suite fast.
FAST_KDF = {"time_cost": 1, "memory_cost": 8_192, "parallelism": 1}
MASTER = "correct horse battery staple"


@pytest.fixture
def vault(tmp_path):
    v = Vault(tmp_path / "vault.json", kdf_params=FAST_KDF)
    v.create(MASTER)
    return v


def test_roundtrip(vault, tmp_path):
    entry = vault.add_entry("GitHub", "s3cret!" * 8, 300.0, notes="me@example.com")
    vault.lock()

    reopened = Vault(tmp_path / "vault.json")
    reopened.unlock(MASTER)
    [loaded] = reopened.list_entries()
    assert loaded.id == entry.id
    assert loaded.title == "GitHub"
    assert loaded.password == "s3cret!" * 8
    assert loaded.notes == "me@example.com"


def test_file_contains_no_plaintext(vault):
    vault.add_entry("My Bank", "TopSecretPassword123", 300.0)
    raw = vault.path.read_text()
    assert "My Bank" not in raw
    assert "TopSecretPassword123" not in raw
    doc = json.loads(raw)
    assert doc["cipher"] == "aes-256-gcm"
    assert doc["kdf"]["name"] == "argon2id"


def test_wrong_password_is_rejected(vault):
    vault.lock()
    with pytest.raises(InvalidMasterPasswordError):
        vault.unlock("wrong password!!")


def test_tampering_is_detected(vault):
    vault.add_entry("x", "y" * 40, 300.0)
    vault.lock()
    doc = json.loads(vault.path.read_text())
    doc["kdf"]["time_cost"] = 2  # header is authenticated as associated data
    vault.path.write_text(json.dumps(doc))
    with pytest.raises(InvalidMasterPasswordError):
        vault.unlock(MASTER)


def test_nonce_changes_on_every_save(vault):
    nonces = set()
    for i in range(5):
        vault.add_entry(f"e{i}", "p" * 40, 300.0)
        nonces.add(json.loads(vault.path.read_text())["nonce"])
    assert len(nonces) == 5


def test_locked_vault_refuses_access(vault):
    vault.lock()
    with pytest.raises(VaultLockedError):
        vault.list_entries()


def test_update_and_delete(vault):
    entry = vault.add_entry("Old", "p" * 40, 300.0)
    vault.update_entry(entry.id, title="New")
    assert vault.get_entry(entry.id).title == "New"
    vault.delete_entry(entry.id)
    assert vault.list_entries() == []
    with pytest.raises(EntryNotFoundError):
        vault.delete_entry(entry.id)


def test_title_is_required(vault):
    with pytest.raises(VaultError):
        vault.add_entry("   ", "p" * 40, 300.0)


def test_short_master_password_rejected(tmp_path):
    with pytest.raises(VaultError):
        Vault(tmp_path / "v.json", kdf_params=FAST_KDF).create("short")


def test_cannot_overwrite_existing_vault(vault):
    with pytest.raises(VaultError):
        Vault(vault.path, kdf_params=FAST_KDF).create(MASTER)
