import os
from pathlib import Path

import pytest

from file_protect import crypto


@pytest.fixture(autouse=True)
def small_chunks(monkeypatch):
    # Small chunks exercise the multi-chunk path without large test files.
    monkeypatch.setattr(crypto, "CHUNK_SIZE", 1024)


@pytest.mark.parametrize("size", [0, 1, 1024, 1025, 5000])
def test_roundtrip(tmp_path: Path, size: int):
    data = os.urandom(size)
    src = tmp_path / "doc.bin"
    src.write_bytes(data)

    enc = crypto.encrypted_output_path(src)
    crypto.encrypt_file(src, enc, "correct horse", depth=1)
    assert enc.name == "doc.bin.fpa"
    assert crypto.read_depth(enc) == 1

    dec = crypto.decrypted_output_path(enc)
    assert dec.name == "doc (1).bin"  # original still exists
    crypto.decrypt_file(enc, dec, "correct horse")
    assert dec.read_bytes() == data


def test_wrong_password(tmp_path: Path):
    src = tmp_path / "a.txt"
    src.write_bytes(b"secret")
    enc = tmp_path / "a.txt.fpa"
    crypto.encrypt_file(src, enc, "password1", depth=1)
    out = tmp_path / "out"
    with pytest.raises(crypto.DecryptionError, match="Wrong password"):
        crypto.decrypt_file(enc, out, "password2")
    assert not out.exists()
    assert not list(tmp_path.glob("*.part"))


def test_existing_part_file_untouched(tmp_path: Path):
    src = tmp_path / "a.txt"
    src.write_bytes(b"secret")
    enc = tmp_path / "a.txt.fpa"
    crypto.encrypt_file(src, enc, "password1", depth=1)
    # A user file named like the old fixed temp path must survive a failed run.
    bystander = tmp_path / "out.part"
    bystander.write_bytes(b"user data")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_file(enc, tmp_path / "out", "wrong")
    assert bystander.read_bytes() == b"user data"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.txt", "a.txt.fpa", "out.part"]


@pytest.mark.parametrize("op", ["encrypt", "decrypt"])
def test_abort_from_progress_leaves_no_output(tmp_path: Path, op: str):
    src = tmp_path / "a.bin"
    src.write_bytes(os.urandom(3000))
    enc = tmp_path / "a.bin.fpa"
    crypto.encrypt_file(src, enc, "password1", depth=1)

    def abort(done, total):
        raise KeyboardInterrupt

    out = tmp_path / "out"
    with pytest.raises(KeyboardInterrupt):
        if op == "encrypt":
            crypto.encrypt_file(src, out, "password1", depth=1, progress=abort)
        else:
            crypto.decrypt_file(enc, out, "password1", progress=abort)
    assert not out.exists()
    assert not list(tmp_path.glob("*.part"))


def test_decrypt_accepts_chunks_larger_than_current_chunk_size(tmp_path: Path, monkeypatch):
    src = tmp_path / "a.bin"
    data = os.urandom(5000)
    src.write_bytes(data)
    enc = tmp_path / "a.bin.fpa"
    monkeypatch.setattr(crypto, "CHUNK_SIZE", 4096)
    crypto.encrypt_file(src, enc, "password1", depth=1)
    monkeypatch.setattr(crypto, "CHUNK_SIZE", 1024)
    out = tmp_path / "out"
    crypto.decrypt_file(enc, out, "password1")
    assert out.read_bytes() == data


@pytest.mark.parametrize("mutation", ["truncate_chunk", "append", "flip", "depth"])
def test_tampering_detected(tmp_path: Path, mutation: str):
    src = tmp_path / "a.bin"
    src.write_bytes(os.urandom(3000))
    enc = tmp_path / "a.bin.fpa"
    crypto.encrypt_file(src, enc, "password1", depth=1)
    blob = bytearray(enc.read_bytes())

    if mutation == "truncate_chunk":
        # Drop the last chunk entirely (4-byte length + 3000 - 2048 + 16 tag).
        blob = blob[: -(4 + 952 + 16)]
    elif mutation == "append":
        blob += blob[crypto.HEADER_SIZE : crypto.HEADER_SIZE + 4 + 1024 + 16]
    elif mutation == "flip":
        blob[-1] ^= 1
    elif mutation == "depth":
        blob[len(crypto.MAGIC)] = 2
    enc.write_bytes(bytes(blob))

    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_file(enc, tmp_path / "out", "password1")


def test_not_encrypted_file(tmp_path: Path):
    src = tmp_path / "plain.txt"
    src.write_bytes(b"hello world, this is not encrypted at all")
    with pytest.raises(crypto.DecryptionError, match="Not a File Protect"):
        crypto.decrypt_file(src, tmp_path / "out", "whatever")
