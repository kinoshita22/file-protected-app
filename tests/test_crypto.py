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
    assert not (tmp_path / "out.part").exists()


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
