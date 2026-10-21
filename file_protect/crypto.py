"""Password-based file encryption.

File format (all integers big-endian):

    magic      4 bytes   b"FPA1"
    depth      1 byte    encryption depth level (1-5), selects scrypt cost
    salt      16 bytes   scrypt salt
    nonce_pfx  8 bytes   random prefix for per-chunk nonces
    chunks...            each: 4-byte ciphertext length + AES-256-GCM ciphertext/tag

Each chunk uses nonce = nonce_pfx || chunk_index (4 bytes) and authenticates
the header plus a "final" flag, so reordering, truncation or appending chunks
is detected during decryption.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"FPA1"
EXTENSION = ".fpa"
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 8
CHUNK_SIZE = 1024 * 1024
# Largest chunk the FPA1 format allows. Fixed, so files stay readable if CHUNK_SIZE changes.
MAX_CHUNK_SIZE = 1024 * 1024
TAG_SIZE = 16
HEADER_SIZE = len(MAGIC) + 1 + SALT_SIZE + NONCE_PREFIX_SIZE

# depth level -> (label, scrypt log2(N)); memory use is 128 * r * N bytes (r = 8).
DEPTH_LEVELS = {
    1: ("Fast", 14),        # 16 MiB
    2: ("Standard", 15),    # 32 MiB
    3: ("Strong", 16),      # 64 MiB
    4: ("Very strong", 17), # 128 MiB
    5: ("Maximum", 18),     # 256 MiB
}
DEFAULT_DEPTH = 2

ProgressCallback = Callable[[int, int], None]


class DecryptionError(Exception):
    """Raised when a file cannot be decrypted (wrong password or corrupt data)."""


def derive_key(password: str, salt: bytes, depth: int) -> bytes:
    if depth not in DEPTH_LEVELS:
        raise ValueError(f"Unsupported encryption depth: {depth}")
    log_n = DEPTH_LEVELS[depth][1]
    kdf = Scrypt(salt=salt, length=32, n=2**log_n, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def _aad(header: bytes, final: bool) -> bytes:
    return header + (b"\x01" if final else b"\x00")


def _nonce(prefix: bytes, index: int) -> bytes:
    if index >= 2**32:
        raise ValueError("File too large")
    return prefix + struct.pack(">I", index)


def _open_temp(dst: Path):
    """Create a new, uniquely named temp file next to `dst`. Returns (file, path)."""
    fd, name = tempfile.mkstemp(prefix=dst.name + ".", suffix=".part", dir=dst.parent)
    return os.fdopen(fd, "wb"), Path(name)


def unique_path(path: Path) -> Path:
    """Return `path`, or a variant with " (n)" appended if it already exists."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    n = 1
    while True:
        candidate = path.with_name(f"{stem} ({n}){suffix}")
        if not candidate.exists():
            return candidate
        n += 1


def encrypted_output_path(src: Path) -> Path:
    return unique_path(src.with_name(src.name + EXTENSION))


def decrypted_output_path(src: Path) -> Path:
    if src.suffix.lower() == EXTENSION:
        return unique_path(src.with_suffix(""))
    return unique_path(src.with_name(src.name + ".decrypted"))


def encrypt_file(
    src: Path,
    dst: Path,
    password: str,
    depth: int = DEFAULT_DEPTH,
    progress: Optional[ProgressCallback] = None,
) -> None:
    if CHUNK_SIZE > MAX_CHUNK_SIZE:
        raise ValueError("CHUNK_SIZE exceeds the format's maximum chunk size")
    salt = os.urandom(SALT_SIZE)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    header = MAGIC + bytes([depth]) + salt + nonce_prefix
    aesgcm = AESGCM(derive_key(password, salt, depth))

    total = src.stat().st_size
    done = 0
    fout, tmp = _open_temp(dst)
    try:
        with open(src, "rb") as fin, fout:
            fout.write(header)
            index = 0
            chunk = fin.read(CHUNK_SIZE)
            while True:
                next_chunk = fin.read(CHUNK_SIZE)
                final = not next_chunk
                ct = aesgcm.encrypt(_nonce(nonce_prefix, index), chunk, _aad(header, final))
                fout.write(struct.pack(">I", len(ct)))
                fout.write(ct)
                done += len(chunk)
                if progress:
                    progress(done, total)
                if final:
                    break
                chunk = next_chunk
                index += 1
        os.replace(tmp, dst)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def read_depth(src: Path) -> int:
    with open(src, "rb") as f:
        header = f.read(HEADER_SIZE)
    if len(header) < HEADER_SIZE or not header.startswith(MAGIC):
        raise DecryptionError("Not a File Protect encrypted file")
    return header[len(MAGIC)]


def decrypt_file(
    src: Path,
    dst: Path,
    password: str,
    progress: Optional[ProgressCallback] = None,
) -> None:
    total = src.stat().st_size
    tmp: Optional[Path] = None
    try:
        with open(src, "rb") as fin:
            header = fin.read(HEADER_SIZE)
            if len(header) < HEADER_SIZE or not header.startswith(MAGIC):
                raise DecryptionError("Not a File Protect encrypted file")
            depth = header[len(MAGIC)]
            if depth not in DEPTH_LEVELS:
                raise DecryptionError(f"Unsupported encryption depth: {depth}")
            salt = header[len(MAGIC) + 1 : len(MAGIC) + 1 + SALT_SIZE]
            nonce_prefix = header[-NONCE_PREFIX_SIZE:]
            aesgcm = AESGCM(derive_key(password, salt, depth))

            fout, tmp = _open_temp(dst)
            with fout:
                index = 0
                done = HEADER_SIZE
                while True:
                    length_bytes = fin.read(4)
                    if len(length_bytes) != 4:
                        raise DecryptionError("File is truncated or corrupt")
                    (length,) = struct.unpack(">I", length_bytes)
                    if length > MAX_CHUNK_SIZE + TAG_SIZE:
                        raise DecryptionError("File is corrupt")
                    ct = fin.read(length)
                    if len(ct) != length:
                        raise DecryptionError("File is truncated or corrupt")
                    done += 4 + length
                    final = done == total
                    try:
                        pt = aesgcm.decrypt(_nonce(nonce_prefix, index), ct, _aad(header, final))
                    except InvalidTag:
                        if index == 0:
                            raise DecryptionError("Wrong password or corrupt file") from None
                        raise DecryptionError("File is corrupt or has been tampered with") from None
                    fout.write(pt)
                    if progress:
                        progress(done, total)
                    if final:
                        break
                    index += 1
        os.replace(tmp, dst)
    except BaseException:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
        raise
