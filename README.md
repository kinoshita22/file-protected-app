# File Protect App

A PyQt5 desktop app that encrypts and decrypts files with a password.

## Features

- Pick several files at once (add, remove, clear)
- Choose a mode: **Encrypt** or **Decrypt**
- Encryption depth from 1 (Fast) to 5 (Maximum). Higher levels make password guessing slower.
- Password entry with confirmation, a "show password" toggle and live checks (encryption needs at least 8 characters)
- Can delete the original files after a successful run
- Work runs on a background thread with a progress bar and a log for each file

## Install and run

```bash
pip install -r requirements.txt
python main.py
```

## Build a Windows executable

PyInstaller only builds for the system it runs on, so build on Windows. There are two ways.

**On a Windows PC** (needs Python 3.9 or newer from python.org, with the `py` launcher):

```bat
build_windows.bat
```

This creates a `.venv`, installs the dependencies and writes `dist\FileProtect.exe`. That single file runs without Python installed.

**With GitHub Actions:** the workflow in `.github/workflows/build-windows.yml` runs on pushes to `main`, on pull requests, on `v*` tags and when started by hand. It runs the tests, builds the `.exe` on a Windows runner and attaches it to the run as the `FileProtect-windows` artifact.

The build settings are in `FileProtect.spec`.

## How it works

- Encryption uses **AES-256-GCM** and processes the file in 1 MiB chunks, so large files never have to fit in memory.
- The key comes from the password via **scrypt**. The depth level sets scrypt's cost, from 16 MiB to 256 MiB of memory per file.
- The depth, a random salt and a nonce prefix go in the file header, so you don't need to pick the depth again to decrypt.
- Each chunk is authenticated together with the header, its position and a "last chunk" flag. A wrong password, a damaged file, or chunks that were reordered, cut off or added are all detected, and no partial output is left behind.
- Encrypted files get the `.fpa` extension. Decrypting removes it. If the output name already exists, the app adds ` (1)`, ` (2)` and so on instead of overwriting.

## Tests

```bash
python -m pytest tests
```
