# PyInstaller build spec. Build with:  pyinstaller --clean --noconfirm FileProtect.spec
# Produces a single-file, windowed executable in dist/ (FileProtect.exe on Windows).

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    # Only PyQt5 is used; keep other Qt bindings out if they happen to be installed.
    excludes=["PyQt6", "PySide2", "PySide6", "tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="FileProtect",
    debug=False,
    strip=False,
    upx=False,
    console=False,
)
