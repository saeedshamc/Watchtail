# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Watchtail.

Builds a one-directory bundle (fast startup, easy to inspect):
    pyinstaller watchtail.spec
"""

import os
from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

datas = [
    ("app/templates", "app/templates"),
    ("app/static", "app/static"),
    ("config/watchtail.example.yml", "config"),
]
datas += collect_data_files("jinja2", include_py_files=False)

hiddenimports = [
    "engineio.async_drivers.threading",
]

a = Analysis(
    ["frozen_main.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest"],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="watchtail",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="watchtail",
)
