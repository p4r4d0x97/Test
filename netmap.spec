# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for NetMap.
#
# Build with:
#     python -m PyInstaller netmap.spec
#
# What this bundles:
#   • launcher.py           — startup entry point (opens browser + starts server)
#   • server.py             — HTTP/HTTPS API + file server
#   • inventory.py          — network scanner (replaces old xmlbuilder.py)
#   • www/index.html        — full frontend
#
# What lives NEXT TO the .exe at runtime (not bundled):
#   • netmap.crt / netmap.key   — auto-generated on first launch
#   • site_config.json          — per-plant config (users create via ⚙ Settings)
#   • Whatever XML the user passes as argv[1]
#   • layout.json, presence.json, live_status.json, etc. — created next to XML

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# All third-party deps that inventory.py + server.py need
hiddenimports = [
    'paramiko', 'cryptography',
    'requests', 'urllib3',
] + collect_submodules('cryptography')

# inventory.py is imported dynamically by server.py, so it must be discoverable.
datas = [
    ('www/index.html', 'www'),
    ('inventory.py',   '.'),          # module lives next to the .exe entry
]

a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports + ['inventory', 'server'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'matplotlib', 'PIL', 'PyQt5', 'PyQt6',
        'lxml',                       # replaced with stdlib xml.etree
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='NetMap',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
