# PyInstaller specification for Planner Desktop Application

import os
import sys

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['D:/Projects/Activity_dashboard'],
    binaries=[],
    datas=[
        # Resources
        ('desktop/resources/fonts/*.ttf', 'fonts'),
        ('desktop/resources/themes/*.qss', 'themes'),
    ],
    hiddenimports=[
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'PySide6.QtNetwork',
        'keyring',
        'psutil',
        'jdatetime',
        'cryptography',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        'unittest',
        'doctest',
        'pdb',
        'json',
        'tkinter',
    ],
    win_no_prefer_redirects=True,
    win_private_excludes=None,
    cipher=block_cipher,
    noarchive=False,
)

p = PYZ(
    a.pure_data,
    a.binaries,
    a.zip_modules,
    cipher=block_cipher,
)

# --- PE Analysis ---

# --- PYZ Analysis ---

a = Analysis(
    p.a,
    pathex=['D:/Projects/Activity_dashboard'],
    binaries=[],
    datas=[
        ('desktop/resources/fonts/*.ttf', 'fonts'),
        ('desktop/resources/themes/*.qss', 'themes'),
    ],
    hiddenimports=[
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'PySide6.QtNetwork',
        'keyring',
        'psutil',
        'jdatetime',
        'cryptography',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        'unittest',
        'doctest',
        'pdb',
        'json',
        'tkinter',
    ],
    win_no_prefer_redirects=True,
    win_private_excludes=None,
    cipher=block_cipher,
    noarchive=False,
)

p = PYZ(
    a.pure_data,
    a.binaries,
    a.zip_modules,
    cipher=block_cipher,
)

# --- Executable ---

exe = EXE(
    p,
    a.script,
    a.manifest,
    base='Win32GUI',  # Use Win32GUI for GUI apps (no console window)
    target_name='PlannerDesktop.exe',
    icon=None,
    distribution_name='Planner',
    command_filename='Planner',
    support_path='',
    uac_admin=False,
    uac_ui_access=False,
    bootloader_signing_id='',
    blind_skip_signature=True,
    code_signing_signature='',
    asking='asking' not in sys.argv,
    uac_admin_ui_access=False,
    multi_script=None,
    name='PlannerDesktop',
    for_win32=True,
    debug=False,
    noarchive=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    upx_mix_binaries=1.0,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    copyright='',
    with_console_in_front=False,
    raw_script_text=None,
    show_boot_loader=False,
    edition='',
)


# --- Other scripts ---

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.tarfile,
    here='d:_MEIPASS',
    optimize=2,
    upx_info=a,
    name='PlannerDesktop',
)


# --- Archives ---

lib = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.tarfile,
    here='d:_MEIPASS',
    optimize=2,
    upx_info=a,
    name='PlannerDesktop',
)


# --- msvcr ---

msvc = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.tarfile,
    here='d:_MEIPASS',
    optimize=2,
    upx_info=a,
    name='PlannerDesktop',
)