@echo off
REM Windows helper: build the PyInstaller bundle and portable zip.
REM Usage: scripts\build_exe.bat

setlocal
cd /d "%~dp0.."

if not exist .venv\Scripts\python.exe (
    echo No .venv found. Create one and install requirements.txt first.
    exit /b 1
)

.venv\Scripts\python.exe -m pip install --quiet pyinstaller || goto :error
.venv\Scripts\python.exe -m PyInstaller watchtail.spec --noconfirm --distpath build\dist --workpath build\work || goto :error

.venv\Scripts\python.exe - <<PYEOF
import zipfile
from pathlib import Path

src = Path("build/dist/watchtail")
out = Path("dist")
out.mkdir(exist_ok=True)
zip_path = out / "watchtail-portable-win64.zip"
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for file in sorted(src.rglob("*")):
        zf.write(file, file.relative_to(src.parent))
print("wrote", zip_path)
PYEOF

echo Done. Installer: compile scripts\watchtail.iss with Inno Setup (ISCC.exe).
exit /b 0

:error
echo Build failed.
exit /b 1
