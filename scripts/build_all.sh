#!/usr/bin/env bash
# Build every distributable for the current platform.
#
#   Windows:  scripts/build_all.sh            -> portable zip (installer via
#                                                scripts/watchtail.iss + Inno Setup)
#   Linux:    scripts/build_all.sh appimage   -> dist/watchtail-<version>-x86_64.AppImage
#             scripts/build_all.sh deb        -> dist/watchtail_<version>_amd64.deb
#             scripts/build_all.sh            -> both
#
# Requirements: python3, pip, PyInstaller (pip install pyinstaller).
# AppImage additionally needs a linuxdeploy x86_64 binary in PATH or
# downloaded on the fly; deb needs nothing beyond coreutils.
#
# Output lands in dist/ next to the repository root.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
DIST="$ROOT/dist"
BUILD="$ROOT/build"

VERSION="$("$PY" -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])" 2>/dev/null \
  || "$PY" -c "import re; print(re.search(r'version = \"([^\"]+)\"', open('pyproject.toml').read()).group(1))")"
echo "==> Watchtail $VERSION"

mkdir -p "$DIST"

build_bundle() {
    echo "==> PyInstaller bundle"
    "$PY" -m pip install --quiet pyinstaller
    "$PY" -m PyInstaller watchtail.spec --noconfirm --distpath "$BUILD/dist" --workpath "$BUILD/work"
}

# ---------------------------------------------------------------------------
# Windows portable zip
# ---------------------------------------------------------------------------
build_windows_zip() {
    echo "==> Portable zip"
    "$PY" - <<PYEOF
import shutil, zipfile
from pathlib import Path

src = Path(r"$BUILD/dist/watchtail")
zip_path = Path(r"$DIST/watchtail-$VERSION-portable-win64.zip")
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for file in sorted(src.rglob("*")):
        zf.write(file, file.relative_to(src.parent))
print("wrote", zip_path)
PYEOF
}

# ---------------------------------------------------------------------------
# Linux AppImage (via linuxdeploy)
# ---------------------------------------------------------------------------
build_appimage() {
    echo "==> AppImage"
    local appdir="$BUILD/appimage/Watchtail.AppDir"
    rm -rf "$BUILD/appimage"
    mkdir -p "$appdir/usr/bin" "$appdir/usr/share/icons/hicolor/256x256/apps"

    # Reuse the PyInstaller bundle; AppImage only wraps it.
    cp -r "$BUILD/dist/watchtail/." "$appdir/usr/bin/"

    cat > "$appdir/watchtail.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Watchtail
Comment=Self-hosted log monitoring and threat detection
Exec=watchtail
Icon=watchtail
Categories=Network;System;Monitor;
Terminal=true
EOF

    if [ -f scripts/watchtail-icon.png ]; then
        cp scripts/watchtail-icon.png "$appdir/usr/share/icons/hicolor/256x256/apps/watchtail.png"
    fi

    local linuxdeploy="linuxdeploy-x86_64.AppImage"
    if [ ! -f "$ROOT/$linuxdeploy" ]; then
        echo "==> Downloading linuxdeploy"
        curl -L -o "$ROOT/$linuxdeploy" \
            https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
        chmod +x "$ROOT/$linuxdeploy"
    fi

    # linuxdeploy bakes the AppDir into the final AppImage; we skip its
    # plugin deployment because the bundle already contains everything.
    OUTPUT="$DIST/watchtail-$VERSION-x86_64.AppImage" \
        "$ROOT/$linuxdeploy" --appdir "$appdir" --output appimage
    chmod +x "$DIST/watchtail-$VERSION-x86_64.AppImage"
    echo "==> wrote $DIST/watchtail-$VERSION-x86_64.AppImage"
}

# ---------------------------------------------------------------------------
# Debian package (.deb)
# ---------------------------------------------------------------------------
build_deb() {
    echo "==> deb"
    local pkgroot="$BUILD/deb/watchtail-$VERSION"
    rm -rf "$BUILD/deb"
    local destdir="$pkgroot/usr/lib/watchtail"
    mkdir -p "$destdir" "$pkgroot/usr/bin" "$pkgroot/DEBIAN"

    cp -r "$BUILD/dist/watchtail/." "$destdir/"
    ln -sf /usr/lib/watchtail/watchtail "$pkgroot/usr/bin/watchtail"

    mkdir -p "$pkgroot/usr/share/doc/watchtail"
    cp README.md "$pkgroot/usr/share/doc/watchtail/"
    cp LICENSE "$pkgroot/usr/share/doc/watchtail/"

    cat > "$pkgroot/DEBIAN/control" <<EOF
Package: watchtail
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Maintainer: Watchtail maintainers <noreply@localhost>
Depends: libc6
Description: Lightweight self-hosted log monitoring and threat detection
 Watchtail tails server log files (nginx, Apache, auth.log), detects
 brute force and scanning patterns and shows everything on a live web
 dashboard.
Homepage: https://example.invalid/watchtail
EOF

    cat > "$pkgroot/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# Nothing to configure on install; /var/lib/watchtail is created on
# first run by the service user.
if [ "$1" = "configure" ]; then
    getent group watchtail >/dev/null || groupadd --system watchtail
    getent passwd watchtail >/dev/null || useradd --system --gid watchtail \
        --home-dir /var/lib/watchtail --create-home --shell /usr/sbin/nologin watchtail
fi
EOF

    cat > "$pkgroot/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] && [ -x /bin/systemctl ]; then
    systemctl stop watchtail.service >/dev/null 2>&1 || true
fi
EOF

    chmod 755 "$pkgroot/DEBIAN/postinst" "$pkgroot/DEBIAN/prerm"

    # Service unit so `systemctl enable --now watchtail` works out of the box.
    local servicedir="$pkgroot/lib/systemd/system"
    mkdir -p "$servicedir"
    cat > "$servicedir/watchtail.service" <<EOF
[Unit]
Description=Watchtail log monitor
After=network.target

[Service]
Type=simple
User=watchtail
Group=watchtail
WorkingDirectory=/var/lib/watchtail
Environment=WATCHTAIL_DATA_DIR=/var/lib/watchtail
ExecStart=/usr/lib/watchtail/watchtail --host 127.0.0.1 --port 5555
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    dpkg-deb --root-owner-group --build "$pkgroot" \
        "$DIST/watchtail_${VERSION}_amd64.deb"
    echo "==> wrote $DIST/watchtail_${VERSION}_amd64.deb"
}

case "${1:-all}" in
    zip)      build_bundle; build_windows_zip ;;
    appimage) build_appimage ;;
    deb)      build_bundle; build_deb ;;
    all)
        build_bundle
        if [[ "${OS:-}" == "Windows_NT" ]]; then
            build_windows_zip
        else
            build_appimage
            build_deb
        fi
        ;;
    *) echo "usage: $0 [zip|appimage|deb|all]" >&2; exit 2 ;;
esac
