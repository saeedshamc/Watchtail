# Installing and packaging Watchtail

This guide covers every supported way to get Watchtail running: direct
execution on Windows (portable or installer), AppImage and deb packages
on Linux, plus building from source anywhere.

## Which package for which platform

| Platform | Artifact | Best for |
| --- | --- | --- |
| Windows | `watchtail-portable-win64.zip` | Run without installing; USB sticks |
| Windows | `watchtail-setup-<version>.exe` | Normal installed use, Start-menu shortcuts, uninstaller |
| Linux | `watchtail-<version>-x86_64.AppImage` | Run anywhere without installation |
| Linux | `watchtail_<version>_amd64.deb` | Debian/Ubuntu servers, systemd service |
| Any | from source | Development, customising, other distros |

All packaged builds ship a bundled Python runtime — there is nothing to
pip install on the target machine.

---

## Windows

### Option A — portable ZIP (direct execution)

1. Download `watchtail-portable-win64.zip` and extract it anywhere,
   e.g. `C:\Watchtail`.
2. Double-click `watchtail.exe`. A console window opens showing the
   server log; the dashboard is at `http://127.0.0.1:5555`.
3. First run creates `watchtail.yml` (next to the exe or, if that
   folder is read-only, under `%LOCALAPPDATA%\Watchtail`), the SQLite
   database under `data\`, and prints a generated admin password once.
   Set `WATCHTAIL_ADMIN_PASSWORD` instead if you want to choose it.

To start Watchtail automatically at login, create a shortcut to
`watchtail.exe` in the Startup folder (`Win+R` → `shell:startup`).

### Option B — installer

1. Download `watchtail-setup-<version>.exe`.
2. Run it and follow the wizard. Per-user install is the default, so
   no admin rights are required; you can switch to per-machine in the
   installer dialog.
3. Launch from the Start menu. Uninstalling removes the program files;
   your `data\` folder (database, generated password) is deleted with
   it unless you saved a copy beforehand.

The installer is built from `scripts\watchtail.iss` with
[Inno Setup 6](https://jrsoftware.org/isinfo.php).

---

## Linux

### Option A — AppImage

```bash
chmod +x watchtail-<version>-x86_64.AppImage
./watchtail-<version>-x86_64.AppImage --port 5555
```

Config and database are created in `data/` next to the AppImage (or
`~/.local/share/Watchtail` when read-only). The AppImage targets
x86_64 glibc 2.31+, which covers Ubuntu 20.04+, Debian 11+, and most
current distributions. No FUSE? Run it with `--appimage-extract-and-run`.

### Option B — deb package

```bash
sudo apt install ./watchtail_<version>_amd64.deb
```

The package installs `/usr/lib/watchtail`, a `watchtail` command on
`PATH`, and a `watchtail.service` systemd unit running as the
`watchtail` system user with its data in `/var/lib/watchtail`:

```bash
sudo systemctl enable --now watchtail
sudo systemctl status watchtail
```

Edit the service settings (host, port, thresholds) either in
`/etc/systemd/system/watchtail.service.d/override.conf` or by placing a
`watchtail.yml` in `/var/lib/watchtail` — the config there wins once
present. Removing the package (`sudo apt remove watchtail`) stops the
service but keeps `/var/lib/watchtail`.

### Other distributions

Use the AppImage, or run from source (below).

---

## From source (all platforms)

```bash
git clone <repository-url> watchtail
cd watchtail

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
python scripts/fetch_vendor.py     # one-time: Chart.js / socket.io client

cp config/watchtail.example.yml watchtail.yml   # Windows: copy instead
export WATCHTAIL_ADMIN_PASSWORD='choose-a-password'
python run.py
```

Windows equivalent of the export line:
`set WATCHTAIL_ADMIN_PASSWORD=choose-a-password` (cmd) or
`$env:WATCHTAIL_ADMIN_PASSWORD="choose-a-password"` (PowerShell).

---

## Building the packages yourself

One-time: create a venv, install `requirements.txt` **and**
`pip install pyinstaller`.

### Windows

```bat
scripts\build_exe.bat
```

produces `dist\watchtail-portable-win64.zip`. For the installer,
compile `scripts\watchtail.iss` with Inno Setup's `ISCC.exe`; the
result lands in `dist\output\watchtail-setup-<version>.exe`.

### Linux

```bash
scripts/build_all.sh            # AppImage + deb
scripts/build_all.sh appimage   # only the AppImage
scripts/build_all.sh deb        # only the deb
```

The AppImage step downloads `linuxdeploy` on first use. Building the
deb requires `dpkg-deb` (present on any Debian-family host).

### CI

`.github/workflows` (template in `scripts/ci.yml`) builds the Windows
zip + installer and the Linux AppImage + deb on every `v*` tag and
uploads them as artifacts; attach them to the GitHub release.

---

## Configuration and secrets

All builds read the same settings, in the same way:

- `watchtail.yml` next to the executable (or under the data directory)
  — log sources, thresholds, webhook. See
  [config/watchtail.example.yml](../config/watchtail.example.yml).
- `WATCHTAIL_ADMIN_PASSWORD` — dashboard password; generated and
  printed once when unset.
- `WATCHTAIL_SECRET_KEY` — session key; generated and stored in the
  data directory when unset.
- `WATCHTAIL_DATABASE_URL` — overrides `database.url`; the packaged
  builds default to a SQLite file inside their data directory.

## Troubleshooting

- **Port already in use** — start with `--port 5556`.
- **"Permission denied" on a log file** — run Watchtail as a user that
  can read the logs; on Linux the deb package's `watchtail` user can be
  added to the group owning the logs
  (`sudo usermod -aG adm watchtail`).
- **Dashboard unreachable** — check the console/log for binding
  errors; the default bind is `127.0.0.1`, use `--host 0.0.0.0` to
  expose it on the network (behind a reverse proxy with TLS).
