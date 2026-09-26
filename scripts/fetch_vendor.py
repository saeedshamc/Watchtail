"""Download front-end vendor libraries into app/static/vendor.

The repo does not carry minified third-party bundles; run this once
after cloning. The dashboard falls back to a CDN if a file is missing.

Usage: python scripts/fetch_vendor.py
"""

import os
import sys
import urllib.request

FILES = {
    "chart.umd.min.js": "https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js",
    "socket.io.min.js": "https://cdn.socket.io/4.8.1/socket.io.min.js",
}

DEST = os.path.join(os.path.dirname(__file__), "..", "app", "static", "vendor")


def main() -> int:
    os.makedirs(DEST, exist_ok=True)
    failures = 0
    for name, url in FILES.items():
        target = os.path.join(DEST, name)
        if os.path.exists(target) and os.path.getsize(target) > 0:
            print(f"already present: {name}")
            continue
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read()
            with open(target, "wb") as fh:
                fh.write(data)
            print(f"fetched {name} ({len(data)} bytes)")
        except OSError as error:
            failures += 1
            print(f"could not fetch {name}: {error}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
