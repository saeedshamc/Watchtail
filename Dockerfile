FROM python:3.13-slim

# tini forwards signals and reaps the tailer threads' leftovers so
# SQLite WAL files shut down cleanly on container stop. gunicorn with
# the eventlet worker is the production WSGI story for Socket.IO
# (threading mode + werkzeug is a dev convenience, see run.py).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/watchtail

COPY pyproject.toml README.md ./
COPY app ./app
COPY run.py wsgi.py entrypoint.sh ./

# Checkouts on Windows can carry CRLF into the entrypoint script.
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh \
    && pip install --no-cache-dir -e . \
    && pip install --no-cache-dir gunicorn "eventlet>=0.35"

# Non-root runtime; /data holds config, database and session key on a
# volume so state survives container replacement.
RUN useradd --system --create-home --uid 1000 watchtail \
    && mkdir -p /data /srv/watchtail/data \
    && chown -R watchtail:watchtail /srv/watchtail /data
USER watchtail

ENV WATCHTAIL_DATA_DIR=/data \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 5555

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('WATCHTAIL_PORT','5555') + '/health').read()"

ENTRYPOINT ["/usr/bin/tini", "--", "/srv/watchtail/entrypoint.sh"]
