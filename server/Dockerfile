# SecretBroker Server. Built from the repository root (docker compose does it for you, from server/):
#   docker build -f server/Dockerfile -t secretbroker-server .
# Every package comes from the hash-pinned locks in requirements/ (tools/update_locks.py): the exact versions and
# files reviewed, nothing resolved from PyPI by name, the build backend included.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SB_DATA_DIR=/data \
    SB_INSTALL=docker

# An unprivileged account owns the data: the database, the server secret and the backups are readable by it alone
# (folders 700; the server also creates its files 600).
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin secretbroker \
    && mkdir -p /data /backups && chown secretbroker:secretbroker /data /backups && chmod 700 /data /backups

WORKDIR /app
COPY requirements/build.txt requirements/server.txt ./requirements/
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps --only-binary :all: \
        -r requirements/build.txt -r requirements/server.txt
COPY server/pyproject.toml ./
COPY server/secretbroker_server ./secretbroker_server
RUN pip install --no-cache-dir --disable-pip-version-check --no-deps --no-build-isolation --no-index . \
    && pip check \
    && pip uninstall --quiet --disable-pip-version-check -y setuptools \
    && rm -rf /root/.cache

USER secretbroker
VOLUME /data
EXPOSE 8080

# /api/v1/health answers 200 only while the database does; it reveals nothing else.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=4)" || exit 1

CMD ["secretbroker-server", "serve", "--host", "0.0.0.0", "--port", "8080"]
