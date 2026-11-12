# SecretBroker Server: build from this folder (docker compose does it for you).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SB_DATA_DIR=/data

# An unprivileged account owns the data: the database, the server secret and the backups are readable by it alone
# (folders 700; the server also creates its files 600).
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin secretbroker \
    && mkdir -p /data /backups && chown secretbroker:secretbroker /data /backups && chmod 700 /data /backups

WORKDIR /app
COPY pyproject.toml ./
COPY secretbroker_server ./secretbroker_server
RUN pip install --no-cache-dir . && rm -rf /root/.cache

USER secretbroker
VOLUME /data
EXPOSE 8080

# /api/v1/health answers 200 only while the database does; it reveals nothing else.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=4)" || exit 1

CMD ["secretbroker-server", "serve", "--host", "0.0.0.0", "--port", "8080"]
