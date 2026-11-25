# SecurCode API and scan worker (same image, different command).
#   API:    uvicorn app.main:app --host 0.0.0.0 --port 8000
#   Worker: python -m app.v1.worker
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 securcode \
 && useradd --system --uid 10001 --gid securcode --home-dir /app --shell /usr/sbin/nologin securcode

WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

COPY --chown=securcode:securcode backend/ ./
COPY --chown=securcode:securcode scanner-fixtures/ /scanner-fixtures/

# Scan workspaces live on a tmpfs/ephemeral path owned by the unprivileged user.
RUN mkdir -p /tmp/securcode-scans && chown securcode:securcode /tmp/securcode-scans
ENV SECURCODE_SCAN_WORKDIR=/tmp/securcode-scans \
    SECURCODE_LEGACY_API=false

USER securcode
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live', timeout=4).status == 200 else 1)"

CMD ["sh", "scripts/start.sh"]
