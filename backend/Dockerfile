# SecurCode API and scan worker (same image, different command).
#   API:    uvicorn app.main:app --host 0.0.0.0 --port 8000
#   Worker: python -m app.v1.worker
FROM python:3.12-slim AS base

# Apply OS security updates and current pip/setuptools before anything else.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip install --no-cache-dir --upgrade pip setuptools wheel

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 securcode \
 && useradd --system --uid 10001 --gid securcode --home-dir /app --shell /usr/sbin/nologin securcode

WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
# Install runtime dependencies, then drop the build-only packaging tools
# (setuptools, wheel and pip itself, whose vendored pkg_resources pins
# setuptools 70.3.0 / CVE-2025-47273) so none of them ship in the runtime image.
RUN pip install -r requirements.txt \
 && python -m pip uninstall -y setuptools wheel \
 && find / -xdev -depth \( -name 'setuptools' -o -name 'setuptools-*' -o -name '_distutils_hack' \
      -o -name 'distutils-precedence.pth' -o -name 'wheel-*.dist-info' \) -print -exec rm -rf {} + \
 && python -c "import fastapi, sqlalchemy, alembic, argon2, cryptography, psycopg, uvicorn" \
 && python -m pip uninstall -y pip

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
