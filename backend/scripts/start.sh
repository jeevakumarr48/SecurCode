#!/bin/sh
# Container entry point for the API.
# SECURCODE_EMBEDDED_WORKER=true also starts the scan worker as a *separate
# process* in the same container. This is the low-cost mode for hosts whose
# free tier has no background-worker service. Scans still run in their own
# resource-limited subprocess; the trade-off is shared CPU/memory with the API.
set -eu
python -m app.v1.cli migrate
if [ "${SECURCODE_EMBEDDED_WORKER:-false}" = "true" ]; then
  python -m app.v1.worker --concurrency "${SECURCODE_WORKER_CONCURRENCY:-1}" &
fi
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers --forwarded-allow-ips='*'
