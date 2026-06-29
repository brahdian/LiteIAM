FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Upgrade pip first to clear installer CVEs (PYSEC-2026-196, CVE-2025-8869, etc.)
RUN pip install --no-cache-dir --upgrade "pip>=26.1.2" \
    && pip install --no-cache-dir -r requirements.txt \
    # Force-upgrade transitive deps past fastapi-users' stale hard-pins to clear CVEs
    # (pyjwt 2.10.1→2.13.0, python-multipart 0.0.21→0.0.31). API-compatible; see
    # requirements.txt note. Remove once fastapi-users relaxes its pins upstream.
    && pip install --no-cache-dir --upgrade "pyjwt[crypto]==2.13.0" "python-multipart==0.0.31"

COPY . .

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]