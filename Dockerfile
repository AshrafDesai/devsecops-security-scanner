FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS final

WORKDIR /app

COPY scanner/ ./scanner/
COPY scripts/  ./scripts/

RUN mkdir -p reports /home/scanner /tmp/zap_work \
    && addgroup --system scanner \
    && adduser --system --ingroup scanner --home /home/scanner scanner \
    && chown -R scanner:scanner /app /home/scanner /tmp/zap_work

ENV HOME=/home/scanner \
    REPORT_DIR=reports

USER scanner

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python scanner/main.py --target https://example.com --out-dir /tmp/healthcheck || exit 1

ENTRYPOINT ["python", "scanner/main.py"]
CMD ["--help"]