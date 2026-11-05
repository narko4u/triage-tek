# Demo container for TriageTek.
# The ledger is deterministic (seed 20261120), so no volume is required:
# the process seals its own cycle at boot and the record resets on restart.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="TriageTek demo" \
      org.opencontainers.image.description="Consent-bound screening triage with a sealed, tamper-evident record" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/narko4u/triage-tek"

WORKDIR /app

COPY server.py LICENSE README.md ./
COPY sel ./sel
COPY web ./web

RUN useradd --system --uid 10001 app \
    && mkdir -p /data \
    && chown -R app:app /app /data

USER app

ENV SEL_DATA=/data \
    SEL_DEMO_RESET_SECONDS=1800 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
  CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/summary', timeout=2).status == 200 else 1)"

CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "8080"]
