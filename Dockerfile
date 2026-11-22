FROM python:3.11-slim AS builder

WORKDIR /app
COPY . .
RUN python -m pip install --no-cache-dir --prefix=/install -r requirements.txt \
    && python -m pip install --no-cache-dir --prefix=/install -e .

FROM python:3.11-slim AS runtime

WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .

USER 10001:10001

EXPOSE 8000 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import json,urllib.request; response=urllib.request.urlopen('http://127.0.0.1:8000/'); assert json.load(response)['status']=='V11.4.0 LIVE'" || exit 1

ENTRYPOINT ["sh", "-c", "exec uvicorn realworld:app --host 0.0.0.0 --port ${PORT:-8000}"]
