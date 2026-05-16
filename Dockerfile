FROM python:3.12-slim AS builder

WORKDIR /build

COPY . .

RUN pip install --no-cache-dir build && \
    python -m build --wheel

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        file \
        && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/dist/*.whl /tmp/

RUN pip install --no-cache-dir /tmp/*.whl && \
    rm /tmp/*.whl

RUN addgroup --system --gid 1001 filo && \
    adduser --system --uid 1001 --gid 1001 filo && \
    mkdir -p /home/filo/.filo && \
    chown -R filo:filo /home/filo/.filo

USER filo

WORKDIR /data

ENTRYPOINT ["filo"]
CMD ["--help"]
