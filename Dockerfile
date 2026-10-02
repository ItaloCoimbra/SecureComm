FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS frontend
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt requirements-legacy.txt requirements-training.txt requirements-dev.txt ./
COPY setup.py pyproject.toml MANIFEST.in README.md LICENSE train_model.py ./
COPY client/ ./client/
COPY core/ ./core/
COPY server/ ./server/
COPY utils/ ./utils/
COPY benchmark/ ./benchmark/
COPY data/*.py ./data/
COPY --from=frontend /build/server/web_static ./server/web_static/
RUN python -m pip install . && groupadd --gid 10001 securecomm \
    && useradd --uid 10001 --gid 10001 --no-create-home securecomm \
    && mkdir /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8443
VOLUME ["/data"]
CMD ["securecomm-web", "--host", "0.0.0.0", "--port", "8443", "--database", "/data/relay.sqlite", "--tls-cert", "/tls/fullchain.pem", "--tls-key", "/tls/privkey.pem"]
