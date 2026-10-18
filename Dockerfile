# ---- Stage 1 : build du frontend Svelte --------------------------------
FROM node:22-alpine AS frontend
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html svelte.config.js tsconfig.json vite.config.ts ./
COPY src ./src
RUN npm run build

# ---- Stage 2 : build du backend Rust (axum + rusqlite bundled) ----------
FROM rust:1-alpine AS backend
WORKDIR /build
# rust:alpine inclut gcc/musl-dev, requis pour compiler SQLite bundled.
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/src ./src
RUN cargo build --release --locked

# ---- Stage 3 : runtime minimal ------------------------------------------
FROM alpine:3.21
WORKDIR /app

RUN adduser -D -u 10001 xvault

COPY --from=frontend /build/dist ./dist
COPY --from=backend /build/target/release/xvault ./xvault

# Configuration comes from environment variables (see docker-compose.yml).
RUN mkdir -p /app/data && chown -R xvault:xvault /app/data

USER xvault
EXPOSE 58951

ENV XVAULT_DB_PATH=/app/data/xVault.sqlite
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:58951/api/auth/status >/dev/null || exit 1
CMD ["./xvault"]
