# syntax=docker/dockerfile:1

# =============================================================================
# excapp-db image (multi-stage build)
#
#   builder : rust:1-slim-trixie compiles the release binary excapp-db
#   runtime : debian:trixie-slim ships only the binary and LICENSE
#
# Notes:
#   - All dependencies are pure Rust (tokio-postgres without the TLS
#     feature, no OpenSSL or other system libraries), so the build stage
#     needs no extra system packages;
#   - builder and runtime must use the same Debian major version for
#     glibc compatibility; override RUST_IMAGE / RUNTIME_IMAGE in pairs
#     when switching;
#   - config.template.toml is compiled into the binary via include_str!,
#     so it needs no separate packaging.
#
# Build: ./docker-build.sh (recommended; supports tag / platform /
#        no-cache and other options)
# Run:   docker run --rm -p 8000:8000 \
#          -v "$PWD/config.toml:/etc/excapp-db/config.toml:ro" \
#          excapp-db:<tag>
#        Note: to be reachable outside the container, set
#        app.mcp.streamable.addr to "0.0.0.0" in config.toml (the
#        template default 127.0.0.1 is reachable only inside the
#        container).
# =============================================================================

ARG RUST_IMAGE=rust:1-slim-trixie
ARG RUNTIME_IMAGE=debian:trixie-slim
ARG APP_VERSION=1.0.0

# ---------- Stage 1: compile ----------
FROM ${RUST_IMAGE} AS builder

WORKDIR /build

# Copy the source (constrained by .dockerignore: target/, .git/, local
# config.toml, etc. stay out of the context).
COPY . .

# BuildKit cache mounts: crate downloads and build artifacts are reused
# across builds, speeding up rebuilds; --locked pins dependency versions
# per Cargo.lock for reproducibility.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p cli \
    && cp target/release/excapp-db /usr/local/bin/excapp-db

# ---------- Stage 2: runtime ----------
FROM ${RUNTIME_IMAGE} AS runtime

ARG APP_VERSION

# ca-certificates: reserved for future TLS connections (databases /
# private registries); app: unprivileged runtime user; /etc/excapp-db:
# default config mount point.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1000 --user-group app \
    && mkdir -p /etc/excapp-db

LABEL org.opencontainers.image.title="excapp-db" \
      org.opencontainers.image.description="Read-only database query MCP server" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.url="https://github.com/qq809326636/db-query"

USER app

COPY --from=builder /usr/local/bin/excapp-db /usr/local/bin/excapp-db
COPY LICENSE /usr/share/doc/excapp-db/LICENSE

# Streamable HTTP listen port (template default 8000; the actual value
# follows config.toml).
EXPOSE 8000

# Consistent with `excapp-db mcp stop`: SIGTERM triggers a graceful
# shutdown.
STOPSIGNAL SIGTERM

ENTRYPOINT ["excapp-db"]
# Defaults to streamable mode; the config is provided via a mount:
#   -v "$PWD/config.toml:/etc/excapp-db/config.toml:ro"
CMD ["mcp", "start", "--transport", "streamable", "--config", "/etc/excapp-db/config.toml"]
